import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import uuid


_ALLOWED_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_NEVER_EXPOSE_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")
_PROCESS_AUDIT_KEY = secrets.token_bytes(32)


def _db_path():
    return os.environ.get("CUSTOMER_DB_PATH", "app.db")


def _audit_token(value):
    """
    L4: 安全なログ記録用。
    生の driver_id/customer_id はログに出さず、HMAC化した追跡用トークンだけを残す。
    """
    if value is None:
        return None

    secret = os.environ.get("AUDIT_LOG_SECRET")
    key = secret.encode("utf-8") if secret else _PROCESS_AUDIT_KEY

    return hmac.new(
        key,
        str(value).encode("utf-8", "surrogatepass"),
        hashlib.sha256,
    ).hexdigest()[:24]


def _safe_audit(event, trace_id, driver_id=None, customer_id=None, status=None):
    """
    L4: 制度的正統性。
    PIIや禁止フィールド値をログに出さず、追跡可能な最小情報だけ記録する。
    """
    try:
        _AUDIT_LOGGER.info(
            "event=%s trace_id=%s driver_ref=%s customer_ref=%s status=%s",
            event,
            trace_id,
            _audit_token(driver_id),
            _audit_token(customer_id),
            status,
        )
    except Exception:
        # ログ障害でAPI処理を失敗させない。値は一切出力しない。
        pass


def _mask_and_detect_forbidden_fields(record):
    """
    L1: 業務運用。
    万一、禁止フィールドが混入しても値をマスクし、検知フラグを返す。
    """
    detected = False
    masked = {}

    for key, value in record.items():
        if key in _NEVER_EXPOSE_FIELDS:
            detected = True
            masked[key] = "***MASKED***"
        else:
            masked[key] = value

    return masked, detected


def _sanitize_customer_record(record):
    """
    L2: AI監査。
    最小権限化: 返却可能な identity/contact フィールドだけを allowlist で残す。
    """
    return {
        field: record.get(field)
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }


def _guard_before_return(record):
    """
    L3: 人間介入。
    返却直前のガード節。禁止フィールドや想定外フィールドがあれば返さない。
    """
    if record is None:
        return None

    keys = set(record.keys())

    if keys & _NEVER_EXPOSE_FIELDS:
        raise RuntimeError("unsafe customer payload blocked")

    if not keys.issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        raise RuntimeError("unexpected customer payload blocked")

    return record


def get_customer_for_driver(driver_id, customer_id):
    trace_id = str(uuid.uuid4())

    if not isinstance(driver_id, str) or not isinstance(customer_id, str):
        _safe_audit(
            "customer_lookup",
            trace_id,
            driver_id=None,
            customer_id=None,
            status="invalid_input",
        )
        return None

    if not driver_id.strip() or not customer_id.strip():
        _safe_audit(
            "customer_lookup",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="invalid_input",
        )
        return None

    _safe_audit(
        "customer_lookup",
        trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        status="started",
    )

    sql = """
        SELECT
            c.customer_id,
            c.id,
            c.name,
            c.display_name,
            c.full_name,
            c.address,
            c.phone,
            c.phone_number
        FROM customers AS c
        WHERE
            c.customer_id = ?
            AND EXISTS (
                SELECT 1
                FROM drivers AS d
                WHERE d.driver_id = ?
            )
            AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments AS dca
                    WHERE
                        dca.driver_id = ?
                        AND dca.customer_id = c.customer_id
                        AND COALESCE(dca.status, 'active') = 'active'
                )
                OR (
                    NOT EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca2
                        WHERE
                            dca2.driver_id = ?
                            AND dca2.customer_id = c.customer_id
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE
                            a.driver_id = ?
                            AND a.customer_id = c.customer_id
                    )
                )
            )
        LIMIT 1
    """

    try:
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                sql,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    driver_id,
                    driver_id,
                ),
            ).fetchone()

    except sqlite3.Error:
        _safe_audit(
            "customer_lookup",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="db_error",
        )
        raise RuntimeError("customer lookup failed") from None

    if row is None:
        _safe_audit(
            "customer_lookup",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="not_found_or_denied",
        )
        return None

    raw_record = dict(row)

    masked_record, forbidden_detected = _mask_and_detect_forbidden_fields(raw_record)

    if forbidden_detected:
        _safe_audit(
            "customer_lookup",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="forbidden_fields_detected_and_removed",
        )

    sanitized_record = _sanitize_customer_record(masked_record)
    result = _guard_before_return(sanitized_record)

    _safe_audit(
        "customer_lookup",
        trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        status="success",
    )

    return result