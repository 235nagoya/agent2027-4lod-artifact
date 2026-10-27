import hashlib
import hmac
import logging
import os
import sqlite3


_DB_PATH_ENV = "CUSTOMER_DB_PATH"
_AUDIT_KEY_ENV = "AUDIT_HASH_KEY"

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

_FORBIDDEN_CUSTOMER_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def _db_path():
    return os.environ.get(_DB_PATH_ENV, "customers.db")


def _audit_key():
    return os.environ.get(_AUDIT_KEY_ENV, "change-me-for-production").encode("utf-8")


def _trace_token(value):
    """
    L4: 制度的正統性
    監査ログ用に driver_id/customer_id を直接出さず、HMAC化した追跡トークンだけを残す。
    """
    raw = b"<none>" if value is None else str(value).encode("utf-8", errors="replace")
    return hmac.new(_audit_key(), raw, hashlib.sha256).hexdigest()[:16]


def _audit(event, driver_id, customer_id):
    """
    L4: 安全なログ記録と追跡。
    顧客属性・連絡先・機密列の値は一切ログ出力しない。
    """
    _logger.info(
        "customer_api.%s driver_trace=%s customer_trace=%s",
        event,
        _trace_token(driver_id),
        _trace_token(customer_id),
    )


def _is_forbidden_key(key):
    return str(key).lower() in _FORBIDDEN_CUSTOMER_FIELDS


def _sanitize_customer_row(row):
    """
    L1/L2:
    - L1: 取得データ内に返却禁止列が混入していないか検知。
    - L2: ホワイトリスト方式で identity/contact data のみに最小化。
    """
    if row is None:
        return None

    row_keys = set(row.keys())

    # 検知のみ。列名や値はログに出さない。
    if any(_is_forbidden_key(k) for k in row_keys):
        _logger.warning("customer_api.blocked_columns_detected")

    return {
        field: row[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in row_keys
    }


def _guard_safe_payload(payload, driver_id, customer_id):
    """
    L3: 人間介入相当の返却直前ガード。
    返却禁止列やホワイトリスト外のキーが混入した場合は返却を停止する。
    """
    if payload is None:
        return

    if not isinstance(payload, dict):
        _logger.error(
            "customer_api.payload_blocked driver_trace=%s customer_trace=%s",
            _trace_token(driver_id),
            _trace_token(customer_id),
        )
        raise RuntimeError("Unsafe customer payload blocked")

    allowed = set(_ALLOWED_CUSTOMER_FIELDS)

    for key in payload.keys():
        if key not in allowed or _is_forbidden_key(key):
            _logger.error(
                "customer_api.payload_blocked driver_trace=%s customer_trace=%s",
                _trace_token(driver_id),
                _trace_token(customer_id),
            )
            raise RuntimeError("Unsafe customer payload blocked")


def get_customer_for_driver(driver_id, customer_id):
    payload = None
    outcome = "not_found_or_unauthorized"

    if driver_id is None or customer_id is None:
        outcome = "invalid_request"
    else:
        _audit("request", driver_id, customer_id)

        allowed_columns_sql = ", ".join(_ALLOWED_CUSTOMER_FIELDS)

        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row

            authorized = conn.execute(
                """
                SELECT 1
                FROM drivers d
                WHERE d.driver_id = ?
                  AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments dca
                        WHERE dca.driver_id = ?
                          AND dca.customer_id = ?
                          AND lower(COALESCE(dca.status, 'active')) = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments a
                        WHERE a.driver_id = ?
                          AND a.customer_id = ?
                    )
                  )
                LIMIT 1
                """,
                (driver_id, driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if authorized is not None:
                row = conn.execute(
                    f"""
                    SELECT {allowed_columns_sql}
                    FROM customers
                    WHERE customer_id = ?
                    LIMIT 1
                    """,
                    (customer_id,),
                ).fetchone()

                payload = _sanitize_customer_row(row)
                if payload is not None:
                    outcome = "success"

    # L3: 返却直前の最終ガード
    _guard_safe_payload(payload, driver_id, customer_id)

    # L4: 生データを含まない安全な監査ログ
    _audit(outcome, driver_id, customer_id)

    return payload