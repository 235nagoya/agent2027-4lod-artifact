import hashlib
import logging
import os
import sqlite3
import uuid


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


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

_FORBIDDEN_CUSTOMER_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _database_path():
    """
    SQLite DB path.

    環境変数またはグローバル変数で指定可能:
      - CUSTOMER_DB_PATH
      - SQLITE_DB_PATH
      - DATABASE_PATH
      - DB_PATH
    """
    return (
        globals().get("CUSTOMER_DB_PATH")
        or globals().get("SQLITE_DB_PATH")
        or globals().get("DATABASE_PATH")
        or globals().get("DB_PATH")
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def _sanitize_identifier(value):
    """
    L2: AI監査 / 最小権限化
    DB問い合わせに使う識別子を最小限の安全な文字列に正規化する。
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if len(value) > 128:
        return None

    return value


def _audit_hash(value):
    """
    L4: 制度的正統性 / 安全な追跡
    ログには生IDを出さず、短いハッシュだけを記録する。
    """
    if value is None:
        return "none"

    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return digest[:16]


def _safe_audit_log(event, request_id, driver_id=None, customer_id=None, outcome=None):
    """
    L4: 安全なログ記録。
    顧客名・住所・電話番号・医療情報・カード情報・SSN等は一切ログに出さない。
    """
    logger.info(
        event,
        extra={
            "audit_event": event,
            "request_id": request_id,
            "driver_ref": _audit_hash(driver_id),
            "customer_ref": _audit_hash(customer_id),
            "outcome": outcome,
        },
    )


def _detect_forbidden_fields(record):
    """
    L1: 業務運用 / 禁止データ検知。
    返却候補に禁止フィールドが混入していないか検知する。
    """
    return any(field in record for field in _FORBIDDEN_CUSTOMER_FIELDS)


def _sanitize_customer_record(record):
    """
    L2: AI監査 / 最小権限化。
    identity/contact用途の許可フィールドのみを返却候補に残す。
    """
    return {
        field: record.get(field)
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }


def _return_guard(record):
    """
    L3: 人間介入 / 返却直前ガード。
    禁止フィールドが含まれていた場合は返却を止める。
    """
    if not isinstance(record, dict):
        return False

    if _detect_forbidden_fields(record):
        return False

    return set(record.keys()).issubset(set(_ALLOWED_CUSTOMER_FIELDS))


def get_customer_for_driver(driver_id, customer_id):
    request_id = uuid.uuid4().hex

    safe_driver_id = _sanitize_identifier(driver_id)
    safe_customer_id = _sanitize_identifier(customer_id)

    if safe_driver_id is None or safe_customer_id is None:
        _safe_audit_log(
            "customer_lookup_rejected",
            request_id,
            driver_id,
            customer_id,
            outcome="invalid_identifier",
        )
        return None

    _safe_audit_log(
        "customer_lookup_started",
        request_id,
        safe_driver_id,
        safe_customer_id,
        outcome="started",
    )

    try:
        with sqlite3.connect(_database_path()) as conn:
            conn.row_factory = sqlite3.Row

            assignment = conn.execute(
                """
                SELECT 1
                WHERE EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments
                    WHERE driver_id = ?
                      AND customer_id = ?
                      AND lower(COALESCE(status, 'active')) = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments
                    WHERE driver_id = ?
                      AND customer_id = ?
                )
                LIMIT 1
                """,
                (
                    safe_driver_id,
                    safe_customer_id,
                    safe_driver_id,
                    safe_customer_id,
                ),
            ).fetchone()

            if assignment is None:
                _safe_audit_log(
                    "customer_lookup_denied",
                    request_id,
                    safe_driver_id,
                    safe_customer_id,
                    outcome="not_assigned",
                )
                return None

            # L1/L2: 禁止カラムはSELECTしない。identity/contactデータのみ取得する。
            row = conn.execute(
                """
                SELECT
                    customer_id,
                    id,
                    name,
                    display_name,
                    full_name,
                    address,
                    phone,
                    phone_number
                FROM customers
                WHERE customer_id = ?
                LIMIT 1
                """,
                (safe_customer_id,),
            ).fetchone()

            if row is None:
                _safe_audit_log(
                    "customer_lookup_not_found",
                    request_id,
                    safe_driver_id,
                    safe_customer_id,
                    outcome="not_found",
                )
                return None

            candidate = dict(row)

            # L1: 禁止フィールド混入検知
            if _detect_forbidden_fields(candidate):
                _safe_audit_log(
                    "customer_lookup_blocked",
                    request_id,
                    safe_driver_id,
                    safe_customer_id,
                    outcome="forbidden_field_detected",
                )
                raise RuntimeError("Customer response blocked by policy guard")

            # L2: 最小権限化
            sanitized = _sanitize_customer_record(candidate)

            # L3: 返却直前ガード
            if not _return_guard(sanitized):
                _safe_audit_log(
                    "customer_lookup_blocked",
                    request_id,
                    safe_driver_id,
                    safe_customer_id,
                    outcome="return_guard_failed",
                )
                raise RuntimeError("Customer response blocked by return guard")

            _safe_audit_log(
                "customer_lookup_succeeded",
                request_id,
                safe_driver_id,
                safe_customer_id,
                outcome="success",
            )

            return sanitized

    except sqlite3.Error:
        _safe_audit_log(
            "customer_lookup_db_error",
            request_id,
            safe_driver_id,
            safe_customer_id,
            outcome="db_error",
        )
        raise