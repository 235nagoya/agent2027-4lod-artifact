import hashlib
import hmac
import logging
import os
import sqlite3

_LOGGER = logging.getLogger(__name__)

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


class CustomerDataReleaseBlocked(RuntimeError):
    pass


def _database_path():
    return (
        globals().get("DB_PATH")
        or globals().get("DATABASE_PATH")
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )


def _audit_ref(value):
    key = os.environ.get("AUDIT_HMAC_KEY", "local-audit-key-change-in-production")
    return hmac.new(
        key.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _safe_audit_log(outcome, driver_id, customer_id):
    # L4: 制度的正統性 - 生IDや顧客データを記録せず、追跡用のHMAC参照のみを記録する
    _LOGGER.info(
        "get_customer_for_driver outcome=%s driver_ref=%s customer_ref=%s",
        outcome,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


def _detect_forbidden_fields(record):
    # L1: 業務運用 - 返却候補データ内に禁止フィールドが混入していないか検知
    return any(str(key).lower() in _FORBIDDEN_CUSTOMER_FIELDS for key in record.keys())


def _sanitize_customer_record(record):
    # L2: AI監査 - サニタイズ関数で最小権限化し、許可フィールドのみ残す
    if _detect_forbidden_fields(record):
        raise CustomerDataReleaseBlocked("unsafe customer payload blocked")

    return {
        field: record[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }


def _release_guard(payload):
    # L3: 人間介入相当 - 返却直前の最終ガード節
    if not isinstance(payload, dict):
        raise CustomerDataReleaseBlocked("unsafe customer payload blocked")

    for key in payload.keys():
        normalized = str(key).lower()
        if normalized in _FORBIDDEN_CUSTOMER_FIELDS:
            raise CustomerDataReleaseBlocked("unsafe customer payload blocked")
        if normalized not in _ALLOWED_CUSTOMER_FIELDS:
            raise CustomerDataReleaseBlocked("unsafe customer payload blocked")

    return dict(payload)


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _safe_audit_log("invalid_request", driver_id, customer_id)
        raise ValueError("driver_id and customer_id are required")

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
        WHERE c.customer_id = ?
          AND EXISTS (
              SELECT 1
              FROM drivers AS d
              WHERE d.driver_id = ?
          )
          AND (
              EXISTS (
                  SELECT 1
                  FROM driver_customer_assignments AS dca
                  WHERE dca.driver_id = ?
                    AND dca.customer_id = c.customer_id
                    AND LOWER(COALESCE(dca.status, 'active')) = 'active'
              )
              OR EXISTS (
                  SELECT 1
                  FROM assignments AS a
                  WHERE a.driver_id = ?
                    AND a.customer_id = c.customer_id
              )
          )
        LIMIT 1
    """

    try:
        with sqlite3.connect(_database_path()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                sql,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            _safe_audit_log("not_found_or_not_authorized", driver_id, customer_id)
            return None

        sanitized = _sanitize_customer_record(dict(row))
        result = _release_guard(sanitized)

        _safe_audit_log("released", driver_id, customer_id)
        return result

    except Exception:
        _safe_audit_log("error", driver_id, customer_id)
        raise