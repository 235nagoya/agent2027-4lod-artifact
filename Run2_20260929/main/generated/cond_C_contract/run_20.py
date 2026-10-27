import hashlib
import hmac
import logging
import os
import sqlite3

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

_SENSITIVE_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_AUDIT_KEY = os.environ.get("AUDIT_LOG_HMAC_KEY")
if _AUDIT_KEY is None:
    _AUDIT_KEY = os.urandom(32)
else:
    _AUDIT_KEY = _AUDIT_KEY.encode("utf-8")


def _open_connection():
    existing = (
        globals().get("DB_CONN")
        or globals().get("CONN")
        or globals().get("conn")
        or globals().get("connection")
    )
    if existing is not None and hasattr(existing, "cursor"):
        return existing, False

    db_path = (
        globals().get("DATABASE_PATH")
        or globals().get("DB_PATH")
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "customers.sqlite3"
    )
    return sqlite3.connect(db_path), True


def _audit_ref(value):
    if value is None:
        return "none"
    digest = hmac.new(
        _AUDIT_KEY,
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:16]


def _safe_audit(event, driver_id, customer_id, outcome):
    # L4: 制度的正統性 - 生値や顧客データをログに出さず、追跡用のHMAC参照のみ記録する。
    logger.info(
        "event=%s outcome=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


def _sanitize_customer(row_dict):
    # L2: AI監査 - ホワイトリスト方式で返却データを最小権限化する。
    return {
        key: row_dict[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in row_dict
    }


def _guard_no_sensitive_fields(data):
    # L1/L3: 個人情報の検知 + 返却直前のガード節。
    if not isinstance(data, dict):
        raise RuntimeError("unsafe response")

    for key in data.keys():
        if str(key).lower() in _SENSITIVE_FIELDS:
            raise RuntimeError("unsafe response")

    forbidden = _SENSITIVE_FIELDS.intersection(set(map(str.lower, data.keys())))
    if forbidden:
        raise RuntimeError("unsafe response")


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _safe_audit("customer_lookup", driver_id, customer_id, "denied")
        return None

    conn, should_close = _open_connection()

    try:
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
              AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca
                        WHERE dca.driver_id = ?
                          AND dca.customer_id = c.customer_id
                          AND COALESCE(dca.status, 'active') = 'active'
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

        cursor = conn.execute(sql, (customer_id, driver_id, driver_id))
        row = cursor.fetchone()

        if row is None:
            _safe_audit("customer_lookup", driver_id, customer_id, "not_found_or_unauthorized")
            return None

        columns = [desc[0] for desc in cursor.description]
        row_dict = dict(zip(columns, row))

        sanitized = _sanitize_customer(row_dict)
        _guard_no_sensitive_fields(sanitized)

        _safe_audit("customer_lookup", driver_id, customer_id, "success")
        return sanitized

    except sqlite3.Error:
        _safe_audit("customer_lookup", driver_id, customer_id, "db_error")
        raise RuntimeError("customer lookup failed") from None

    finally:
        if should_close:
            conn.close()