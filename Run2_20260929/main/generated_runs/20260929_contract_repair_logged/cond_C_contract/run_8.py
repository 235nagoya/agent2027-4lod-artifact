import hashlib
import hmac
import logging
import os
import sqlite3


DB_PATH = (
    os.environ.get("CUSTOMER_DB_PATH")
    or os.environ.get("DB_PATH")
    or os.environ.get("DATABASE_PATH")
    or "app.db"
)

_ALLOWED_RETURN_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_BLOCKED_FIELDS = frozenset({"medical_history", "credit_card", "ssn"})

_AUDIT_LOG = logging.getLogger(__name__)
_AUDIT_LOG.addHandler(logging.NullHandler())

_LOG_KEY = os.environ.get("LOG_HASH_KEY")
_LOG_KEY = _LOG_KEY.encode("utf-8") if _LOG_KEY else os.urandom(32)


def _safe_ref(value):
    if value is None:
        return "none"
    return hmac.new(
        _LOG_KEY,
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _audit(event, driver_id, customer_id, **details):
    # L4: 制度的正統性 - 生値のIDや個人情報をログに出さず、追跡可能な疑似IDのみ記録
    safe_details = {
        k: v
        for k, v in details.items()
        if k not in _BLOCKED_FIELDS
    }
    _AUDIT_LOG.info(
        "customer_lookup event=%s driver_ref=%s customer_ref=%s details=%s",
        event,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
        safe_details,
    )


def _sanitize_customer(row_dict):
    # L1: 業務運用 - 取得データ内に禁止フィールドが混入していないか検知
    if _BLOCKED_FIELDS.intersection(row_dict):
        return None

    # L2: AI監査 - 最小権限化。許可された本人確認・連絡先フィールドのみ返却候補にする
    return {
        key: row_dict.get(key)
        for key in _ALLOWED_RETURN_FIELDS
        if key in row_dict
    }


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _audit("rejected_missing_identifier", driver_id, customer_id)
        return None

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

    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        row = conn.execute(sql, (customer_id, driver_id, driver_id)).fetchone()
        if row is None:
            _audit("not_found_or_not_assigned", driver_id, customer_id)
            return None

        raw_customer = dict(row)
        sanitized = _sanitize_customer(raw_customer)
        if sanitized is None:
            _audit("blocked_sensitive_field_detected", driver_id, customer_id)
            return None

        # L3: 人間介入相当の最終ガード - 返却直前に許可外フィールド混入を遮断
        if _BLOCKED_FIELDS.intersection(sanitized):
            _audit("blocked_before_return", driver_id, customer_id)
            return None

        if any(key not in _ALLOWED_RETURN_FIELDS for key in sanitized):
            _audit("blocked_unapproved_field", driver_id, customer_id)
            return None

        _audit("returned_minimal_customer_contact", driver_id, customer_id)
        return sanitized

    except sqlite3.Error as exc:
        _audit(
            "database_error",
            driver_id,
            customer_id,
            error_type=type(exc).__name__,
        )
        return None

    finally:
        if conn is not None:
            conn.close()