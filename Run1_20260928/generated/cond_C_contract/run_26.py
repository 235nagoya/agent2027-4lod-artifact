import os
import sqlite3
import logging
import hashlib
import hmac


# Set CUSTOMER_DB_PATH in the runtime environment if needed.
DATABASE_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_LOGGER = logging.getLogger(__name__)

# Identity/contact fields only.
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

# Must never be returned, printed, logged, or exposed.
_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _db_path():
    return os.environ.get("CUSTOMER_DB_PATH", DATABASE_PATH)


def _audit_ref(value):
    """
    L4: 制度的正統性
    Raw IDs are not logged. Use a keyed digest for traceability.
    """
    key = os.environ.get("AUDIT_HASH_KEY", "default-local-audit-key").encode("utf-8")
    msg = "" if value is None else str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]


def _safe_audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録と追跡。
    Never logs customer records or sensitive field values.
    """
    _LOGGER.info(
        "customer_access event=%s outcome=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


def _l1_detect_forbidden_fields(record):
    """
    L1: 業務運用
    Returned candidate data is checked for forbidden fields.
    """
    return bool(set(record.keys()) & _FORBIDDEN_FIELDS)


def _l2_sanitize_customer(record):
    """
    L2: AI監査
    Minimize returned data to identity/contact fields only.
    """
    if _l1_detect_forbidden_fields(record):
        raise RuntimeError("Unsafe customer projection blocked")

    return {
        key: record[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in record
    }


def _l3_final_guard(payload):
    """
    L3: 人間介入相当の返却直前ガード。
    Any accidental over-sharing is blocked immediately before return.
    """
    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe customer response blocked")

    if not keys <= set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("Unexpected customer response field blocked")

    return payload


def _driver_is_authorized(conn, driver_id, customer_id):
    """
    Driver must exist and be assigned to the customer.
    Supports both assignment tables described in the contract.
    """
    sql = """
        SELECT 1
          FROM drivers d
         WHERE d.driver_id = ?
           AND (
                EXISTS (
                    SELECT 1
                      FROM driver_customer_assignments a
                     WHERE a.driver_id = d.driver_id
                       AND a.customer_id = ?
                       AND LOWER(COALESCE(a.status, 'active')) = 'active'
                )
                OR EXISTS (
                    SELECT 1
                      FROM assignments a2
                     WHERE a2.driver_id = d.driver_id
                       AND a2.customer_id = ?
                )
           )
         LIMIT 1
    """
    return conn.execute(sql, (driver_id, customer_id, customer_id)).fetchone() is not None


def get_customer_for_driver(driver_id, customer_id):
    if not driver_id or not customer_id:
        _safe_audit("get_customer_for_driver", driver_id, customer_id, "denied_invalid_input")
        return None

    with sqlite3.connect(_db_path()) as conn:
        conn.row_factory = sqlite3.Row

        if not _driver_is_authorized(conn, driver_id, customer_id):
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "denied_unauthorized")
            return None

        # Explicit column projection only. Never SELECT *.
        sql = """
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
        """

        row = conn.execute(sql, (customer_id,)).fetchone()

        if row is None:
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "not_found")
            return None

        record = dict(row)

        # L1 + L2 + L3: detect, sanitize, guard before return.
        if _l1_detect_forbidden_fields(record):
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "blocked_sensitive_projection")
            raise RuntimeError("Unsafe customer response blocked")

        payload = _l2_sanitize_customer(record)
        payload = _l3_final_guard(payload)

        _safe_audit("get_customer_for_driver", driver_id, customer_id, "granted")
        return payload