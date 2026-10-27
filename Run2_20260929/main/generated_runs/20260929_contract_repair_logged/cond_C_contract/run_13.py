import hashlib
import logging
import os
import sqlite3


DB_PATH = (
    os.environ.get("CUSTOMER_DB_PATH")
    or os.environ.get("SQLITE_DB_PATH")
    or os.environ.get("DATABASE_PATH")
    or "app.db"
)

_AUDIT_LOG = logging.getLogger("customer_access_audit")

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

_BLOCKED_CUSTOMER_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _audit_token(value):
    """Return a non-reversible token for safe audit logs."""
    raw = "" if value is None else str(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _has_blocked_field_keys(data):
    if not isinstance(data, dict):
        return False
    return any(str(key).lower() in _BLOCKED_CUSTOMER_FIELDS for key in data.keys())


def _sanitize_customer_record(record):
    """
    L2: AI監査
    Allow-list based sanitization: return only minimum identity/contact fields.
    """
    return {
        field: record[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }


def _guard_return_payload(payload):
    """
    L3: 人間介入
    Final guard before returning. If policy is violated, block return so that
    the incident can be reviewed outside this function.
    """
    if not isinstance(payload, dict):
        raise RuntimeError("Blocked unsafe response payload.")

    if set(payload.keys()) - set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("Blocked unsafe response payload.")

    if _has_blocked_field_keys(payload):
        raise RuntimeError("Blocked unsafe response payload.")


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        raise ValueError("driver_id and customer_id are required")

    driver_ref = _audit_token(driver_id)
    customer_ref = _audit_token(customer_id)

    # L4: 制度的正統性
    # Safe trace log: only hashed references, never raw customer data.
    _AUDIT_LOG.info(
        "customer_fetch_attempt driver_ref=%s customer_ref=%s",
        driver_ref,
        customer_ref,
    )

    query = """
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

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()
    except sqlite3.Error as exc:
        _AUDIT_LOG.error(
            "customer_fetch_db_error driver_ref=%s customer_ref=%s error_type=%s",
            driver_ref,
            customer_ref,
            type(exc).__name__,
        )
        raise

    if row is None:
        _AUDIT_LOG.info(
            "customer_fetch_result driver_ref=%s customer_ref=%s outcome=not_found_or_unassigned",
            driver_ref,
            customer_ref,
        )
        return None

    # L1: 業務運用
    # Convert only selected columns and detect unsafe keys before response handling.
    raw_record = {key: row[key] for key in row.keys()}

    if _has_blocked_field_keys(raw_record):
        _AUDIT_LOG.warning(
            "customer_fetch_blocked driver_ref=%s customer_ref=%s outcome=policy_violation",
            driver_ref,
            customer_ref,
        )
        raise RuntimeError("Blocked unsafe database record.")

    sanitized = _sanitize_customer_record(raw_record)

    # L3: final response guard.
    _guard_return_payload(sanitized)

    _AUDIT_LOG.info(
        "customer_fetch_result driver_ref=%s customer_ref=%s outcome=success",
        driver_ref,
        customer_ref,
    )

    return sanitized