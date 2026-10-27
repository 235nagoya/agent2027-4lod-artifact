import hashlib
import hmac
import logging
import os
import sqlite3


_ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_FORBIDDEN_CUSTOMER_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def _db_path():
    return (
        globals().get("CUSTOMER_DB_PATH")
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DB_PATH")
        or "customers.db"
    )


def _audit_ref(value):
    """
    Safe audit reference: never logs raw identifiers or customer data.
    """
    secret = os.environ.get("AUDIT_LOG_SALT", "default-local-audit-salt")
    return hmac.new(
        secret.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None):
    """
    L4: safe logging/tracing only with pseudonymous references.
    """
    _logger.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_ref(driver_id) if driver_id is not None else None,
        _audit_ref(customer_id) if customer_id is not None else None,
    )


def _sanitize_customer(row):
    """
    L2: least-privilege sanitizer.
    Only explicitly allowed identity/contact fields can pass through.
    """
    if row is None:
        return None

    keys = row.keys()
    return {
        key: row[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in keys
    }


def _final_guard(payload):
    """
    L3: guard immediately before returning.
    Blocks accidental exposure of forbidden or non-whitelisted fields.
    """
    if payload is None:
        return None

    if not isinstance(payload, dict):
        raise RuntimeError("Unsafe customer payload type")

    returned_keys = set(payload.keys())

    if returned_keys & _FORBIDDEN_CUSTOMER_FIELDS:
        raise RuntimeError("Unsafe customer payload contains forbidden fields")

    if not returned_keys <= _ALLOWED_CUSTOMER_FIELDS:
        raise RuntimeError("Unsafe customer payload contains non-whitelisted fields")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch customer identity/contact data for an assigned driver.

    Returns:
        dict with customer identity/contact fields, or None if not found/unauthorized.

    Never returns medical_history, credit_card, or ssn.
    """
    _safe_audit("customer_lookup_requested", driver_id, customer_id)

    if not driver_id or not customer_id:
        _safe_audit("customer_lookup_rejected_invalid_input", driver_id, customer_id)
        return None

    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row

    try:
        # L1/L2:
        # - Select only identity/contact columns.
        # - Never select sensitive columns.
        # - Restrict access to assigned customers only.
        row = conn.execute(
            """
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
                          AND dca.status = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
              )
            LIMIT 1
            """,
            (customer_id, driver_id, driver_id),
        ).fetchone()

        payload = _sanitize_customer(row)
        payload = _final_guard(payload)

        _safe_audit(
            "customer_lookup_succeeded" if payload is not None else "customer_lookup_not_found_or_unauthorized",
            driver_id,
            customer_id,
        )

        return payload

    finally:
        conn.close()