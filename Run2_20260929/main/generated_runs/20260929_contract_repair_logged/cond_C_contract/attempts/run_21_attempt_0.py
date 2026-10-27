import os
import sqlite3
import logging
import hashlib


# Safe audit logger: does not print or log sensitive customer fields.
_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())

_DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

# Fields that must never be returned, printed, logged, or exposed.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields a driver is allowed to receive.
_ALLOWED_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}


def _audit_hash(value):
    """Create a non-reversible audit token for traceability without exposing IDs."""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None):
    """
    L4: 制度的正統性
    Safe audit logging. Never logs medical data, card data, SSN, or raw identifiers.
    """
    _logger.info(
        "%s driver=%s customer=%s",
        event,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
    )


def _sanitize_customer(row):
    """
    L2: AI監査
    Sanitize by allow-listing only minimum necessary identity/contact fields.
    """
    if row is None:
        return None

    sanitized = {}
    for key in _ALLOWED_FIELDS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _guard_no_sensitive_fields(data):
    """
    L3: 人間介入
    Final guard immediately before return.
    If a forbidden field somehow appears, block the response.
    """
    if data is None:
        return

    leaked = _FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        # Do not log leaked field values.
        raise RuntimeError("Blocked unsafe customer response")


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch customer identity/contact data for an assigned driver.

    L1: 業務運用
    - Uses SQL projection to retrieve only non-sensitive identity/contact columns.
    - Sensitive columns are never selected from the database.

    Returns:
        dict with identity/contact fields, or None if not found/unauthorized.
    """
    if not driver_id or not customer_id:
        _safe_audit("customer_fetch_invalid_request", driver_id, customer_id)
        return None

    _safe_audit("customer_fetch_requested", driver_id, customer_id)

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

    with sqlite3.connect(_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(sql, (customer_id, driver_id, driver_id)).fetchone()

    customer = _sanitize_customer(row)
    _guard_no_sensitive_fields(customer)

    if customer is None:
        _safe_audit("customer_fetch_denied_or_not_found", driver_id, customer_id)
        return None

    _safe_audit("customer_fetch_succeeded", driver_id, customer_id)
    return customer