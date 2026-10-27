import os
import sqlite3
import logging
import hashlib


# Never include these fields in SELECT, return values, exceptions, or logs.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields allowed to be returned to a driver.
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

_LOGGER = logging.getLogger(__name__)


def _db_path():
    """
    Uses only the standard library.

    Set APP_DB_PATH in the environment when deploying/testing.
    Defaults to ./app.db.
    """
    return os.environ.get("APP_DB_PATH", "app.db")


def _safe_hash(value):
    """
    L4: 制度的正統性
    Safe trace identifier for logs.
    Does not log raw driver_id/customer_id.
    """
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event, driver_id=None, customer_id=None):
    """
    L4: 制度的正統性
    Log only non-sensitive metadata and hashed identifiers.
    Never log medical_history, credit_card, ssn, or full DB rows.
    """
    _LOGGER.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _safe_hash(driver_id),
        _safe_hash(customer_id),
    )


def _driver_is_assigned(conn, driver_id, customer_id):
    """
    Enforces driver/customer relationship.

    Supports both:
    - driver_customer_assignments with status='active'
    - assignments
    """
    row = conn.execute(
        """
        SELECT 1
        WHERE EXISTS (
            SELECT 1
              FROM driver_customer_assignments
             WHERE driver_id = ?
               AND customer_id = ?
               AND COALESCE(status, 'active') = 'active'
        )
        OR EXISTS (
            SELECT 1
              FROM assignments
             WHERE driver_id = ?
               AND customer_id = ?
        )
        LIMIT 1
        """,
        (driver_id, customer_id, driver_id, customer_id),
    ).fetchone()

    return row is not None


def _sanitize_customer_record(record):
    """
    L2: AI監査
    Sanitization by allow-listing only minimum necessary fields.

    This function deliberately ignores every field not in
    _ALLOWED_CUSTOMER_FIELDS, so sensitive fields cannot be returned even
    if a future query accidentally includes extra columns.
    """
    sanitized = {
        field: record.get(field)
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }

    for forbidden in _FORBIDDEN_FIELDS:
        sanitized.pop(forbidden, None)

    return sanitized


def _mask_for_detection_only(record):
    """
    L1: 業務運用
    Detect forbidden fields and create a masked internal-only view.

    The returned value is not exposed by get_customer_for_driver.
    This is used only to ensure sensitive keys would be masked if present.
    """
    masked = dict(record)
    for field in _FORBIDDEN_FIELDS:
        if field in masked:
            masked[field] = "[REDACTED]"
    return masked


def _assert_no_forbidden_fields(data):
    """
    L3: 人間介入
    Final guard clause before returning data.

    If forbidden fields are present, fail closed.
    """
    leaked = _FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Unsafe customer payload blocked before return")


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch customer identity/contact data for an assigned driver.

    Returns:
        dict with customer identity/contact fields, or None when:
        - driver_id/customer_id is missing
        - driver is not assigned to the customer
        - customer does not exist

    Never returns, prints, logs, or exposes:
        medical_history, credit_card, ssn
    """
    if not driver_id or not customer_id:
        _safe_audit_log("customer_fetch_rejected_missing_id", driver_id, customer_id)
        return None

    columns = ", ".join(_ALLOWED_CUSTOMER_FIELDS)

    with sqlite3.connect(_db_path()) as conn:
        conn.row_factory = sqlite3.Row

        if not _driver_is_assigned(conn, driver_id, customer_id):
            _safe_audit_log("customer_fetch_denied_unassigned", driver_id, customer_id)
            return None

        row = conn.execute(
            f"""
            SELECT {columns}
              FROM customers
             WHERE customer_id = ?
             LIMIT 1
            """,
            (customer_id,),
        ).fetchone()

        if row is None:
            _safe_audit_log("customer_fetch_not_found", driver_id, customer_id)
            return None

        raw_record = dict(row)

        # L1: Detect/mask sensitive keys internally if they ever appear.
        _mask_for_detection_only(raw_record)

        # L2: Minimum-privilege sanitization through allow-listing.
        sanitized = _sanitize_customer_record(raw_record)

        # L3: Final guard before return.
        _assert_no_forbidden_fields(sanitized)

        # L4: Safe trace log with hashed identifiers only.
        _safe_audit_log("customer_fetch_allowed", driver_id, customer_id)

        return sanitized