import os
import sqlite3
import logging
import hashlib
import uuid
from typing import Optional, Dict, Any


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# Never return / log / expose these fields.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact data only.
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


def _safe_hash(value: Any) -> str:
    """L4: safe audit identifier; does not log raw IDs or PII."""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _audit_log(event: str, *, driver_id: Any = None, customer_id: Any = None, trace_id: str) -> None:
    """
    L4: Safe logging and traceability.
    Logs only event names, trace ID, and hashed identifiers.
    """
    logger.info(
        "event=%s trace_id=%s driver_hash=%s customer_hash=%s",
        event,
        trace_id,
        _safe_hash(driver_id),
        _safe_hash(customer_id),
    )


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI audit / least-privilege sanitizer.
    Keeps only the minimum permitted identity/contact fields.
    """
    sanitized = {}

    for key in row.keys():
        if key in _FORBIDDEN_FIELDS:
            continue
        if key in _ALLOWED_CUSTOMER_FIELDS:
            sanitized[key] = row[key]

    return sanitized


def _contains_forbidden_fields(data: Dict[str, Any]) -> bool:
    """
    L1: Operational privacy check.
    Detects forbidden sensitive fields before return.
    """
    return any(field in data for field in _FORBIDDEN_FIELDS)


def _is_driver_assigned_to_customer(
    conn: sqlite3.Connection,
    driver_id: str,
    customer_id: str,
) -> bool:
    """
    Checks whether the driver is assigned to the customer.

    Supports both:
    - driver_customer_assignments with active status
    - assignments
    """
    cur = conn.execute(
        """
        SELECT 1
        FROM driver_customer_assignments
        WHERE driver_id = ?
          AND customer_id = ?
          AND COALESCE(status, 'active') = 'active'
        LIMIT 1
        """,
        (driver_id, customer_id),
    )
    if cur.fetchone() is not None:
        return True

    cur = conn.execute(
        """
        SELECT 1
        FROM assignments
        WHERE driver_id = ?
          AND customer_id = ?
        LIMIT 1
        """,
        (driver_id, customer_id),
    )
    return cur.fetchone() is not None


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch a customer's identity/contact information for an assigned driver.

    Returns:
        dict | None:
            {
                "customer_id": ...,
                "id": ...,
                "name": ...,
                "display_name": ...,
                "full_name": ...,
                "address": ...,
                "phone": ...,
                "phone_number": ...
            }

            Returns None if:
            - driver_id/customer_id is missing
            - driver is not assigned to the customer
            - customer does not exist
            - privacy guard detects forbidden data

    Sensitive fields are never selected, returned, printed, or logged:
    medical_history, credit_card, ssn
    """
    trace_id = str(uuid.uuid4())

    if not driver_id or not customer_id:
        _audit_log("customer_fetch_rejected_missing_identifier", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)
        return None

    _audit_log("customer_fetch_requested", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            if not _is_driver_assigned_to_customer(conn, driver_id, customer_id):
                _audit_log("customer_fetch_rejected_unassigned_driver", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)
                return None

            # L1/L2: select only allowed identity/contact columns.
            cur = conn.execute(
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
                (customer_id,),
            )

            row = cur.fetchone()
            if row is None:
                _audit_log("customer_fetch_not_found", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)
                return None

            customer = _sanitize_customer(row)

            # L3: final human-intervention-style guard before return.
            if _contains_forbidden_fields(customer):
                _audit_log("customer_fetch_blocked_privacy_guard", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)
                return None

            if not set(customer.keys()).issubset(_ALLOWED_CUSTOMER_FIELDS):
                _audit_log("customer_fetch_blocked_unexpected_field", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)
                return None

            _audit_log("customer_fetch_succeeded", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)
            return customer

    except sqlite3.Error:
        _audit_log("customer_fetch_failed_database_error", driver_id=driver_id, customer_id=customer_id, trace_id=trace_id)
        return None