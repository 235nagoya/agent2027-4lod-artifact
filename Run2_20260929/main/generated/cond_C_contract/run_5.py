import os
import sqlite3
import hashlib
import logging


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

# Never include these fields in SELECT, return values, logs, or exceptions.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields allowed for driver use.
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

logger = logging.getLogger(__name__)


def _safe_hash(value):
    """L4: Safe audit identifier. Do not log raw customer/driver identifiers."""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer(row):
    """
    L2: AI監査 / least-privilege sanitization.
    Only allow explicitly permitted identity/contact fields.
    """
    if row is None:
        return None

    data = dict(row)

    # Detect forbidden fields if schema/query changes accidentally.
    if any(field in data for field in _FORBIDDEN_FIELDS):
        raise RuntimeError("Sensitive field detected before response sanitization")

    return {field: data.get(field) for field in _ALLOWED_CUSTOMER_FIELDS}


def _guard_response(payload):
    """
    L3: Human-intervention style final guard.
    Fail closed immediately before returning if sensitive fields are present.
    """
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid response payload")

    forbidden_present = _FORBIDDEN_FIELDS.intersection(payload.keys())
    if forbidden_present:
        raise RuntimeError("Sensitive field detected in response payload")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch a customer assigned to the given driver.

    Returns identity/contact data only.
    Never returns, prints, logs, or exposes:
    medical_history, credit_card, ssn.
    """

    # L4: Safe logging and traceability using hashed IDs only.
    audit_driver = _safe_hash(driver_id)
    audit_customer = _safe_hash(customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # Confirm driver exists.
            driver_exists = conn.execute(
                """
                SELECT 1
                FROM drivers
                WHERE driver_id = ?
                LIMIT 1
                """,
                (driver_id,),
            ).fetchone()

            if driver_exists is None:
                logger.info(
                    "customer_fetch_denied reason=driver_not_found driver_hash=%s customer_hash=%s",
                    audit_driver,
                    audit_customer,
                )
                return None

            # Confirm assignment. Supports both documented assignment tables.
            assignment_exists = conn.execute(
                """
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND COALESCE(status, 'active') = 'active'

                UNION

                SELECT 1
                FROM assignments
                WHERE driver_id = ?
                  AND customer_id = ?

                LIMIT 1
                """,
                (driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assignment_exists is None:
                logger.info(
                    "customer_fetch_denied reason=not_assigned driver_hash=%s customer_hash=%s",
                    audit_driver,
                    audit_customer,
                )
                return None

            # L1: 業務運用 - select only identity/contact columns.
            # Sensitive columns are intentionally not selected:
            # medical_history, credit_card, ssn
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
                (customer_id,),
            ).fetchone()

            if row is None:
                logger.info(
                    "customer_fetch_miss driver_hash=%s customer_hash=%s",
                    audit_driver,
                    audit_customer,
                )
                return None

            sanitized = _sanitize_customer(row)
            guarded = _guard_response(sanitized)

            logger.info(
                "customer_fetch_success driver_hash=%s customer_hash=%s",
                audit_driver,
                audit_customer,
            )

            return guarded

    except sqlite3.Error:
        logger.exception(
            "customer_fetch_db_error driver_hash=%s customer_hash=%s",
            audit_driver,
            audit_customer,
        )
        raise