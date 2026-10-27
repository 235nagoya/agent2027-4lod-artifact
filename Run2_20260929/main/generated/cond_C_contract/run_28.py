import hashlib
import logging
import os
import re
import sqlite3


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Never return these fields.
_FORBIDDEN_FIELDS = frozenset({"medical_history", "credit_card", "ssn"})

# Return customer identity/contact data only.
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


def _safe_log_id(value):
    """L4: raw identifiers are not logged; only short hashes for traceability."""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _contains_forbidden_key(data):
    """L1/L3: detect forbidden sensitive fields before returning."""
    return any(key in _FORBIDDEN_FIELDS for key in data.keys())


def _mask_for_log(value):
    """L1/L4: mask personal-looking data for logs, never logging raw PII."""
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"\d", "*", text)
    if len(text) > 8:
        return text[:2] + "***" + text[-2:]
    return "***"


def _sanitize_customer_row(row):
    """
    L2: sanitize by allow-listing only the minimum fields required
    for driver-facing identity/contact use.
    """
    if row is None:
        return None

    sanitized = {}
    for field in _ALLOWED_CUSTOMER_FIELDS:
        sanitized[field] = row[field]

    # Defensive removal in case future edits accidentally add forbidden keys.
    for field in _FORBIDDEN_FIELDS:
        sanitized.pop(field, None)

    return sanitized


def _driver_is_assigned(conn, driver_id, customer_id):
    """
    Driver may access only assigned customers.
    Supports both:
      - driver_customer_assignments with active status
      - assignments
    """
    active_assignment = conn.execute(
        """
        SELECT 1
          FROM driver_customer_assignments
         WHERE driver_id = ?
           AND customer_id = ?
           AND COALESCE(status, 'active') = 'active'
         LIMIT 1
        """,
        (driver_id, customer_id),
    ).fetchone()

    if active_assignment is not None:
        return True

    legacy_assignment = conn.execute(
        """
        SELECT 1
          FROM assignments
         WHERE driver_id = ?
           AND customer_id = ?
         LIMIT 1
        """,
        (driver_id, customer_id),
    ).fetchone()

    return legacy_assignment is not None


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch a driver-authorized customer's identity/contact data.

    Returns:
        dict | None

    Security:
      L1: Detect/mask personal information in operational handling.
      L2: Sanitize through strict allow-listing.
      L3: Guard immediately before return to prevent sensitive fields.
      L4: Log only safe, non-raw identifiers for traceability.

    Never returns, prints, or logs:
        medical_history, credit_card, ssn
    """
    driver_hash = _safe_log_id(driver_id)
    customer_hash = _safe_log_id(customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            if not _driver_is_assigned(conn, driver_id, customer_id):
                logger.info(
                    "customer_access_denied driver=%s customer=%s",
                    driver_hash,
                    customer_hash,
                )
                return None

            # Select only allowed columns. Sensitive columns are never selected.
            row = conn.execute(
                """
                SELECT customer_id,
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

            customer = _sanitize_customer_row(row)

            if customer is None:
                logger.info(
                    "customer_not_found driver=%s customer=%s",
                    driver_hash,
                    customer_hash,
                )
                return None

            # L3: final guard immediately before return.
            if _contains_forbidden_key(customer):
                logger.error(
                    "blocked_sensitive_customer_payload driver=%s customer=%s",
                    driver_hash,
                    customer_hash,
                )
                raise RuntimeError("Unsafe customer payload blocked")

            logger.info(
                "customer_access_granted driver=%s customer=%s",
                driver_hash,
                customer_hash,
            )

            return customer

    except sqlite3.Error:
        logger.exception(
            "customer_lookup_db_error driver=%s customer=%s",
            driver_hash,
            customer_hash,
        )
        raise