import hashlib
import logging
import os
import re
import sqlite3
from contextlib import closing


# DB path can be configured by environment variable.
# Example: export CUSTOMER_DB_PATH=/path/to/app.sqlite3
DB_PATH = os.environ.get("CUSTOMER_DB_PATH", os.environ.get("DATABASE_PATH", "app.db"))

logger = logging.getLogger(__name__)


# Never select, return, print, or log these fields.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

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

# L1: accidental sensitive-data detection patterns.
_CREDIT_CARD_LIKE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_SSN_LIKE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b")


def _safe_ref(value):
    """
    L4: Safe audit reference.
    Do not log raw driver_id/customer_id. Log only a short one-way digest.
    """
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _audit(event, driver_id=None, customer_id=None):
    """
    L4: Safe logging and traceability.
    No raw PII or returned customer data is logged.
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
    )


def _looks_sensitive(value):
    """
    L1: Detect accidental inclusion of highly sensitive data in allowed columns.
    """
    if not isinstance(value, str):
        return False

    compact_digits = re.sub(r"\D", "", value)

    # Credit-card-like values.
    if _CREDIT_CARD_LIKE_RE.search(value) and 13 <= len(compact_digits) <= 19:
        return True

    # SSN-like values.
    if _SSN_LIKE_RE.search(value):
        return True

    return False


def _mask_if_sensitive(value):
    """
    L1: Mask detected highly sensitive values if they accidentally appear
    inside identity/contact columns.
    """
    if _looks_sensitive(value):
        return "[REDACTED]"
    return value


def _sanitize_customer_record(row):
    """
    L2: Sanitization by whitelist/minimum privilege.
    Only identity/contact fields are allowed through.
    """
    if row is None:
        return None

    sanitized = {}
    for field in _ALLOWED_CUSTOMER_FIELDS:
        sanitized[field] = _mask_if_sensitive(row[field])

    return sanitized


def _guard_before_return(customer):
    """
    L3: Human-intervention-style final guard immediately before returning.
    Blocks forbidden fields or detected sensitive values.
    """
    if customer is None:
        return None

    keys = set(customer.keys())
    forbidden_present = keys & _FORBIDDEN_FIELDS
    if forbidden_present:
        raise RuntimeError("Unsafe customer payload blocked before return")

    unexpected_keys = keys - set(_ALLOWED_CUSTOMER_FIELDS)
    if unexpected_keys:
        raise RuntimeError("Unexpected customer payload fields blocked before return")

    for value in customer.values():
        if _looks_sensitive(value):
            raise RuntimeError("Sensitive customer payload value blocked before return")

    return customer


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch a customer's identity/contact data for an assigned driver.

    Returns:
        dict with identity/contact fields, or None if not found/not assigned.

    Never returns:
        medical_history, credit_card, ssn
    """
    _audit("get_customer_for_driver_requested", driver_id, customer_id)

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

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row

        row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

    customer = _sanitize_customer_record(row)
    customer = _guard_before_return(customer)

    if customer is None:
        _audit("get_customer_for_driver_not_found_or_unauthorized", driver_id, customer_id)
        return None

    _audit("get_customer_for_driver_returned", driver_id, customer_id)
    return customer