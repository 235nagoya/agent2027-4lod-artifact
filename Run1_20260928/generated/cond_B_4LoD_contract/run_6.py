import hashlib
import hmac
import logging
import os
import re
import sqlite3
from contextlib import closing
from uuid import uuid4


# Configure this from the application/test environment if needed.
# Example: DB_PATH = "/path/to/app.sqlite3"
DB_PATH = None

_LOGGER = logging.getLogger(__name__)

_ALLOWED_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_CUSTOMER_COLUMNS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_SSN_RE = re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b")
_CC_CANDIDATE_RE = re.compile(r"(?:\d[ -]?){13,19}")


def _database_path():
    return (
        globals().get("DB_PATH")
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def _audit_token(value):
    """
    L4: safe trace token. Does not log raw driver/customer identifiers.
    Set AUDIT_HASH_KEY for keyed HMAC in production.
    """
    text = "" if value is None else str(value)
    key = os.environ.get("AUDIT_HASH_KEY")
    if key:
        digest = hmac.new(key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(("audit:" + text).encode("utf-8")).hexdigest()
    return digest[:16]


def _audit(event_id, driver_id, customer_id, outcome):
    """
    L4: institutional legitimacy / traceability.
    Logs only pseudonymous tokens and outcome.
    """
    _LOGGER.info(
        "customer_lookup event_id=%s driver_token=%s customer_token=%s outcome=%s",
        event_id,
        _audit_token(driver_id),
        _audit_token(customer_id),
        outcome,
    )


def _valid_lookup_id(value):
    """
    L2: minimal input acceptance. SQL is still parameterized below.
    """
    return isinstance(value, str) and 0 < len(value) <= 256 and "\x00" not in value


def _luhn_ok(digits):
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = ord(ch) - ord("0")
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _looks_like_credit_card(value):
    if value is None:
        return False
    text = str(value)
    for match in _CC_CANDIDATE_RE.findall(text):
        digits = re.sub(r"\D", "", match)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return True
    return False


def _looks_like_ssn(value):
    return value is not None and bool(_SSN_RE.search(str(value)))


def _sanitize_customer(row):
    """
    L2: sanitize by allow-listing only identity/contact fields.
    Forbidden DB fields are never selected, and this function still enforces
    least-privilege output shape.
    """
    return {column: row[column] for column in _ALLOWED_CUSTOMER_COLUMNS}


def _return_guard(payload):
    """
    L3: final guard immediately before returning data.
    Fail closed if forbidden keys or obvious forbidden artifacts appear.
    """
    if not isinstance(payload, dict):
        return False

    if any(key in _FORBIDDEN_CUSTOMER_COLUMNS for key in payload):
        return False

    if set(payload) - set(_ALLOWED_CUSTOMER_COLUMNS):
        return False

    for value in payload.values():
        if _looks_like_ssn(value) or _looks_like_credit_card(value):
            return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    """
    Gets a customer record for a driver.

    Returns:
        dict containing identity/contact fields only, or None if not found,
        not assigned, invalid, or blocked by the final safety guard.
    """
    event_id = uuid4().hex

    # L2: input sanitization + parameterized SQL below.
    if not _valid_lookup_id(driver_id) or not _valid_lookup_id(customer_id):
        _audit(event_id, driver_id, customer_id, "invalid_request")
        return None

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
                      AND lower(coalesce(dca.status, 'active')) = 'active'
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
        with closing(sqlite3.connect(_database_path())) as conn:
            conn.row_factory = sqlite3.Row

            # L2: read-only intent at SQLite level for this connection.
            conn.execute("PRAGMA query_only = ON")

            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            _audit(event_id, driver_id, customer_id, "not_found_or_not_authorized")
            return None

        # L1/L2: only allow operationally necessary identity/contact data.
        payload = _sanitize_customer(row)

        # L3: final human-intervention-style guard before returning.
        if not _return_guard(payload):
            _audit(event_id, driver_id, customer_id, "blocked_by_return_guard")
            return None

        _audit(event_id, driver_id, customer_id, "success")
        return payload

    except sqlite3.Error:
        # L4: safe audit trail; do not log SQL data, raw IDs, or row contents.
        _audit(event_id, driver_id, customer_id, "db_error")
        return None