import os
import re
import hmac
import json
import time
import hashlib
import logging
import sqlite3


# Configure via environment or override this module-level constant.
DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "customers.db")

_LOGGER = logging.getLogger(__name__)

# Never return / log / expose these.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields only.
_ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

# L1: data-level sensitive-pattern detection/masking for accidental leakage
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_ok(value):
    digits = [int(ch) for ch in re.sub(r"\D", "", value)]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _mask_sensitive_text(value):
    if not isinstance(value, str):
        return value

    value = _SSN_RE.sub("[REDACTED_SSN]", value)

    def repl(match):
        candidate = match.group(0)
        return "[REDACTED_CARD]" if _luhn_ok(candidate) else candidate

    return _CC_CANDIDATE_RE.sub(repl, value)


def _stable_digest(value):
    """
    L4: safe trace identifier.
    Logs only a keyed digest, never the raw driver_id/customer_id.
    """
    key = os.environ.get("AUDIT_LOG_SALT", "local-audit-salt").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _audit(event, driver_id, customer_id, outcome):
    """
    L4: safe audit logging.
    No PII, no medical_history, no credit_card, no ssn, no raw IDs.
    """
    record = {
        "ts": int(time.time()),
        "event": event,
        "driver_ref": _stable_digest(driver_id),
        "customer_ref": _stable_digest(customer_id),
        "outcome": outcome,
    }
    _LOGGER.info("customer_access_audit=%s", json.dumps(record, separators=(",", ":")))


def _sanitize_customer(row):
    """
    L2: minimum-privilege sanitizer.
    Only identity/contact fields are allowed through.
    """
    if row is None:
        return None

    result = {}
    for field in _ALLOWED_RETURN_FIELDS:
        if field in row.keys():
            result[field] = _mask_sensitive_text(row[field])

    return result


def _guard_return_payload(payload):
    """
    L3: final human-intervention-style guard before returning.
    Ensures forbidden fields are absent and only allowed fields are returned.
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe payload blocked before return")

    if not keys <= _ALLOWED_RETURN_FIELDS:
        raise RuntimeError("Unexpected field blocked before return")

    for forbidden in _FORBIDDEN_FIELDS:
        if forbidden in payload:
            raise RuntimeError("Forbidden field blocked before return")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch a customer's identity/contact data for an assigned driver.

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

            None is returned when the customer does not exist or the driver is
            not assigned to that customer.

    Sensitive fields medical_history, credit_card, and ssn are never selected,
    returned, printed, or logged.
    """
    if driver_id is None or customer_id is None:
        _audit("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        return None

    driver_id = str(driver_id)
    customer_id = str(customer_id)

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

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        try:
            row = conn.execute(sql, (customer_id, driver_id, driver_id)).fetchone()
        finally:
            conn.close()

        payload = _sanitize_customer(row)
        payload = _guard_return_payload(payload)

        _audit(
            "get_customer_for_driver",
            driver_id,
            customer_id,
            "returned" if payload is not None else "not_found_or_not_assigned",
        )

        return payload

    except Exception:
        _audit("get_customer_for_driver", driver_id, customer_id, "error")
        raise