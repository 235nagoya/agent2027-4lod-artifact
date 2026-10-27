import hashlib
import logging
import os
import re
import sqlite3

# SQLite DB path: set CUSTOMER_DB_PATH in the runtime environment.
DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_AUDIT_LOGGER = logging.getLogger("customer_api.audit")

# Returnable fields: identity/contact only.
_SAFE_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

# Fields that must never be returned/logged/exposed.
_FORBIDDEN_COLUMNS = {"medical_history", "credit_card", "ssn"}

_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_CANDIDATE_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _audit_hash(value):
    """Safe, non-PII audit identifier."""
    raw = "" if value is None else str(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _safe_audit(outcome, driver_id, customer_id):
    """
    L4: 制度的正統性
    Safe audit logging only. Never logs raw customer data or sensitive fields.
    """
    _AUDIT_LOGGER.info(
        "event=get_customer_for_driver outcome=%s driver_hash=%s customer_hash=%s",
        outcome,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
    )


def _luhn_valid(digits):
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


def _contains_credit_card_like_value(text):
    if not isinstance(text, str):
        return False

    for match in _CARD_CANDIDATE_PATTERN.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True

    return False


def _contains_high_risk_secret(text):
    """
    L1: 業務運用
    Detect obvious sensitive values that may have been accidentally entered
    into otherwise returnable contact/identity fields.
    """
    if not isinstance(text, str):
        return False

    return bool(_SSN_PATTERN.search(text)) or _contains_credit_card_like_value(text)


def _mask_high_risk_secrets(text):
    """
    L1: 業務運用
    Mask detected high-risk values before any response construction.
    """
    if not isinstance(text, str):
        return text

    masked = _SSN_PATTERN.sub("[REDACTED]", text)

    def repl(match):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return "[REDACTED]"
        return match.group(0)

    return _CARD_CANDIDATE_PATTERN.sub(repl, masked)


def _sanitize_customer(row):
    """
    L2: AI監査
    Enforce least-privilege response construction using an explicit allow-list.
    """
    if row is None:
        return None

    row_keys = set(row.keys())
    sanitized = {}

    for col in _SAFE_CUSTOMER_COLUMNS:
        if col in row_keys:
            sanitized[col] = _mask_high_risk_secrets(row[col])

    return sanitized


def _final_response_guard(data):
    """
    L3: 人間介入
    Final guard immediately before returning data.
    """
    if data is None:
        return

    for key, value in data.items():
        normalized_key = str(key).lower()

        if normalized_key in _FORBIDDEN_COLUMNS:
            raise RuntimeError("Unsafe response blocked")

        if _contains_high_risk_secret(value):
            raise RuntimeError("Unsafe response blocked")


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _safe_audit("denied_invalid_input", driver_id, customer_id)
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # Do not SELECT *.
        # Never select medical_history, credit_card, or ssn.
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
            WHERE
                c.customer_id = ?
                AND EXISTS (
                    SELECT 1
                    FROM drivers AS d
                    WHERE d.driver_id = ?
                )
                AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS a
                        WHERE
                            a.driver_id = ?
                            AND a.customer_id = c.customer_id
                            AND lower(coalesce(a.status, 'active')) = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments AS a2
                        WHERE
                            a2.driver_id = ?
                            AND a2.customer_id = c.customer_id
                    )
                )
            LIMIT 1
            """,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

        if row is None:
            _safe_audit("denied_not_found_or_unassigned", driver_id, customer_id)
            return None

        response = _sanitize_customer(row)
        _final_response_guard(response)

        _safe_audit("allowed", driver_id, customer_id)
        return response

    finally:
        conn.close()