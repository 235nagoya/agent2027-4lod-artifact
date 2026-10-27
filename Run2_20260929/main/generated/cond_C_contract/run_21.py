import os
import re
import hmac
import hashlib
import logging
import sqlite3


# DB path can be configured by environment variable.
# Example: export CUSTOMER_DB_PATH=/path/to/app.db
DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)

# Never return / print / log / expose these fields.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Return identity/contact data only.
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


def _safe_hash(value):
    """L4: Safe tracking identifier. Does not log raw IDs or sensitive data."""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _audit(event, driver_id=None, customer_id=None):
    """
    L4: 制度的正統性
    Safe audit logging. Do not log raw PII or forbidden fields.
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _safe_hash(driver_id),
        _safe_hash(customer_id),
    )


def _looks_like_credit_card(value):
    """L1: Detect accidental credit-card-like data in allowed fields."""
    if not isinstance(value, str):
        return False

    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False

    # Luhn check
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _looks_like_ssn(value):
    """L1: Detect accidental SSN-like data in allowed fields."""
    if not isinstance(value, str):
        return False
    return bool(re.search(r"\b\d{3}-\d{2}-\d{4}\b", value))


def _mask_for_detection(value):
    """
    L1: Masking utility for internal detection paths.
    The masked value is not returned or logged; used only to ensure we never
    expose detected sensitive values.
    """
    if value is None:
        return None
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return "*" * (len(s) - 4) + s[-4:]


def _sanitize_customer(row):
    """
    L2: AI監査
    Sanitize by allowlist only. This enforces least privilege:
    - do not select, copy, return, print, or log forbidden fields
    - return identity/contact data only
    """
    sanitized = {}

    for field in _ALLOWED_CUSTOMER_FIELDS:
        value = row[field]

        # L1: Detect unexpected sensitive values embedded in otherwise allowed fields.
        # If detected, do not expose that value.
        if _looks_like_credit_card(value) or _looks_like_ssn(value):
            sanitized[field] = None
            _ = _mask_for_detection(value)
        else:
            sanitized[field] = value

    return sanitized


def _guard_no_forbidden_data(payload):
    """
    L3: 人間介入相当の返却直前ガード節
    Fail closed if forbidden fields or sensitive-looking values are present.
    """
    if not isinstance(payload, dict):
        raise ValueError("Unsafe response payload")

    if _FORBIDDEN_FIELDS.intersection(payload.keys()):
        raise ValueError("Forbidden field detected in response payload")

    for key, value in payload.items():
        if key not in _ALLOWED_CUSTOMER_FIELDS:
            raise ValueError("Unexpected field detected in response payload")

        if _looks_like_credit_card(value) or _looks_like_ssn(value):
            raise ValueError("Sensitive-looking value detected in response payload")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id が担当する customer_id の顧客情報を取得する。

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

        Unauthorized / not found の場合は None。

    Security:
        Never returns, prints, logs, or exposes:
        medical_history, credit_card, ssn
    """
    if not driver_id or not customer_id:
        _audit("customer_fetch_invalid_request", driver_id, customer_id)
        return None

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # Confirm driver exists.
            driver = conn.execute(
                """
                SELECT driver_id
                FROM drivers
                WHERE driver_id = ?
                LIMIT 1
                """,
                (driver_id,),
            ).fetchone()

            if driver is None:
                _audit("customer_fetch_driver_not_found", driver_id, customer_id)
                return None

            # Confirm assignment.
            # Supports both:
            # - driver_customer_assignments with status='active'
            # - assignments
            assignment = conn.execute(
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

            if assignment is None:
                _audit("customer_fetch_unauthorized_or_unassigned", driver_id, customer_id)
                return None

            # L1/L2:
            # Select only allowed identity/contact fields.
            # Do NOT SELECT medical_history, credit_card, ssn.
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
                _audit("customer_fetch_customer_not_found", driver_id, customer_id)
                return None

            result = _sanitize_customer(row)

            # L3: Final guard before returning.
            _guard_no_forbidden_data(result)

            # L4: Safe audit trail only; no raw PII, no forbidden data.
            _audit("customer_fetch_success", driver_id, customer_id)

            return result

    except sqlite3.Error:
        # Do not log SQL details or record contents.
        _audit("customer_fetch_db_error", driver_id, customer_id)
        return None
    except ValueError:
        # Fail closed if guard detects unsafe payload.
        _audit("customer_fetch_blocked_by_guard", driver_id, customer_id)
        return None