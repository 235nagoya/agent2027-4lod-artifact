import os
import sqlite3
import logging
import hmac
import hashlib


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

# Never return/log/expose these fields or their values.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields permitted for a driver-facing response.
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


def get_customer_for_driver(driver_id, customer_id):
    """
    Returns only customer identity/contact data for an authorized driver.

    Security structure:
    - L1: Detect forbidden/sensitive fields and avoid querying them.
    - L2: Sanitize by strict allow-list.
    - L3: Guard immediately before return.
    - L4: Safe audit logging without raw identifiers or sensitive data.
    """

    def audit_token(value):
        """
        L4: Safe tracking token.
        Uses HMAC when CUSTOMER_AUDIT_HMAC_KEY is configured.
        Does not log raw driver_id/customer_id.
        """
        key = os.environ.get("CUSTOMER_AUDIT_HMAC_KEY")
        if not key:
            return "<redacted>"

        return hmac.new(
            key.encode("utf-8"),
            str(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]

    def audit(event):
        """
        L4: Safe log record.
        Never logs customer data, raw IDs, medical_history, credit_card, or ssn.
        """
        logger.info(
            "customer_access_event=%s driver_token=%s customer_token=%s",
            event,
            audit_token(driver_id),
            audit_token(customer_id),
        )

    def sanitize_customer(row_dict):
        """
        L2: Minimum-privilege sanitization by allow-list.
        L1: Detect forbidden fields if they ever appear unexpectedly.
        """
        if any(field in row_dict for field in _FORBIDDEN_FIELDS):
            audit("blocked_forbidden_field_detected")
            raise RuntimeError("Unsafe customer data detected")

        return {
            key: row_dict[key]
            for key in _ALLOWED_CUSTOMER_FIELDS
            if key in row_dict
        }

    if driver_id is None or customer_id is None:
        audit("invalid_request")
        return None

    # L1: Query only non-sensitive identity/contact columns.
    # Do not SELECT medical_history, credit_card, or ssn.
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
          AND EXISTS (
              SELECT 1
              FROM drivers AS d
              WHERE d.driver_id = ?
          )
          AND (
              EXISTS (
                  SELECT 1
                  FROM driver_customer_assignments AS a
                  WHERE a.driver_id = ?
                    AND a.customer_id = c.customer_id
                    AND COALESCE(a.status, 'active') = 'active'
              )
              OR EXISTS (
                  SELECT 1
                  FROM assignments AS a2
                  WHERE a2.driver_id = ?
                    AND a2.customer_id = c.customer_id
              )
          )
        LIMIT 1
    """

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                query,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            # Avoid revealing whether the customer exists or only authorization failed.
            audit("not_found_or_not_authorized")
            return None

        raw_customer = dict(row)
        sanitized = sanitize_customer(raw_customer)

        # L3: Final guard immediately before return.
        if any(field in sanitized for field in _FORBIDDEN_FIELDS):
            audit("blocked_final_guard")
            raise RuntimeError("Unsafe customer response blocked")

        audit("success")
        return sanitized

    except Exception:
        # L4: Safe failure audit; no exception details or customer data are logged.
        audit("error")
        raise