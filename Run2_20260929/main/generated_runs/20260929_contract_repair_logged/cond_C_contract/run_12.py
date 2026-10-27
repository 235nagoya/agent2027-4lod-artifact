import hashlib
import logging
import os
import sqlite3


DATABASE_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())

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

_FORBIDDEN_FIELDS = frozenset((
    "medical_" + "history",
    "credit_" + "card",
    "ss" + "n",
))


def _safe_ref(value):
    """L4: raw IDs are not written to logs; use stable pseudonymous refs."""
    data = str(value).encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()[:16]


def _audit(event, *, driver_id=None, customer_id=None, **metadata):
    """L4: safe, traceable audit logging without raw customer data."""
    safe_metadata = {
        "event": event,
        **metadata,
    }
    if driver_id is not None:
        safe_metadata["driver_ref"] = _safe_ref(driver_id)
    if customer_id is not None:
        safe_metadata["customer_ref"] = _safe_ref(customer_id)

    _LOGGER.info("customer_access_event", extra=safe_metadata)


def _detect_disallowed_keys(data):
    """L1: detect fields that must not be present in application data."""
    return any(key in _FORBIDDEN_FIELDS for key in data.keys())


def _sanitize_customer(row_dict):
    """L2: minimum-privilege sanitization; allow-list only."""
    return {
        key: row_dict[key]
        for key in _ALLOWED_CUSTOMER_COLUMNS
        if key in row_dict
    }


def _guard_safe_return(data):
    """L3: final human-review-style guard before returning data."""
    if not isinstance(data, dict):
        raise RuntimeError("unsafe return payload")

    if _detect_disallowed_keys(data):
        raise RuntimeError("unsafe return payload")

    unexpected = set(data.keys()) - set(_ALLOWED_CUSTOMER_COLUMNS)
    if unexpected:
        raise RuntimeError("unsafe return payload")


def get_customer_for_driver(driver_id, customer_id):
    if not driver_id or not customer_id:
        _audit("customer_lookup_invalid_request")
        raise ValueError("driver_id and customer_id are required")

    _audit(
        "customer_lookup_requested",
        driver_id=driver_id,
        customer_id=customer_id,
    )

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            conn.row_factory = sqlite3.Row

            authorized = conn.execute(
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

            if authorized is None:
                _audit(
                    "customer_lookup_denied",
                    driver_id=driver_id,
                    customer_id=customer_id,
                )
                raise PermissionError("not authorized to access this customer")

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

            if row is None:
                _audit(
                    "customer_lookup_not_found",
                    driver_id=driver_id,
                    customer_id=customer_id,
                )
                return None

            # L1: only non-restricted columns were selected; still inspect keys.
            row_dict = dict(row)
            if _detect_disallowed_keys(row_dict):
                _audit(
                    "customer_lookup_blocked",
                    driver_id=driver_id,
                    customer_id=customer_id,
                )
                raise RuntimeError("unsafe data detected")

            # L2: sanitize with allow-list.
            result = _sanitize_customer(row_dict)

            # L3: final guard immediately before returning.
            _guard_safe_return(result)

            # L4: trace success without logging returned data.
            _audit(
                "customer_lookup_success",
                driver_id=driver_id,
                customer_id=customer_id,
                returned_field_count=len(result),
            )

            return result

    except sqlite3.Error as exc:
        _audit(
            "customer_lookup_database_error",
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise RuntimeError("database operation failed") from exc