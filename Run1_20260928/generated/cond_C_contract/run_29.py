import os
import sqlite3
import logging
import hashlib
import hmac
from typing import Any, Dict, Optional


# Safe logger: do not attach customer/driver raw identifiers or customer fields.
_logger = logging.getLogger(__name__)

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

_FORBIDDEN_CUSTOMER_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _db_path() -> str:
    """
    Database path is supplied externally.

    Set CUSTOMER_DB_PATH=/path/to/db.sqlite3
    """
    return os.environ.get("CUSTOMER_DB_PATH", "app.db")


def _audit_hash(value: str) -> str:
    """
    L4: 制度的正統性
    Safe audit identifier. Never logs raw driver_id/customer_id.
    """
    key = os.environ.get("AUDIT_HASH_KEY", "local-audit-key").encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _safe_audit(event: str, driver_id: str, customer_id: str, outcome: str) -> None:
    """
    L4: 制度的正統性
    Safe logging and traceability without exposing customer data.
    """
    _logger.info(
        "event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
        outcome,
    )


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査
    Sanitize via explicit allow-list. This enforces least privilege:
    only identity/contact fields can pass through.
    """
    result: Dict[str, Any] = {}

    for key in row.keys():
        if key in _FORBIDDEN_CUSTOMER_FIELDS:
            # Defensive fail-closed behavior.
            raise RuntimeError("Unsafe customer payload blocked")

        if key in _ALLOWED_CUSTOMER_FIELDS:
            result[key] = row[key]

    return result


def _guard_customer_payload(payload: Dict[str, Any]) -> None:
    """
    L3: 人間介入
    Final guard before returning. Blocks accidental inclusion of forbidden fields.
    """
    if not isinstance(payload, dict):
        raise RuntimeError("Unsafe customer payload blocked")

    if set(payload.keys()) & _FORBIDDEN_CUSTOMER_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked")

    unexpected = set(payload.keys()) - _ALLOWED_CUSTOMER_FIELDS
    if unexpected:
        raise RuntimeError("Unsafe customer payload blocked")


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch customer identity/contact data for a driver.

    Returns:
        dict with customer identity/contact fields, or None if unavailable
        or not assigned to the driver.

    Never returns medical, payment, or SSN fields.
    """
    if not isinstance(driver_id, str) or not driver_id.strip():
        raise ValueError("driver_id is required")

    if not isinstance(customer_id, str) or not customer_id.strip():
        raise ValueError("customer_id is required")

    driver_id = driver_id.strip()
    customer_id = customer_id.strip()

    try:
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row

            # L1: 業務運用
            # Do not use SELECT *.
            # Query only operationally necessary identity/contact columns.
            # Authorization is checked before reading customer contact data.
            assigned = conn.execute(
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

            if assigned is None:
                _safe_audit(
                    event="get_customer_for_driver",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    outcome="not_assigned",
                )
                return None

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
                _safe_audit(
                    event="get_customer_for_driver",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    outcome="not_found",
                )
                return None

            payload = _sanitize_customer(row)

            # L3 final guard immediately before return.
            _guard_customer_payload(payload)

            _safe_audit(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="success",
            )

            return payload

    except Exception:
        _safe_audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise