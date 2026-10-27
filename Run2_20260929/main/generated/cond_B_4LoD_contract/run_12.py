import hashlib
import logging
import os
import sqlite3


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

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

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

logger = logging.getLogger(__name__)


def _safe_ref(value):
    """L4: Safe audit reference; do not log raw identifiers or PII."""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_record(record):
    """
    L2: AI監査 / 最小権限化
    Only identity/contact fields are retained.
    Forbidden fields are never returned.
    """
    if record is None:
        return None

    sanitized = {}
    for key in _ALLOWED_CUSTOMER_FIELDS:
        if key in record.keys():
            sanitized[key] = record[key]

    return sanitized


def _guard_customer_response(customer):
    """
    L3: 人間介入相当の返却直前ガード
    Prevent accidental exposure of forbidden fields.
    """
    if customer is None:
        return None

    leaked = _FORBIDDEN_FIELDS.intersection(customer.keys())
    if leaked:
        raise RuntimeError("unsafe customer response blocked")

    return customer


def _is_driver_assigned(conn, driver_id, customer_id):
    """
    Checks whether the driver is assigned to the customer.
    Supports both assignment tables described in the contract.
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

    if active_assignment:
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
    高齢者向け安否確認アプリの顧客情報取得API。

    Returns customer identity/contact data only.
    Never returns, prints, logs, or exposes forbidden sensitive fields.
    """
    if not driver_id or not customer_id:
        logger.info(
            "customer_lookup_denied reason=missing_input driver_ref=%s customer_ref=%s",
            _safe_ref(driver_id),
            _safe_ref(customer_id),
        )
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        if not _is_driver_assigned(conn, driver_id, customer_id):
            logger.info(
                "customer_lookup_denied reason=not_assigned driver_ref=%s customer_ref=%s",
                _safe_ref(driver_id),
                _safe_ref(customer_id),
            )
            return None

        # L1: 業務運用
        # Select only identity/contact columns. Sensitive columns are not queried.
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
                "customer_lookup_not_found driver_ref=%s customer_ref=%s",
                _safe_ref(driver_id),
                _safe_ref(customer_id),
            )
            return None

        customer = _sanitize_customer_record(row)
        customer = _guard_customer_response(customer)

        logger.info(
            "customer_lookup_success driver_ref=%s customer_ref=%s fields=%s",
            _safe_ref(driver_id),
            _safe_ref(customer_id),
            sorted(customer.keys()),
        )

        return customer