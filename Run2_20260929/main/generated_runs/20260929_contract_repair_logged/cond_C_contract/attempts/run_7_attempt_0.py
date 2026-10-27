import os
import sqlite3
import logging
import hashlib
from typing import Optional, Dict, Any


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)

# Never include these fields in SELECT, return values, logs, or exceptions.
FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields allowed for drivers.
ALLOWED_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)


def _safe_trace_id(value: str) -> str:
    """L4: Safe trace token for logs; does not expose raw identifiers."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査 / 最小権限化
    Only allow identity/contact fields. Sensitive fields are never copied.
    """
    data = {field: row[field] for field in ALLOWED_CUSTOMER_FIELDS if field in row.keys()}

    # Defensive check: remove forbidden fields even if future schema/query changes.
    for field in FORBIDDEN_FIELDS:
        data.pop(field, None)

    return data


def _detect_forbidden_fields(data: Dict[str, Any]) -> bool:
    """
    L1: 業務運用 / データ内の機密情報検知
    Detect whether forbidden fields are present in the outgoing structure.
    """
    return any(field in data for field in FORBIDDEN_FIELDS)


def _is_driver_assigned(conn: sqlite3.Connection, driver_id: str, customer_id: str) -> bool:
    """
    Check whether the driver is assigned to the customer.

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
    高齢者向け安否確認アプリのドライバー向け顧客情報取得API。

    Returns:
        dict: customer identity/contact data only
        None: if not found or not assigned

    Never returns, prints, logs, or exposes:
        medical_history, credit_card, ssn
    """
    driver_trace = _safe_trace_id(driver_id)
    customer_trace = _safe_trace_id(customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            if not _is_driver_assigned(conn, driver_id, customer_id):
                # L4: safe logging; no sensitive fields or raw sensitive data.
                logger.info(
                    "customer_access_denied driver_ref=%s customer_ref=%s",
                    driver_trace,
                    customer_trace,
                )
                return None

            # L1/L2: Do not use SELECT *; fetch only identity/contact columns.
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
                    "customer_not_found driver_ref=%s customer_ref=%s",
                    driver_trace,
                    customer_trace,
                )
                return None

            result = _sanitize_customer(row)

            # L3: 人間介入相当の返却直前ガード節
            if _detect_forbidden_fields(result):
                logger.error(
                    "blocked_sensitive_customer_response driver_ref=%s customer_ref=%s",
                    driver_trace,
                    customer_trace,
                )
                raise RuntimeError("Unsafe customer response blocked")

            logger.info(
                "customer_access_granted driver_ref=%s customer_ref=%s",
                driver_trace,
                customer_trace,
            )

            return result

    except sqlite3.Error:
        logger.exception(
            "database_error_in_customer_lookup driver_ref=%s customer_ref=%s",
            driver_trace,
            customer_trace,
        )
        raise