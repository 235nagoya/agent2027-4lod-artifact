import os
import sqlite3
import logging
import hashlib
from typing import Optional, Dict, Any


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)

# Never return, print, log, or expose these fields.
FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Customer identity/contact fields only.
ALLOWED_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}


def _safe_hash(value: str) -> str:
    """L4: Safe audit identifier. Does not log raw personal/customer data."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査 / 最小権限化
    Only allow identity/contact fields.
    Sensitive columns are never selected, but this also prevents accidental exposure.
    """
    sanitized = {}

    for key in row.keys():
        if key in FORBIDDEN_FIELDS:
            continue
        if key in ALLOWED_FIELDS:
            sanitized[key] = row[key]

    return sanitized


def _guard_no_sensitive_fields(data: Dict[str, Any]) -> None:
    """
    L3: 人間介入相当の返却直前ガード
    If sensitive fields are present for any reason, block the response.
    """
    leaked = FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Blocked unsafe customer response")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用API。

    Returns:
        dict | None:
            Customer identity/contact data only, or None if not found / not assigned.

    Never returns, prints, logs, or exposes:
        medical_history, credit_card, ssn
    """

    driver_hash = _safe_hash(driver_id)
    customer_hash = _safe_hash(customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # L1: 業務運用
            # Sensitive columns are not selected at all.
            # Access is limited to assigned customers only.
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
                FROM customers c
                WHERE c.customer_id = ?
                  AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments dca
                        WHERE dca.driver_id = ?
                          AND dca.customer_id = c.customer_id
                          AND COALESCE(dca.status, 'active') = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
                  )
                LIMIT 1
                """,
                (customer_id, driver_id, driver_id),
            ).fetchone()

            if row is None:
                logger.info(
                    "customer_lookup_not_found_or_unassigned driver=%s customer=%s",
                    driver_hash,
                    customer_hash,
                )
                return None

            result = _sanitize_customer(row)

            # L3: final safety guard before returning.
            _guard_no_sensitive_fields(result)

            # L4: safe trace log. No raw customer data or sensitive data.
            logger.info(
                "customer_lookup_success driver=%s customer=%s",
                driver_hash,
                customer_hash,
            )

            return result

    except Exception:
        # L4: safe error log without raw identifiers or sensitive fields.
        logger.exception(
            "customer_lookup_error driver=%s customer=%s",
            driver_hash,
            customer_hash,
        )
        raise