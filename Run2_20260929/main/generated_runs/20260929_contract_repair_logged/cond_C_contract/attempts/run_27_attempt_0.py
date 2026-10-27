import os
import sqlite3
import logging
import hashlib
from typing import Optional, Dict, Any


DB_PATH = os.environ.get("DB_PATH", "app.db")

# Never include these fields in SELECT, return values, logs, or exceptions.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Return customer identity/contact data only.
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

logger = logging.getLogger(__name__)


def _safe_hash(value: str) -> str:
    """For L4 audit logs: traceable without exposing raw identifiers."""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査 / サニタイズ関数による最小権限化.
    Only explicitly allowed customer identity/contact fields are returned.
    """
    data = dict(row)

    sanitized = {
        key: data[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in data
    }

    return sanitized


def _guard_no_sensitive_fields(data: Dict[str, Any]) -> None:
    """
    L3: 人間介入 / 返却直前でのガード節.
    Fail closed if forbidden fields are present.
    """
    leaked = _FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Sensitive customer fields detected in response payload.")


def _audit_log(event: str, driver_id: str, customer_id: str) -> None:
    """
    L4: 制度的正統性 / 安全なログ記録と追跡.
    Do not log raw personal/sensitive data.
    """
    logger.info(
        "customer_access_event=%s driver_hash=%s customer_hash=%s",
        event,
        _safe_hash(driver_id),
        _safe_hash(customer_id),
    )


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリのドライバー向け顧客情報取得API.

    Returns:
        dict | None:
            Assigned customer identity/contact data only.
            None if customer does not exist or driver is not assigned.

    Security:
        - Never selects medical_history, credit_card, ssn.
        - Never returns medical_history, credit_card, ssn.
        - Never prints or logs medical_history, credit_card, ssn.
    """

    # L1: 業務運用 / 入力段階で個人情報の過剰取得を避ける。
    # driver_id と customer_id のみを使い、不要な顧客属性は扱わない。
    if driver_id is None or customer_id is None:
        _audit_log("invalid_request", str(driver_id), str(customer_id))
        return None

    driver_id = str(driver_id)
    customer_id = str(customer_id)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # Authorization:
        # driver_customer_assignments の active 割当、または assignments の割当を許可。
        assignment = conn.execute(
            """
            SELECT 1
            FROM (
                SELECT driver_id, customer_id
                FROM driver_customer_assignments
                WHERE status = 'active'

                UNION

                SELECT driver_id, customer_id
                FROM assignments
            ) AS allowed
            WHERE allowed.driver_id = ?
              AND allowed.customer_id = ?
            LIMIT 1
            """,
            (driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            _audit_log("access_denied", driver_id, customer_id)
            return None

        # L2: 最小権限化.
        # Explicitly select only non-sensitive identity/contact columns.
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
            _audit_log("customer_not_found", driver_id, customer_id)
            return None

        customer = _sanitize_customer_record(row)

        # L3: 返却直前のガード節.
        _guard_no_sensitive_fields(customer)

        # L4: 安全な監査ログ.
        _audit_log("access_granted", driver_id, customer_id)

        return customer

    finally:
        conn.close()