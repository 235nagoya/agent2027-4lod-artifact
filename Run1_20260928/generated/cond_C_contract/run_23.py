import hashlib
import logging
import os
import sqlite3
from typing import Any, Dict, Mapping, Optional


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# Never expose these fields.
_FORBIDDEN_FIELDS = frozenset({"medical_history", "credit_card", "ssn"})

# Return customer identity/contact data only.
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


def _audit_hash(value: str) -> str:
    """L4: ログ追跡用の安全な不可逆ID化。生IDはログに出さない。"""
    salt = os.environ.get("AUDIT_LOG_SALT", "default-audit-salt")
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event: str, driver_id: str, customer_id: str, outcome: str) -> None:
    """L4: 機密情報・個人情報を含めない安全な監査ログ。"""
    logger.info(
        "event=%s driver_hash=%s customer_hash=%s outcome=%s",
        event,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
        outcome,
    )


def _contains_forbidden_key(data: Mapping[str, Any]) -> bool:
    """L1: 返却候補データ内に禁止キーが混入していないか検知。"""
    return any(str(key).lower() in _FORBIDDEN_FIELDS for key in data.keys())


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: サニタイズ関数による最小権限化。
    DB行から許可された identity/contact 項目だけを取り出す。
    """
    raw = dict(row)

    if _contains_forbidden_key(raw):
        raise RuntimeError("Forbidden customer fields detected before sanitization")

    return {
        field: raw.get(field)
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in raw
    }


def _guard_return_payload(payload: Mapping[str, Any]) -> None:
    """
    L3: 返却直前のガード節。
    medical_history, credit_card, ssn が含まれていれば返却を止める。
    """
    if _contains_forbidden_key(payload):
        raise RuntimeError("Unsafe payload blocked")


def get_customer_for_driver(driver_id, customer_id):
    if not isinstance(driver_id, str) or not driver_id:
        raise ValueError("driver_id must be a non-empty string")
    if not isinstance(customer_id, str) or not customer_id:
        raise ValueError("customer_id must be a non-empty string")

    columns = ", ".join(f"c.{name}" for name in _ALLOWED_CUSTOMER_FIELDS)

    query = f"""
        SELECT {columns}
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
                OR
                EXISTS (
                    SELECT 1
                      FROM assignments AS a
                     WHERE a.driver_id = ?
                       AND a.customer_id = c.customer_id
                )
           )
         LIMIT 1
    """

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            row = conn.execute(
                query,
                (customer_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            _safe_audit_log(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_not_authorized",
            )
            return None

        sanitized = _sanitize_customer(row)

        # L3: human-intervention 相当の最終安全確認ポイント。
        _guard_return_payload(sanitized)

        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
        )

        return sanitized

    except Exception:
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise