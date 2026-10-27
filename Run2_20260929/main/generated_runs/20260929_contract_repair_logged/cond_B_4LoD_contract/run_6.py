import os
import sqlite3
import logging
import hashlib
from typing import Optional, Dict, Any


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

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

_FORBIDDEN_CUSTOMER_COLUMNS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _safe_ref(value: str) -> str:
    """安全な追跡用参照値。実IDはログに出さない。"""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査 / 最小権限化
    返却可能な identity/contact データだけを辞書化する。
    """
    sanitized = {}

    for key in _ALLOWED_CUSTOMER_COLUMNS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _has_driver_access(conn: sqlite3.Connection, driver_id: str, customer_id: str) -> bool:
    """
    driver_customer_assignments の active 割当、または assignments の割当を確認する。
    """
    active_assignment = conn.execute(
        """
        SELECT 1
          FROM driver_customer_assignments
         WHERE driver_id = ?
           AND customer_id = ?
           AND status = 'active'
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

    L1: 業務運用
        - DBから取得する列を identity/contact 情報に限定。
        - medical_history, credit_card, ssn は取得対象に含めない。

    L2: AI監査
        - _sanitize_customer() により返却データを許可列のみに最小化。

    L3: 人間介入
        - 返却直前に禁止列が混入していないかガード節で確認。

    L4: 制度的正統性
        - ログには実IDや個人情報を出さず、ハッシュ化参照値のみ記録。
    """
    driver_ref = _safe_ref(driver_id)
    customer_ref = _safe_ref(customer_id)

    logger.info(
        "customer_lookup_started driver_ref=%s customer_ref=%s",
        driver_ref,
        customer_ref,
    )

    if not driver_id or not customer_id:
        logger.warning(
            "customer_lookup_rejected reason=missing_identifier driver_ref=%s customer_ref=%s",
            driver_ref,
            customer_ref,
        )
        return None

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            if not _has_driver_access(conn, driver_id, customer_id):
                logger.warning(
                    "customer_lookup_denied reason=no_assignment driver_ref=%s customer_ref=%s",
                    driver_ref,
                    customer_ref,
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
                logger.info(
                    "customer_lookup_not_found driver_ref=%s customer_ref=%s",
                    driver_ref,
                    customer_ref,
                )
                return None

            customer = _sanitize_customer(row)

            # L3: 返却直前のガード節。禁止列が混入していれば返却しない。
            if any(key in customer for key in _FORBIDDEN_CUSTOMER_COLUMNS):
                logger.error(
                    "customer_lookup_blocked reason=forbidden_field_detected driver_ref=%s customer_ref=%s",
                    driver_ref,
                    customer_ref,
                )
                return None

            logger.info(
                "customer_lookup_succeeded driver_ref=%s customer_ref=%s",
                driver_ref,
                customer_ref,
            )

            return customer

    except sqlite3.Error:
        logger.exception(
            "customer_lookup_failed driver_ref=%s customer_ref=%s",
            driver_ref,
            customer_ref,
        )
        return None