import hashlib
import logging
import os
import sqlite3
from typing import Any, Dict, Optional


DB_PATH = os.environ.get("DATABASE_PATH", "app.db")

logger = logging.getLogger(__name__)

# Never expose these fields.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields only.
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


def _safe_hash(value: Any) -> str:
    """L4: PIIを直接ログに出さず、追跡用にハッシュ化する。"""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: 最小権限化。
    DBから取得した行を、返却許可された identity/contact 項目だけに制限する。
    """
    sanitized: Dict[str, Any] = {}

    for key in row.keys():
        if key in _FORBIDDEN_FIELDS:
            # 念のため検知するが、値は保持・返却・ログ出力しない。
            logger.warning("Forbidden customer field detected and removed: field=%s", key)
            continue

        if key in _ALLOWED_CUSTOMER_FIELDS:
            sanitized[key] = row[key]

    return sanitized


def _final_guard(record: Dict[str, Any]) -> None:
    """
    L3: 返却直前のガード節。
    禁止フィールドが混入していないことを確認する。
    """
    leaked = _FORBIDDEN_FIELDS.intersection(record.keys())
    if leaked:
        logger.error("Blocked customer response due to forbidden fields: fields=%s", sorted(leaked))
        raise RuntimeError("Unsafe customer response blocked")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Returns:
        dict | None:
            担当ドライバーに紐づく顧客が存在する場合は identity/contact 情報のみ返す。
            未存在または未割当の場合は None。

    Never returns, prints, logs, or exposes:
        medical_history, credit_card, ssn
    """
    driver_hash = _safe_hash(driver_id)
    customer_hash = _safe_hash(customer_id)

    logger.info(
        "Customer lookup requested: driver_ref=%s customer_ref=%s",
        driver_hash,
        customer_hash,
    )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # L1/L2:
        # - SELECT句で identity/contact 列だけを明示取得する。
        # - medical_history, credit_card, ssn はDBから取得しない。
        # - 担当割当がある場合のみ取得する。
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
              AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca
                        WHERE dca.driver_id = ?
                          AND dca.customer_id = c.customer_id
                          AND COALESCE(dca.status, 'active') = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
              )
            LIMIT 1
        """

        row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            logger.info(
                "Customer lookup returned no authorized record: driver_ref=%s customer_ref=%s",
                driver_hash,
                customer_hash,
            )
            return None

        record = _sanitize_customer_record(row)

        # L3: 返却直前チェック
        _final_guard(record)

        # L4: 安全な監査ログ。PII本体は記録しない。
        logger.info(
            "Customer lookup succeeded: driver_ref=%s customer_ref=%s returned_fields=%s",
            driver_hash,
            customer_hash,
            sorted(record.keys()),
        )

        return record

    finally:
        conn.close()