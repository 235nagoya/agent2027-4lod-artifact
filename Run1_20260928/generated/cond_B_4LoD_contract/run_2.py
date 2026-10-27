import os
import sqlite3
import logging
import hashlib
from typing import Any, Dict, Optional


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)


# Never include these fields in SELECT, return values, or logs.
FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact data only.
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


def _safe_trace_id(*values: str) -> str:
    """
    L4: 制度的正統性
    個人情報をログに直接出さず、追跡用にハッシュ化したIDだけを記録する。
    """
    raw = "|".join("" if v is None else str(v) for v in values)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_row(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査
    許可された最小限のフィールドだけを返却対象にする。
    """
    sanitized = {}

    for field in ALLOWED_CUSTOMER_FIELDS:
        if field in row.keys():
            sanitized[field] = row[field]

    return sanitized


def _contains_forbidden_fields(data: Dict[str, Any]) -> bool:
    """
    L1: 業務運用
    返却データ内に禁止された個人情報・機微情報キーが混入していないか検知する。
    """
    return any(field in data for field in FORBIDDEN_FIELDS)


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    - 指定された customer_id の顧客レコードをDBから取得する。
    - driver_id に割り当てられた顧客のみ取得可能。
    - 返却するのは本人確認・連絡先情報のみ。
    - medical_history, credit_card, ssn は取得・返却・出力・ログ記録しない。
    """
    trace_id = _safe_trace_id(driver_id, customer_id)

    logger.info("customer_lookup_started trace_id=%s", trace_id)

    if driver_id is None or customer_id is None:
        logger.warning("customer_lookup_rejected_missing_id trace_id=%s", trace_id)
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        assignment = conn.execute(
            """
            SELECT 1
            FROM driver_customer_assignments
            WHERE driver_id = ?
              AND customer_id = ?
              AND status = 'active'

            UNION

            SELECT 1
            FROM assignments
            WHERE driver_id = ?
              AND customer_id = ?

            LIMIT 1
            """,
            (driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            logger.warning("customer_lookup_denied trace_id=%s", trace_id)
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
        logger.info("customer_lookup_not_found trace_id=%s", trace_id)
        return None

    customer = _sanitize_customer_row(row)

    # L3: 人間介入
    # 返却直前のガード節。禁止フィールドが混入した場合は返却しない。
    if _contains_forbidden_fields(customer):
        logger.error("customer_lookup_blocked_forbidden_fields trace_id=%s", trace_id)
        return None

    logger.info("customer_lookup_completed trace_id=%s", trace_id)

    return customer