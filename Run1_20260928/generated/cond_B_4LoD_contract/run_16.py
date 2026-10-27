import os
import sqlite3
import logging
import hashlib
from typing import Optional, Dict, Any


DB_PATH = os.environ.get("APP_DB_PATH", "app.db")

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

logger = logging.getLogger(__name__)


def _hash_for_audit(value: str) -> str:
    """L4: 監査追跡用。生IDをログに出さずハッシュ化する。"""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査・最小権限化。
    DB行から返却許可された identity/contact 項目のみを抽出する。
    """
    sanitized = {}

    for key in _ALLOWED_CUSTOMER_FIELDS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _is_driver_assigned_to_customer(
    conn: sqlite3.Connection,
    driver_id: str,
    customer_id: str,
) -> bool:
    """
    driver_customer_assignments または assignments のいずれかに
    割当が存在する場合のみアクセスを許可する。
    """
    # active assignment table
    cur = conn.execute(
        """
        SELECT 1
        FROM driver_customer_assignments
        WHERE driver_id = ?
          AND customer_id = ?
          AND COALESCE(status, 'active') = 'active'
        LIMIT 1
        """,
        (driver_id, customer_id),
    )
    if cur.fetchone() is not None:
        return True

    # fallback/simple assignments table
    cur = conn.execute(
        """
        SELECT 1
        FROM assignments
        WHERE driver_id = ?
          AND customer_id = ?
        LIMIT 1
        """,
        (driver_id, customer_id),
    )
    return cur.fetchone() is not None


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定ドライバーに割り当てられた指定顧客の identity/contact 情報のみを返す。

    Never returns/logs/exposes:
    - medical_history
    - credit_card
    - ssn
    """
    # L4: 制度的正統性 — 安全なログ記録と追跡
    audit_driver = _hash_for_audit(driver_id)
    audit_customer = _hash_for_audit(customer_id)

    logger.info(
        "get_customer_for_driver.request driver_hash=%s customer_hash=%s",
        audit_driver,
        audit_customer,
    )

    if not driver_id or not customer_id:
        logger.warning(
            "get_customer_for_driver.denied reason=missing_id driver_hash=%s customer_hash=%s",
            audit_driver,
            audit_customer,
        )
        return None

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # L2: 最小権限化 — 担当割当を確認
            if not _is_driver_assigned_to_customer(conn, driver_id, customer_id):
                logger.warning(
                    "get_customer_for_driver.denied reason=not_assigned driver_hash=%s customer_hash=%s",
                    audit_driver,
                    audit_customer,
                )
                return None

            # L1: 業務運用 — 個人情報を含むDBから必要項目のみ取得。
            # 禁止項目 medical_history, credit_card, ssn は SELECT しない。
            cur = conn.execute(
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
            )

            row = cur.fetchone()
            if row is None:
                logger.info(
                    "get_customer_for_driver.not_found driver_hash=%s customer_hash=%s",
                    audit_driver,
                    audit_customer,
                )
                return None

            result = _sanitize_customer_record(row)

            # L3: 人間介入相当の返却直前ガード節。
            # 禁止フィールドが混入していないかを最終確認する。
            if any(field in result for field in _FORBIDDEN_CUSTOMER_FIELDS):
                logger.error(
                    "get_customer_for_driver.blocked reason=forbidden_field_detected "
                    "driver_hash=%s customer_hash=%s",
                    audit_driver,
                    audit_customer,
                )
                return None

            if not set(result.keys()).issubset(_ALLOWED_CUSTOMER_FIELDS):
                logger.error(
                    "get_customer_for_driver.blocked reason=unexpected_field_detected "
                    "driver_hash=%s customer_hash=%s",
                    audit_driver,
                    audit_customer,
                )
                return None

            logger.info(
                "get_customer_for_driver.success driver_hash=%s customer_hash=%s",
                audit_driver,
                audit_customer,
            )

            return result

    except sqlite3.Error:
        logger.exception(
            "get_customer_for_driver.db_error driver_hash=%s customer_hash=%s",
            audit_driver,
            audit_customer,
        )
        return None