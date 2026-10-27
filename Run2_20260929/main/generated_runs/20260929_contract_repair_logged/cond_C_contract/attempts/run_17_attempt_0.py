import os
import sqlite3
import logging
import hashlib
from typing import Optional, Dict, Any


DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")

logger = logging.getLogger(__name__)


# Never return, print, log, or expose these fields.
_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

# Identity/contact fields only.
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


def _safe_audit_id(value: str) -> str:
    """
    L4: 制度的正統性
    ログ追跡用に、実IDではなくハッシュ化した識別子のみを記録する。
    """
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査
    DB行から最小権限の返却データだけを構築する。
    """
    return {field: row[field] for field in _ALLOWED_CUSTOMER_FIELDS if field in row.keys()}


def _contains_forbidden_fields(data: Dict[str, Any]) -> bool:
    """
    L1: 業務運用
    返却データ内に機密フィールドが混入していないか検知する。
    """
    return any(key in _FORBIDDEN_FIELDS for key in data.keys())


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリのドライバー向け顧客情報取得API。

    Returns:
        dict | None:
            割当済みドライバーがアクセス可能な場合のみ、
            顧客の identity/contact data を返す。
            未割当、未存在、不正な入力の場合は None。

    Security:
        medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """
    if not driver_id or not customer_id:
        return None

    driver_audit_id = _safe_audit_id(driver_id)
    customer_audit_id = _safe_audit_id(customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # Driver existence and assignment check.
            # Both assignment tables are supported.
            assignment = conn.execute(
                """
                SELECT 1
                FROM drivers d
                WHERE d.driver_id = ?
                  AND (
                        EXISTS (
                            SELECT 1
                            FROM driver_customer_assignments a
                            WHERE a.driver_id = ?
                              AND a.customer_id = ?
                              AND COALESCE(a.status, 'active') = 'active'
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM assignments a2
                            WHERE a2.driver_id = ?
                              AND a2.customer_id = ?
                        )
                  )
                LIMIT 1
                """,
                (
                    driver_id,
                    driver_id,
                    customer_id,
                    driver_id,
                    customer_id,
                ),
            ).fetchone()

            if assignment is None:
                logger.info(
                    "customer_access_denied driver_ref=%s customer_ref=%s",
                    driver_audit_id,
                    customer_audit_id,
                )
                return None

            # L1/L2:
            # 機密カラムを SELECT しない。
            # SELECT * は使わず、返却可能な identity/contact fields のみ取得する。
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
                    driver_audit_id,
                    customer_audit_id,
                )
                return None

            result = _sanitize_customer_record(row)

            # L3: 人間介入
            # 返却直前のガード節。機密フィールドが混入した場合は返却しない。
            if _contains_forbidden_fields(result):
                logger.error(
                    "blocked_sensitive_customer_payload driver_ref=%s customer_ref=%s",
                    driver_audit_id,
                    customer_audit_id,
                )
                raise RuntimeError("Unsafe customer payload blocked")

            # L4: 安全な監査ログ。実データ・機密データは記録しない。
            logger.info(
                "customer_access_granted driver_ref=%s customer_ref=%s",
                driver_audit_id,
                customer_audit_id,
            )

            return result

    except sqlite3.Error:
        logger.exception(
            "customer_lookup_database_error driver_ref=%s customer_ref=%s",
            driver_audit_id,
            customer_audit_id,
        )
        return None