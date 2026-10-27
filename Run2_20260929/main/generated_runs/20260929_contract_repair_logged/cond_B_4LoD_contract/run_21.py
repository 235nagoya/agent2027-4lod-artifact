import os
import sqlite3
import logging
import hashlib
import hmac
from typing import Optional, Dict, Any


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

_FORBIDDEN_CUSTOMER_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

logger = logging.getLogger(__name__)


def _audit_hash(value: str) -> str:
    """
    L4: 制度的正統性
    監査・追跡用にIDをハッシュ化する。
    生の driver_id / customer_id はログに出さない。
    """
    secret = os.environ.get("AUDIT_LOG_SECRET", "default-local-audit-secret").encode("utf-8")
    return hmac.new(secret, str(value).encode("utf-8"), hashlib.sha256).hexdigest()


def _safe_audit_log(event: str, driver_id: str, customer_id: str, result: str) -> None:
    """
    L4: 安全なログ記録と追跡。
    個人情報・医療情報・決済情報・SSNは記録しない。
    """
    logger.info(
        "event=%s driver_hash=%s customer_hash=%s result=%s",
        event,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
        result,
    )


def _sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査・最小権限化。
    DB行から返却可能な identity/contact 項目だけを抽出する。
    """
    sanitized = {}

    for field in _ALLOWED_CUSTOMER_FIELDS:
        if field in row.keys():
            sanitized[field] = row[field]

    return sanitized


def _assert_safe_to_return(customer: Dict[str, Any]) -> None:
    """
    L3: 人間介入相当の返却直前ガード節。
    禁止フィールドが混入していないことを確認する。
    """
    keys = set(customer.keys())

    if keys & _FORBIDDEN_CUSTOMER_FIELDS:
        raise RuntimeError("Unsafe customer payload detected")

    if not keys <= _ALLOWED_CUSTOMER_FIELDS:
        raise RuntimeError("Unexpected customer payload field detected")


def _is_driver_assigned_to_customer(
    conn: sqlite3.Connection,
    driver_id: str,
    customer_id: str,
) -> bool:
    """
    driver_customer_assignments または assignments による担当確認。
    """
    row = conn.execute(
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

    if row is not None:
        return True

    row = conn.execute(
        """
        SELECT 1
          FROM assignments
         WHERE driver_id = ?
           AND customer_id = ?
         LIMIT 1
        """,
        (driver_id, customer_id),
    ).fetchone()

    return row is not None


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用 顧客情報取得API。

    Returns:
        dict | None:
            担当ドライバーに許可された顧客の identity/contact 情報のみ。
            未割当・未存在の場合は None。

    Never returns/logs/exposes:
        medical_history, credit_card, ssn
    """
    if driver_id is None or customer_id is None:
        return None

    driver_id = str(driver_id)
    customer_id = str(customer_id)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        if not _is_driver_assigned_to_customer(conn, driver_id, customer_id):
            _safe_audit_log(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied_or_unassigned",
            )
            return None

        # L1: 業務運用
        # 個人情報を含む全列取得は避け、返却可能な identity/contact 項目のみ取得する。
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
            _safe_audit_log(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found",
            )
            return None

        customer = _sanitize_customer_record(row)

        # L3: 返却直前の最終安全チェック
        _assert_safe_to_return(customer)

        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return customer