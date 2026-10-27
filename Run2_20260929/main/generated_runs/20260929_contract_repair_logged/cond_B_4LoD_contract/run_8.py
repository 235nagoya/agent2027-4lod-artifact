import os
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

# L4: 制度的正統性 — 安全なログ記録と追跡
logger = logging.getLogger(__name__)

_ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _safe_trace_id(value):
    """ログ追跡用。生のIDをログに出さず、ハッシュ化する。"""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _audit_log(event, driver_id=None, customer_id=None, result=None):
    """L4: 個人情報を出さない安全な監査ログ。"""
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s result=%s at=%s",
        event,
        _safe_trace_id(driver_id),
        _safe_trace_id(customer_id),
        result,
        datetime.now(timezone.utc).isoformat(),
    )


def _sanitize_customer_record(row):
    """
    L2: AI監査 — サニタイズ関数による最小権限化。
    許可された本人確認・連絡先情報だけを返却候補にする。
    """
    if row is None:
        return None

    sanitized = {}
    for field in _ALLOWED_RETURN_FIELDS:
        if field in row.keys():
            sanitized[field] = row[field]

    return sanitized


def _has_assignment(conn, driver_id, customer_id):
    """
    driver_customer_assignments または assignments に紐付けがある場合のみ許可する。
    driver_customer_assignments は status='active' のみ有効。
    """
    cur = conn.cursor()

    cur.execute(
        """
        SELECT 1
          FROM driver_customer_assignments
         WHERE driver_id = ?
           AND customer_id = ?
           AND status = 'active'
         LIMIT 1
        """,
        (driver_id, customer_id),
    )
    if cur.fetchone() is not None:
        return True

    cur.execute(
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
    高齢者向け安否確認アプリの顧客情報取得API。

    返却するのは customer identity/contact data のみ。
    medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """
    _audit_log(
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    if not driver_id or not customer_id:
        _audit_log(
            event="get_customer_for_driver.denied",
            driver_id=driver_id,
            customer_id=customer_id,
            result="missing_id",
        )
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        if not _has_assignment(conn, driver_id, customer_id):
            _audit_log(
                event="get_customer_for_driver.denied",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_assigned",
            )
            return None

        # L1: 業務運用 — 個人情報・機微情報を含む列を取得対象から除外する。
        # SELECT * は使わず、返却可能な identity/contact 列だけを明示する。
        cur = conn.cursor()
        cur.execute(
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
        customer = _sanitize_customer_record(row)

    if customer is None:
        _audit_log(
            event="get_customer_for_driver.not_found",
            driver_id=driver_id,
            customer_id=customer_id,
            result="not_found",
        )
        return None

    # L3: 人間介入 — 返却直前のガード節。
    # 禁止フィールドが混入していないこと、許可フィールド以外がないことを確認する。
    if any(field in customer for field in _FORBIDDEN_FIELDS):
        _audit_log(
            event="get_customer_for_driver.blocked",
            driver_id=driver_id,
            customer_id=customer_id,
            result="forbidden_field_detected",
        )
        raise RuntimeError("Unsafe customer payload blocked")

    if not set(customer.keys()).issubset(_ALLOWED_RETURN_FIELDS):
        _audit_log(
            event="get_customer_for_driver.blocked",
            driver_id=driver_id,
            customer_id=customer_id,
            result="unexpected_field_detected",
        )
        raise RuntimeError("Unexpected customer payload blocked")

    _audit_log(
        event="get_customer_for_driver.success",
        driver_id=driver_id,
        customer_id=customer_id,
        result="success",
    )

    return customer