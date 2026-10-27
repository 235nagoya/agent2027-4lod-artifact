import os
import sqlite3
import logging
import hashlib


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

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

logger = logging.getLogger(__name__)


def _hash_for_audit(value):
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _sanitize_customer_record(row):
    """
    L2: AI監査
    サニタイズ関数により、返却可能な identity/contact 情報だけに最小化する。
    """
    if row is None:
        return None

    return {
        key: row[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in row.keys()
    }


def _contains_forbidden_fields(data):
    """
    L1: 業務運用
    データ内に返却禁止の個人情報フィールドが混入していないか検知する。
    """
    if not isinstance(data, dict):
        return False
    return any(field in data for field in _FORBIDDEN_FIELDS)


def _audit_log(event, driver_id, customer_id, outcome):
    """
    L4: 制度的正統性
    個人情報を直接ログに出さず、ハッシュ化した識別子で安全に追跡可能にする。
    """
    logger.info(
        "event=%s driver_hash=%s customer_hash=%s outcome=%s",
        event,
        _hash_for_audit(driver_id),
        _hash_for_audit(customer_id),
        outcome,
    )


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    返却するのは顧客の identity/contact 情報のみ。
    medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """
    _audit_log("get_customer_for_driver.start", driver_id, customer_id, "started")

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
    """

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        customer = _sanitize_customer_record(row)

        if customer is None:
            _audit_log("get_customer_for_driver.finish", driver_id, customer_id, "not_found_or_unassigned")
            return None

        # L3: 人間介入
        # 返却直前のガード節。禁止フィールドが混入した場合は返却しない。
        if _contains_forbidden_fields(customer):
            _audit_log("get_customer_for_driver.finish", driver_id, customer_id, "blocked_forbidden_fields")
            raise RuntimeError("Unsafe customer payload blocked before return")

        _audit_log("get_customer_for_driver.finish", driver_id, customer_id, "success")
        return customer

    except Exception:
        _audit_log("get_customer_for_driver.finish", driver_id, customer_id, "error")
        raise