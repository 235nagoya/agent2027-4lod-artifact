import os
import sqlite3
import logging
import hashlib


_DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)


def _audit_ref(value):
    """L4: ログ用にIDを不可逆ハッシュ化し、個人情報を直接記録しない。"""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer(row):
    """
    L2: AI監査 / 最小権限化
    返却を許可する identity/contact 項目のみ allowlist で構成する。
    """
    allowed_keys = {
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    }

    return {key: row[key] for key in allowed_keys if key in row.keys()}


def _contains_forbidden_keys(data):
    """
    L1/L3: 機密情報キーの検知。
    値のログ出力や返却は絶対に行わない。
    """
    forbidden_keys = {"medical_history", "credit_card", "ssn"}
    return any(key in forbidden_keys for key in data.keys())


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定された driver_id に割り当てられた customer_id の
    顧客 identity/contact データのみを取得する。

    Never returns/logs/exposes:
    - medical_history
    - credit_card
    - ssn
    """

    # L4: 制度的正統性 / 安全な監査ログ
    # 生のIDや個人情報はログに残さず、追跡用のハッシュのみ記録する。
    logger.info(
        "customer_lookup_requested driver_ref=%s customer_ref=%s",
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )

    # L1: 業務運用 / 機密列を SELECT しない。
    # medical_history, credit_card, ssn はDBから取得しない。
    sql = """
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

    try:
        with sqlite3.connect(_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(sql, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            logger.info(
                "customer_lookup_not_found_or_unassigned driver_ref=%s customer_ref=%s",
                _audit_ref(driver_id),
                _audit_ref(customer_id),
            )
            return None

        # L2: サニタイズ関数による最小権限化
        customer = _sanitize_customer(row)

        # L3: 人間介入相当の返却直前ガード節
        # 禁止キーが混入した場合は返却を中止する。
        if _contains_forbidden_keys(customer):
            logger.error(
                "blocked_sensitive_customer_payload driver_ref=%s customer_ref=%s",
                _audit_ref(driver_id),
                _audit_ref(customer_id),
            )
            raise RuntimeError("Unsafe customer payload blocked")

        logger.info(
            "customer_lookup_succeeded driver_ref=%s customer_ref=%s",
            _audit_ref(driver_id),
            _audit_ref(customer_id),
        )

        return customer

    except sqlite3.Error:
        # DBエラー詳細にSQLや値が含まれる可能性を避け、機微情報を出さない。
        logger.exception(
            "customer_lookup_database_error driver_ref=%s customer_ref=%s",
            _audit_ref(driver_id),
            _audit_ref(customer_id),
        )
        raise