import os
import sqlite3
import logging
import hashlib

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    配送/訪問担当 driver に割り当てられた customer のうち、
    業務上必要な本人確認・連絡先情報のみを返す。

    Never returns:
      - medical_history
      - credit_card
      - ssn
    """

    # -----------------------------
    # L4: 制度的正統性
    # 安全なログ記録と追跡
    # PIIや機密情報をログに出さず、IDもハッシュ化して記録する
    # -----------------------------
    def _hash_for_log(value):
        if value is None:
            return "none"
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]

    safe_driver_ref = _hash_for_log(driver_id)
    safe_customer_ref = _hash_for_log(customer_id)

    logger.info(
        "get_customer_for_driver_requested driver_ref=%s customer_ref=%s",
        safe_driver_ref,
        safe_customer_ref,
    )

    # -----------------------------
    # L2: AI監査
    # サニタイズ関数による最小権限化
    # 返却可能なフィールドを allowlist で固定する
    # -----------------------------
    allowed_fields = {
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    }

    forbidden_fields = {
        "medical_history",
        "credit_card",
        "ssn",
    }

    def sanitize_customer(row_dict):
        return {
            key: value
            for key, value in row_dict.items()
            if key in allowed_fields and key not in forbidden_fields
        }

    # -----------------------------
    # L1: 業務運用
    # データ内の個人情報・機密情報を検知し、返却対象から除外する
    # そもそもSQLでも機密カラムを取得しない
    # -----------------------------
    query = """
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
    """

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # driver が対象 customer を担当しているか確認する。
            # driver_customer_assignments は active のみ許可。
            assignment = conn.execute(
                """
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND COALESCE(status, 'active') = 'active'

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
                logger.warning(
                    "get_customer_for_driver_denied driver_ref=%s customer_ref=%s",
                    safe_driver_ref,
                    safe_customer_ref,
                )
                return None

            row = conn.execute(query, (customer_id,)).fetchone()

            if row is None:
                logger.info(
                    "get_customer_for_driver_not_found driver_ref=%s customer_ref=%s",
                    safe_driver_ref,
                    safe_customer_ref,
                )
                return None

            customer = sanitize_customer(dict(row))

            # -----------------------------
            # L3: 人間介入
            # 返却直前のガード節
            # 機密フィールドが混入していないことを最終確認する
            # -----------------------------
            leaked_fields = forbidden_fields.intersection(customer.keys())
            if leaked_fields:
                logger.error(
                    "get_customer_for_driver_blocked_sensitive_field driver_ref=%s customer_ref=%s",
                    safe_driver_ref,
                    safe_customer_ref,
                )
                return None

            # allowlist 外のキーが混入していた場合も返却しない
            unexpected_fields = set(customer.keys()) - allowed_fields
            if unexpected_fields:
                logger.error(
                    "get_customer_for_driver_blocked_unexpected_field driver_ref=%s customer_ref=%s",
                    safe_driver_ref,
                    safe_customer_ref,
                )
                return None

            logger.info(
                "get_customer_for_driver_success driver_ref=%s customer_ref=%s",
                safe_driver_ref,
                safe_customer_ref,
            )

            return customer

    except sqlite3.Error:
        logger.exception(
            "get_customer_for_driver_database_error driver_ref=%s customer_ref=%s",
            safe_driver_ref,
            safe_customer_ref,
        )
        return None