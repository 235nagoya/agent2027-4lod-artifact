import os
import sqlite3
import logging
import hashlib


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    返却するのは顧客の識別・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """

    # ---- L4: 制度的正統性 / 安全なログ記録と追跡 ----
    def _safe_trace_id(value):
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]

    def _safe_log(event, **fields):
        safe_fields = {
            key: _safe_trace_id(value)
            for key, value in fields.items()
            if value is not None
        }
        logger.info("%s %s", event, safe_fields)

    # ---- L2: AI監査 / サニタイズ関数による最小権限化 ----
    allowed_columns = (
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    )

    forbidden_columns = {
        "medical_history",
        "credit_card",
        "ssn",
    }

    def _sanitize_customer_row(row):
        if row is None:
            return None

        sanitized = {}
        for column in allowed_columns:
            sanitized[column] = row[column]

        return sanitized

    # ---- L1: 業務運用 / 個人情報の検知・マスキング前提の取り扱い ----
    def _contains_forbidden_data(data):
        if not isinstance(data, dict):
            return False
        return any(key in forbidden_columns for key in data.keys())

    if not driver_id or not customer_id:
        _safe_log("customer_lookup_invalid_input", driver_id=driver_id, customer_id=customer_id)
        return None

    _safe_log("customer_lookup_started", driver_id=driver_id, customer_id=customer_id)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        cur = conn.cursor()

        # driver が customer を担当していることを確認する。
        # active な driver_customer_assignments、または assignments のどちらかに存在すれば許可。
        cur.execute(
            """
            SELECT 1
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
            """,
            (customer_id, driver_id, driver_id),
        )

        if cur.fetchone() is None:
            _safe_log("customer_lookup_not_authorized_or_not_found", driver_id=driver_id, customer_id=customer_id)
            return None

        # 明示的に許可カラムのみ取得する。
        # medical_history, credit_card, ssn は SELECT しない。
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
        result = _sanitize_customer_row(row)

        # ---- L3: 人間介入 / 返却直前のガード節 ----
        if result is None:
            _safe_log("customer_lookup_not_found", driver_id=driver_id, customer_id=customer_id)
            return None

        if _contains_forbidden_data(result):
            _safe_log("customer_lookup_blocked_forbidden_fields", driver_id=driver_id, customer_id=customer_id)
            return None

        _safe_log("customer_lookup_success", driver_id=driver_id, customer_id=customer_id)
        return result

    finally:
        conn.close()