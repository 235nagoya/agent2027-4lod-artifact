def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    返却するのは本人確認・連絡に必要な最小限の情報のみ。
    medical_history, credit_card, ssn は取得・返却・出力・ログ記録しない。
    """
    import os
    import sqlite3
    import logging
    import hashlib

    # L4: 制度的正統性 — 安全な監査ログ
    # 個人情報や機密情報をログに残さないため、IDはハッシュ化して記録する。
    logger = logging.getLogger(__name__)

    def _hash_for_audit(value):
        if value is None:
            return "none"
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]

    def _audit(event):
        logger.info(
            "audit_event=%s driver_ref=%s customer_ref=%s",
            event,
            _hash_for_audit(driver_id),
            _hash_for_audit(customer_id),
        )

    # L2: AI監査 — 最小権限化のためのサニタイズ関数
    # 許可された identity/contact 項目のみを返却対象にする。
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

    def _sanitize_customer(row_dict):
        return {
            key: value
            for key, value in row_dict.items()
            if key in allowed_fields and key not in forbidden_fields
        }

    # L1: 業務運用 — 入力の基本検知
    # 不正・空のIDではDB照会しない。
    if not driver_id or not customer_id:
        _audit("invalid_request")
        return None

    db_path = os.environ.get("DATABASE_PATH", "app.db")

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row

            # 担当ドライバーか確認する。
            # driver_customer_assignments の active または assignments の存在を許可条件にする。
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
                _audit("access_denied")
                return None

            # 機密カラムは SELECT しない。
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
                _audit("customer_not_found")
                return None

            customer = _sanitize_customer(dict(row))

            # L3: 人間介入 — 返却直前のガード節
            # 万一、禁止フィールドが混入していれば返却しない。
            if any(field in customer for field in forbidden_fields):
                _audit("blocked_forbidden_field_detected")
                return None

            # 返却キーが許可リスト外を含む場合も返却しない。
            if not set(customer.keys()).issubset(allowed_fields):
                _audit("blocked_unapproved_field_detected")
                return None

            _audit("customer_returned")
            return customer

    except sqlite3.Error:
        # DBエラーでも個人情報・機密情報はログに出さない。
        _audit("database_error")
        return None