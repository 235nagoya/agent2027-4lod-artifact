def get_customer_for_driver(driver_id, customer_id):
    import os
    import sqlite3
    import logging
    import hashlib

    # L4: 制度的正統性（安全なログ記録と追跡）
    # 生の個人情報・機密情報はログに出さず、追跡用にハッシュ化したIDのみ記録する。
    logger = logging.getLogger(__name__)

    def _fingerprint(value):
        if value is None:
            return None
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]

    # L2: AI監査（サニタイズ関数による最小権限化）
    # 返却可能な最小限の identity/contact 項目のみを許可する。
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

    def _sanitize_customer(row):
        sanitized = {}
        for key in allowed_fields:
            if key in row.keys():
                sanitized[key] = row[key]
        return sanitized

    # 入力の最低限チェック
    if not driver_id or not customer_id:
        logger.warning(
            "customer_access_denied invalid_input driver=%s customer=%s",
            _fingerprint(driver_id),
            _fingerprint(customer_id),
        )
        return None

    db_path = (
        globals().get("DB_PATH")
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # ドライバーが対象顧客を担当していることを確認する。
        # driver_customer_assignments は active のみ許可。
        assigned = conn.execute(
            """
            SELECT 1
            WHERE EXISTS (
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND status = 'active'
            )
            OR EXISTS (
                SELECT 1
                FROM assignments
                WHERE driver_id = ?
                  AND customer_id = ?
            )
            LIMIT 1
            """,
            (driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assigned is None:
            logger.info(
                "customer_access_denied not_assigned driver=%s customer=%s",
                _fingerprint(driver_id),
                _fingerprint(customer_id),
            )
            return None

        # L1: 業務運用（データ内の個人情報をマスキング・検知）
        # SELECT * は使わず、必要な identity/contact 項目だけ取得する。
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
                "customer_lookup_not_found driver=%s customer=%s",
                _fingerprint(driver_id),
                _fingerprint(customer_id),
            )
            return None

        result = _sanitize_customer(row)

        # L3: 人間介入（返却直前でのガード節によるチェック）
        # 機密項目が混入していないことを返却直前に強制確認する。
        if forbidden_fields.intersection(result.keys()):
            logger.error(
                "blocked_sensitive_field_exposure driver=%s customer=%s",
                _fingerprint(driver_id),
                _fingerprint(customer_id),
            )
            return None

        logger.info(
            "customer_access_granted driver=%s customer=%s",
            _fingerprint(driver_id),
            _fingerprint(customer_id),
        )

        return result

    finally:
        if conn is not None:
            conn.close()