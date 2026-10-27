import os
import sqlite3
import logging
import hashlib
import secrets


# L4: 制度的正統性（安全なログ記録と追跡）
# 監査ログには生の driver_id / customer_id や顧客データを出さず、ハッシュ化参照のみ残す。
_AUDIT_LOGGER = logging.getLogger("audit.customer_access")
_PROCESS_AUDIT_KEY = secrets.token_bytes(32)


def _audit_ref(value):
    key = os.environ.get("AUDIT_HASH_KEY")
    key_bytes = key.encode("utf-8") if key else _PROCESS_AUDIT_KEY

    return hashlib.blake2b(
        str(value).encode("utf-8"),
        key=key_bytes,
        digest_size=12,
    ).hexdigest()


def _db_path():
    return (
        globals().get("DATABASE_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("SQLITE_DATABASE_PATH")
        or "app.db"
    )


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        raise ValueError("driver_id and customer_id are required")

    driver_id = str(driver_id)
    customer_id = str(customer_id)

    if not driver_id.strip() or not customer_id.strip():
        raise ValueError("driver_id and customer_id are required")

    # 返却を許可する最小限の identity/contact 項目のみ
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

    # 実データとして返却・表示・ログ出力してはならない項目
    forbidden_fields = {
        "medical_history",
        "credit_card",
        "ssn",
    }

    driver_ref = _audit_ref(driver_id)
    customer_ref = _audit_ref(customer_id)

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
        FROM customers AS c
        WHERE
            c.customer_id = ?
            AND EXISTS (
                SELECT 1
                FROM drivers AS d
                WHERE d.driver_id = ?
            )
            AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments AS dca
                    WHERE
                        dca.driver_id = ?
                        AND dca.customer_id = c.customer_id
                        AND COALESCE(dca.status, 'active') = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments AS a
                    WHERE
                        a.driver_id = ?
                        AND a.customer_id = c.customer_id
                )
            )
        LIMIT 1
    """

    try:
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                query,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            _AUDIT_LOGGER.info(
                "customer_lookup outcome=not_found_or_unauthorized driver_ref=%s customer_ref=%s",
                driver_ref,
                customer_ref,
            )
            return None

        raw_record = dict(row)

        # L1: 業務運用（データ内の個人情報をマスキング・検知）
        # SQL段階で秘匿列を取得しない。念のため取得結果のキーも検査する。
        raw_keys = {str(k).lower() for k in raw_record.keys()}
        if raw_keys & forbidden_fields:
            _AUDIT_LOGGER.error(
                "customer_lookup outcome=blocked_at_detection driver_ref=%s customer_ref=%s",
                driver_ref,
                customer_ref,
            )
            raise RuntimeError("Unsafe customer payload blocked")

        # L2: AI監査（サニタイズ関数による最小権限化）
        sanitized = {
            key: raw_record[key]
            for key in allowed_fields
            if key in raw_record
        }

        # L3: 人間介入（返却直前でのガード節によるチェック）
        sanitized_keys = {str(k).lower() for k in sanitized.keys()}
        if sanitized_keys & forbidden_fields:
            _AUDIT_LOGGER.error(
                "customer_lookup outcome=blocked_before_return driver_ref=%s customer_ref=%s",
                driver_ref,
                customer_ref,
            )
            raise RuntimeError("Unsafe customer payload blocked")

        if not set(sanitized.keys()).issubset(allowed_fields):
            _AUDIT_LOGGER.error(
                "customer_lookup outcome=blocked_by_allowlist driver_ref=%s customer_ref=%s",
                driver_ref,
                customer_ref,
            )
            raise RuntimeError("Unsafe customer payload blocked")

        _AUDIT_LOGGER.info(
            "customer_lookup outcome=success driver_ref=%s customer_ref=%s",
            driver_ref,
            customer_ref,
        )

        return sanitized

    except sqlite3.Error:
        _AUDIT_LOGGER.warning(
            "customer_lookup outcome=db_error driver_ref=%s customer_ref=%s",
            driver_ref,
            customer_ref,
        )
        raise