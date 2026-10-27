import os
import sqlite3
import logging
import hashlib


def _db_path():
    return (
        globals().get("DB_PATH")
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )


def _audit_token(value):
    """
    L4: 安全な追跡用トークン。
    生の driver_id / customer_id はログに出さず、ハッシュ化した短い識別子のみ記録する。
    """
    salt = os.environ.get("AUDIT_LOG_SALT", "default-audit-salt")
    raw = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _sanitize_customer_row(row):
    """
    L2: AI監査 / 最小権限化。
    DB行から、返却を許可する本人確認・連絡先系フィールドだけを明示的に抽出する。
    """
    allowed_fields = (
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    )

    return {field: row[field] for field in allowed_fields}


def get_customer_for_driver(driver_id, customer_id):
    logger = logging.getLogger(__name__)

    # L4: 安全なログ記録と追跡
    audit_driver = _audit_token(driver_id)
    audit_customer = _audit_token(customer_id)

    # L3: 人間介入に相当する返却前ガードの前段として、入力を厳格に確認
    if not isinstance(driver_id, str) or not driver_id.strip():
        logger.warning(
            "get_customer_for_driver.denied invalid_driver driver=%s customer=%s",
            audit_driver,
            audit_customer,
        )
        return None

    if not isinstance(customer_id, str) or not customer_id.strip():
        logger.warning(
            "get_customer_for_driver.denied invalid_customer driver=%s customer=%s",
            audit_driver,
            audit_customer,
        )
        return None

    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row

    try:
        # L1: 業務運用
        # 個人情報を含む顧客表から、必要な本人確認・連絡先データだけを列指定で取得する。
        # driver_id に紐づく担当顧客であることも確認する。
        row = conn.execute(
            """
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
                          AND LOWER(COALESCE(dca.status, 'active')) = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
                  )
            LIMIT 1
            """,
            (customer_id, driver_id, driver_id),
        ).fetchone()

        if row is None:
            logger.info(
                "get_customer_for_driver.not_found_or_not_assigned driver=%s customer=%s",
                audit_driver,
                audit_customer,
            )
            return None

        result = _sanitize_customer_row(row)

        # L3: 返却直前ガード。
        # 返却可能なキーだけで構成されていることを最終確認する。
        allowed_return_keys = {
            "customer_id",
            "id",
            "name",
            "display_name",
            "full_name",
            "address",
            "phone",
            "phone_number",
        }

        if set(result.keys()) - allowed_return_keys:
            logger.error(
                "get_customer_for_driver.blocked unexpected_fields driver=%s customer=%s",
                audit_driver,
                audit_customer,
            )
            return None

        logger.info(
            "get_customer_for_driver.success driver=%s customer=%s",
            audit_driver,
            audit_customer,
        )

        return result

    finally:
        conn.close()