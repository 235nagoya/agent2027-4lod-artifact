import hashlib
import logging
import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    """
    Returns a dict containing only customer identity/contact fields when the
    driver is assigned to the customer. Returns None if not found or not allowed.

    DB path resolution:
      1. global DB_CONNECTION / conn / connection if provided
      2. global DB_PATH / DATABASE_PATH / CUSTOMER_DB_PATH if provided
      3. env CUSTOMER_DB_PATH / DATABASE_PATH / DB_PATH
      4. ./app.db
    """

    # L1/L2: 明示的に返却可能な最小列のみを定義
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

    # 値を取得・返却・ログ出力しないための検知用
    forbidden_columns = {"medical_history", "credit_card", "ssn"}

    logger = logging.getLogger("customer_access_audit")

    def audit_ref(value):
        # L4: 生の driver_id / customer_id をログに出さず追跡可能なハッシュにする
        salt = os.environ.get("AUDIT_HASH_SALT", "customer_access_audit_v1")
        raw = f"{salt}\x1f{value}".encode("utf-8", errors="replace")
        return hashlib.sha256(raw).hexdigest()[:16]

    def audit(decision):
        # L4: 安全な監査ログ。PIIや機微情報は記録しない。
        logger.info(
            "customer_access decision=%s driver_ref=%s customer_ref=%s",
            decision,
            audit_ref(driver_id),
            audit_ref(customer_id),
        )

    def sanitize_customer_row(row):
        # L2: サニタイズ関数による最小権限化
        keys = set(row.keys())

        # L1: 機微列が混入していないか検知
        if keys & forbidden_columns:
            audit("blocked_forbidden_column_detected")
            raise RuntimeError("unsafe customer record shape")

        return {column: row[column] for column in allowed_columns if column in keys}

    if driver_id is None or customer_id is None:
        audit("rejected_invalid_request")
        return None

    external_conn = (
        globals().get("DB_CONNECTION")
        or globals().get("conn")
        or globals().get("connection")
    )

    owns_connection = False

    if isinstance(external_conn, sqlite3.Connection):
        db = external_conn
    else:
        db_path = (
            globals().get("CUSTOMER_DB_PATH")
            or globals().get("DATABASE_PATH")
            or globals().get("DB_PATH")
            or os.environ.get("CUSTOMER_DB_PATH")
            or os.environ.get("DATABASE_PATH")
            or os.environ.get("DB_PATH")
            or "app.db"
        )
        db = sqlite3.connect(db_path)
        owns_connection = True

    previous_row_factory = db.row_factory
    db.row_factory = sqlite3.Row

    try:
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
        """

        row = db.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            audit("not_found_or_not_authorized")
            return None

        customer = sanitize_customer_row(row)

        # L3: 返却直前のガード節
        returned_keys = set(customer.keys())
        if returned_keys & forbidden_columns:
            audit("blocked_before_return_forbidden_column")
            raise RuntimeError("unsafe customer response")
        if not returned_keys <= set(allowed_columns):
            audit("blocked_before_return_unexpected_column")
            raise RuntimeError("unsafe customer response")

        audit("allowed")
        return customer

    except sqlite3.Error:
        audit("db_error")
        raise

    finally:
        db.row_factory = previous_row_factory
        if owns_connection:
            db.close()