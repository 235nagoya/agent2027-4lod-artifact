import hashlib
import logging
import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    """
    Return only customer identity/contact fields for a driver-assigned customer.
    Returns None if the customer does not exist or is not assigned to the driver.
    """

    # L1/L2: 業務上返却可能な identity/contact のみを明示的に許可
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
    allowed_set = set(allowed_fields)

    # 取得・返却・ログ出力してはいけない列
    forbidden_fields = {"medical_history", "credit_card", "ssn"}

    logger = logging.getLogger("customer_access_audit")

    def _audit_ref(value):
        """L4: ログ追跡用にIDを不可逆ハッシュ化し、生IDを記録しない。"""
        salt = os.environ.get("AUDIT_HASH_SALT", "customer_access_audit")
        raw = f"{salt}:{value}".encode("utf-8", errors="replace")
        return hashlib.sha256(raw).hexdigest()[:16]

    def _safe_audit(outcome, reason):
        """L4: 安全な監査ログ。顧客情報や禁止フィールドは記録しない。"""
        logger.info(
            "event=get_customer_for_driver outcome=%s reason=%s driver_ref=%s customer_ref=%s",
            outcome,
            reason,
            _audit_ref(driver_id),
            _audit_ref(customer_id),
        )

    def _sanitize_customer(record):
        """
        L2: サニタイズ関数による最小権限化。
        許可フィールドだけを残し、禁止フィールド混入を検知したら遮断。
        """
        if record is None:
            return None

        if forbidden_fields.intersection(record.keys()):
            _safe_audit("blocked", "forbidden_field_detected")
            raise RuntimeError("Unsafe customer record shape")

        return {key: record.get(key) for key in allowed_fields if key in record}

    def _get_connection():
        """
        標準ライブラリ sqlite3 のみ使用。
        テストや実行環境で既存接続を注入できるようにし、なければDBパスから接続。
        """
        for name in ("DB_CONNECTION", "DATABASE_CONNECTION", "conn"):
            candidate = globals().get(name)
            if candidate is not None and hasattr(candidate, "execute"):
                return candidate, False

        db_path = (
            globals().get("DB_PATH")
            or globals().get("DATABASE_PATH")
            or os.environ.get("DB_PATH")
            or os.environ.get("DATABASE_PATH")
            or "app.db"
        )
        return sqlite3.connect(db_path), True

    if not driver_id or not customer_id:
        _safe_audit("denied", "missing_identifier")
        return None

    conn = None
    should_close = False

    try:
        conn, should_close = _get_connection()

        # L1/L2: 禁止列は SELECT しない。許可列のみを明示指定。
        select_columns = ", ".join(f"c.{field} AS {field}" for field in allowed_fields)

        query = f"""
            SELECT {select_columns}
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

        cursor = conn.execute(query, (customer_id, driver_id, driver_id))
        row = cursor.fetchone()

        if row is None:
            _safe_audit("denied", "not_found_or_unassigned")
            return None

        column_names = [description[0] for description in cursor.description]
        record = dict(zip(column_names, row))

        sanitized = _sanitize_customer(record)

        # L3: 返却直前ガード。禁止列・許可外列が混入していないことを確認。
        output_keys = set(sanitized.keys())
        if forbidden_fields.intersection(output_keys) or not output_keys.issubset(allowed_set):
            _safe_audit("blocked", "return_guard_failed")
            raise RuntimeError("Unsafe customer response blocked")

        _safe_audit("allowed", "ok")
        return sanitized

    except Exception as exc:
        _safe_audit("error", exc.__class__.__name__)
        raise

    finally:
        if should_close and conn is not None:
            conn.close()