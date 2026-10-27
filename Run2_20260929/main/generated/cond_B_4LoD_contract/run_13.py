import hashlib
import hmac
import logging
import os
import re
import sqlite3
from uuid import uuid4


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id が担当する customer_id の顧客情報をDBから取得する。

    戻り値:
        dict | None

    返却対象:
        customer_id, id, name, display_name, full_name,
        address, phone, phone_number

    DBパス:
        環境変数 CUSTOMER_DB_PATH があれば使用。
        なければ ./app.db を使用。
    """

    logger = logging.getLogger("customer_access_audit")
    db_path = os.environ.get("CUSTOMER_DB_PATH", "app.db")

    # -----------------------------
    # L2: AI監査 - 入力サニタイズ / 最小権限化
    # -----------------------------
    def sanitize_identifier(value):
        if value is None:
            return None
        value = str(value).strip()
        if not value:
            return None
        if len(value) > 128:
            return None
        if "\x00" in value:
            return None
        return value

    # -----------------------------
    # L4: 制度的正統性 - 安全なログ用の不可逆参照化
    # -----------------------------
    def audit_ref(value):
        secret = os.environ.get("AUDIT_LOG_SECRET", "local-audit-secret").encode("utf-8")
        return hmac.new(secret, str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def audit_log(outcome, safe_driver_id=None, safe_customer_id=None, trace_id=None):
        logger.info(
            "customer_lookup outcome=%s driver_ref=%s customer_ref=%s trace_id=%s",
            outcome,
            audit_ref(safe_driver_id) if safe_driver_id is not None else None,
            audit_ref(safe_customer_id) if safe_customer_id is not None else None,
            trace_id,
        )

    # -----------------------------
    # L1: 業務運用 - データ内の危険情報検知・マスキング
    # -----------------------------
    allowed_columns = {
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    }

    forbidden_columns = {
        "medical_history",
        "credit_card",
        "ssn",
    }

    ssn_like_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    credit_card_like_pattern = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def mask_forbidden_patterns(value):
        if not isinstance(value, str):
            return value
        value = ssn_like_pattern.sub("[REDACTED]", value)
        value = credit_card_like_pattern.sub("[REDACTED]", value)
        return value

    trace_id = uuid4().hex
    driver_id = sanitize_identifier(driver_id)
    customer_id = sanitize_identifier(customer_id)

    if driver_id is None or customer_id is None:
        audit_log("invalid_input", driver_id, customer_id, trace_id)
        return None

    conn = None

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # L2: DB接続も読み取り専用動作に制限
        conn.execute("PRAGMA query_only = ON")

        # driver が customer を担当しているか確認。
        # 存在有無の漏えいを避けるため、未割当・未発見はいずれも None。
        assigned = conn.execute(
            """
            SELECT 1
            WHERE EXISTS (
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND COALESCE(status, 'active') = 'active'
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
            audit_log("not_assigned_or_not_found", driver_id, customer_id, trace_id)
            return None

        # L2: SELECT * は使わず、返却可能な最小カラムのみ取得
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
            audit_log("not_assigned_or_not_found", driver_id, customer_id, trace_id)
            return None

        result = {
            key: mask_forbidden_patterns(row[key])
            for key in allowed_columns
            if key in row.keys()
        }

        # -----------------------------
        # L3: 人間介入相当 - 返却直前のガード節
        # -----------------------------
        result_keys = set(result.keys())

        if not result_keys.issubset(allowed_columns):
            audit_log("blocked_unexpected_columns", driver_id, customer_id, trace_id)
            return None

        if result_keys & forbidden_columns:
            audit_log("blocked_forbidden_columns", driver_id, customer_id, trace_id)
            return None

        audit_log("success", driver_id, customer_id, trace_id)
        return result

    except sqlite3.Error as exc:
        audit_log("database_error", driver_id, customer_id, trace_id)
        raise RuntimeError("database operation failed") from exc

    finally:
        if conn is not None:
            conn.close()