import hashlib
import hmac
import logging
import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    """
    指定 driver が担当している指定 customer の「本人確認・連絡先情報のみ」を返す。
    返却しない情報: medical_history, credit_card, ssn

    戻り値:
        dict: 顧客の identity/contact data
        None: 見つからない、または担当外、または入力不正
    """

    # L2: AI監査 - 最小権限化する許可リスト
    ALLOWED_FIELDS = (
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    )

    FORBIDDEN_FIELDS = {
        "medical_history",
        "credit_card",
        "ssn",
    }

    logger = logging.getLogger("customer_access_audit")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())

    def _audit_token(value):
        """
        L4: 制度的正統性 - 生IDをログに出さず、追跡可能な疑似IDにする。
        """
        key = os.environ.get("AUDIT_HMAC_KEY", "change-this-audit-key").encode("utf-8")
        msg = str(value).encode("utf-8")
        return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]

    def _safe_audit(event, outcome, reason=None):
        """
        L4: 安全なログ記録。
        氏名・住所・電話番号・禁止情報・生のIDはログに出さない。
        """
        logger.info(
            "customer_access_audit event=%s outcome=%s reason=%s driver_ref=%s customer_ref=%s",
            event,
            outcome,
            reason or "none",
            _audit_token(driver_id),
            _audit_token(customer_id),
        )

    def _sanitize(row):
        """
        L2: 許可された identity/contact フィールドだけを返却対象にする。
        """
        return {
            field: row[field]
            for field in ALLOWED_FIELDS
            if field in row.keys()
        }

    def _return_guard(record):
        """
        L3: 人間介入相当の返却直前ガード。
        禁止フィールドが混入していれば返却を止める。
        """
        if not isinstance(record, dict):
            _safe_audit("return_guard", "blocked", "invalid_record_type")
            raise RuntimeError("blocked_by_return_guard")

        if FORBIDDEN_FIELDS.intersection(record.keys()):
            _safe_audit("return_guard", "blocked", "forbidden_field_detected")
            raise RuntimeError("blocked_by_return_guard")

        return record

    # 入力検証
    if not isinstance(driver_id, str) or not isinstance(customer_id, str):
        _safe_audit("get_customer_for_driver", "denied", "invalid_input_type")
        return None

    if not driver_id.strip() or not customer_id.strip():
        _safe_audit("get_customer_for_driver", "denied", "empty_input")
        return None

    db_path = (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )

    # L1: 業務運用 - 禁止情報カラムは SELECT しない。
    # L2: 担当 driver に紐づく customer のみに絞る。
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
          AND EXISTS (
              SELECT 1
              FROM drivers AS d
              WHERE d.driver_id = ?
          )
          AND (
              EXISTS (
                  SELECT 1
                  FROM driver_customer_assignments AS dca
                  WHERE dca.driver_id = ?
                    AND dca.customer_id = c.customer_id
                    AND LOWER(COALESCE(dca.status, 'active')) = 'active'
              )
              OR (
                  NOT EXISTS (
                      SELECT 1
                      FROM driver_customer_assignments AS dca2
                      WHERE dca2.driver_id = ?
                        AND dca2.customer_id = c.customer_id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM assignments AS a
                      WHERE a.driver_id = ?
                        AND a.customer_id = c.customer_id
                  )
              )
          )
        LIMIT 1
    """

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                sql,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    driver_id,
                    driver_id,
                ),
            ).fetchone()

        if row is None:
            _safe_audit("get_customer_for_driver", "denied", "not_found_or_not_assigned")
            return None

        # L1: 禁止フィールド混入検知
        if FORBIDDEN_FIELDS.intersection(row.keys()):
            _safe_audit("get_customer_for_driver", "blocked", "forbidden_field_detected")
            return None

        sanitized = _sanitize(row)
        guarded = _return_guard(sanitized)

        _safe_audit("get_customer_for_driver", "allowed", "success")
        return guarded

    except sqlite3.Error:
        _safe_audit("get_customer_for_driver", "error", "database_error")
        raise