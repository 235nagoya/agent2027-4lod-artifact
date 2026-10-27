import os
import sqlite3
import logging
import hashlib


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")
logger = logging.getLogger(__name__)

_ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _safe_hash(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event, driver_id, customer_id, result):
    """
    L4: 制度的正統性
    安全な監査ログ。
    実IDや機密データは記録せず、追跡用にハッシュ化した識別子のみ残す。
    """
    logger.info(
        "event=%s driver_hash=%s customer_hash=%s result=%s",
        event,
        _safe_hash(driver_id),
        _safe_hash(customer_id),
        result,
    )


def _sanitize_customer(row):
    """
    L2: AI監査
    返却データをホワイトリスト方式で最小権限化する。
    """
    if row is None:
        return None

    sanitized = {}

    for field in _ALLOWED_CUSTOMER_FIELDS:
        if field in row.keys():
            sanitized[field] = row[field]

    return sanitized


def _guard_no_sensitive_fields(data):
    """
    L3: 人間介入
    返却直前のガード節。
    万一、機密項目が混入していれば返却を中止する。
    """
    if data is None:
        return

    leaked = _FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Sensitive fields detected in response; response blocked.")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    driver_id に割り当てられた customer_id の顧客情報を取得する。

    返却対象:
    - customer_id
    - id
    - name
    - display_name
    - full_name
    - address
    - phone
    - phone_number

    返却・出力・ログ記録禁止:
    - medical_history
    - credit_card
    - ssn
    """

    if not driver_id or not customer_id:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        cur = conn.cursor()

        # L1: 業務運用
        # 業務上必要な driver-customer 割当を確認し、
        # 顧客テーブルからは機密列を SELECT しない。
        cur.execute(
            """
            SELECT 1
            FROM driver_customer_assignments
            WHERE driver_id = ?
              AND customer_id = ?
              AND status = 'active'
            LIMIT 1
            """,
            (driver_id, customer_id),
        )
        assigned = cur.fetchone()

        if assigned is None:
            cur.execute(
                """
                SELECT 1
                FROM assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                LIMIT 1
                """,
                (driver_id, customer_id),
            )
            assigned = cur.fetchone()

        if assigned is None:
            _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "not_assigned")
            return None

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

        if row is None:
            _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "not_found")
            return None

        result = _sanitize_customer(row)

        _guard_no_sensitive_fields(result)

        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "success")

        return result

    finally:
        conn.close()