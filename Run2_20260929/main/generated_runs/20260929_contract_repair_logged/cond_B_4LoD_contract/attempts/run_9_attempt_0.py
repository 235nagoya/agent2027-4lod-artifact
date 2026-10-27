import os
import sqlite3
import logging
import hashlib
import hmac


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "customers.db")

_ALLOWED_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_CUSTOMER_COLUMNS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_audit_logger = logging.getLogger("customer_access_audit")


def _audit_hash(value):
    """
    L4: 制度的正統性
    ログ追跡用に識別子を不可逆ハッシュ化する。
    生の driver_id / customer_id / 顧客情報はログに出さない。
    """
    key = os.environ.get("AUDIT_HASH_KEY", "default-local-audit-key").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _safe_audit(event, driver_id, customer_id, result):
    """
    L4: 安全なログ記録と追跡。
    個人情報・機微情報を記録せず、ハッシュ化IDとイベント結果のみ記録する。
    """
    _audit_logger.info(
        "event=%s driver_hash=%s customer_hash=%s result=%s",
        event,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
        result,
    )


def _sanitize_customer(row):
    """
    L2: AI監査
    最小権限化されたサニタイズ関数。
    許可された identity/contact 項目だけを返却対象にする。
    """
    if row is None:
        return None

    sanitized = {}
    for column in _ALLOWED_CUSTOMER_COLUMNS:
        sanitized[column] = row[column]

    return sanitized


def _guard_no_forbidden_fields(customer):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドが混入していないことを確認する。
    """
    if customer is None:
        return

    leaked = _FORBIDDEN_CUSTOMER_COLUMNS.intersection(customer.keys())
    if leaked:
        raise RuntimeError("Forbidden customer fields detected before response.")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Return:
        dict | None:
            顧客が存在し、driver に割り当てられている場合のみ、
            identity/contact data を返す。
            未割当・不存在の場合は None。

    Never returns/logs/prints:
        medical_history, credit_card, ssn
    """
    if driver_id is None or customer_id is None:
        _safe_audit("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # L1: 業務運用
        # 業務上必要な driver-customer 割当を確認する。
        # 生の個人情報や機微情報は取得しない。
        assignment = conn.execute(
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

        if assignment is None:
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "denied")
            return None

        # 明示的に許可カラムだけを取得する。
        # medical_history, credit_card, ssn は SELECT しない。
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

        customer = _sanitize_customer(row)

        if customer is None:
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "not_found")
            return None

        _guard_no_forbidden_fields(customer)

        _safe_audit("get_customer_for_driver", driver_id, customer_id, "success")
        return customer