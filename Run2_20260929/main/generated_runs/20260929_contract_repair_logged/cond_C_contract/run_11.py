import hashlib
import logging
import os
import sqlite3


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_ALLOWED_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def _safe_audit_id(value):
    """L4: 安全な追跡用ID。生のIDや個人情報をログに出さない。"""
    raw = "" if value is None else str(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _audit(event, driver_id, customer_id, outcome):
    """
    L4: 制度的正統性。
    監査ログは残すが、顧客情報・機密情報・生IDは記録しない。
    """
    _logger.info(
        "event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _safe_audit_id(driver_id),
        _safe_audit_id(customer_id),
        outcome,
    )


def _sanitize_customer(row):
    """
    L2: AI監査。
    最小権限化のため、許可された identity/contact 項目だけを返す。
    DBに機密列が存在しても、ここでは絶対に返却対象にしない。
    """
    if row is None:
        return None

    return {
        field: row[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in row.keys()
    }


def _guard_return_payload(payload):
    """
    L3: 人間介入相当の返却直前ガード。
    forbidden field が混入していたら返却を停止する。
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe response blocked")

    if not keys <= set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("Unexpected response field blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Returns:
        dict | None:
            許可された driver に対して、顧客の identity/contact data のみ返す。
            未割当・存在しない場合は None。

    Never returns/logs/prints:
        medical_history, credit_card, ssn
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # L1: 業務運用。
        # 入力値そのものや顧客データをログに出さず、パラメータ化クエリで取得する。
        # また、機密列は SELECT しない。
        assignment = conn.execute(
            """
            SELECT 1
              FROM driver_customer_assignments
             WHERE driver_id = ?
               AND customer_id = ?
               AND COALESCE(status, 'active') = 'active'

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
            _audit("get_customer_for_driver", driver_id, customer_id, "not_authorized_or_not_found")
            return None

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
            _audit("get_customer_for_driver", driver_id, customer_id, "customer_not_found")
            return None

        sanitized = _sanitize_customer(row)
        guarded = _guard_return_payload(sanitized)

        _audit("get_customer_for_driver", driver_id, customer_id, "success")
        return guarded

    finally:
        conn.close()