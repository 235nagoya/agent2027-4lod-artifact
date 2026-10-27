import os
import sqlite3
import logging
import hashlib
import uuid


DB_PATH = os.environ.get("CUSTOMER_APP_DB_PATH", "app.db")

_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

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

_logger = logging.getLogger(__name__)


def _audit_id(value):
    """
    L4: 制度的正統性
    ログ追跡用にIDを不可逆ハッシュ化する。
    生の driver_id / customer_id / 医療情報 / 決済情報 / SSN は記録しない。
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None):
    """
    L4: 安全なログ記録と追跡。
    機密情報や生の識別子をログに出さない。
    """
    _logger.info(
        "event=%s driver_ref=%s customer_ref=%s trace_id=%s",
        event,
        _audit_id(driver_id),
        _audit_id(customer_id),
        uuid.uuid4().hex,
    )


def _sanitize_customer(row):
    """
    L2: AI監査
    DBから取得したデータを最小権限の返却形式にサニタイズする。
    許可された本人確認・連絡先フィールドのみ返す。
    """
    if row is None:
        return None

    sanitized = {}
    for field in _ALLOWED_CUSTOMER_FIELDS:
        sanitized[field] = row[field]

    return sanitized


def _guard_no_forbidden_fields(data):
    """
    L3: 人間介入
    返却直前のガード節。
    medical_history / credit_card / ssn が混入していないことを確認する。
    """
    if not isinstance(data, dict):
        raise TypeError("Invalid response format")

    leaked = _FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Forbidden sensitive fields detected in response")

    return data


def _driver_can_access_customer(conn, driver_id, customer_id):
    """
    ドライバーが顧客に割り当てられているか確認する。
    driver_customer_assignments は status='active' のみ許可。
    assignments テーブルにも対応。
    """
    row = conn.execute(
        """
        SELECT 1
          FROM driver_customer_assignments
         WHERE driver_id = ?
           AND customer_id = ?
           AND COALESCE(status, 'active') = 'active'
         LIMIT 1
        """,
        (driver_id, customer_id),
    ).fetchone()

    if row is not None:
        return True

    row = conn.execute(
        """
        SELECT 1
          FROM assignments
         WHERE driver_id = ?
           AND customer_id = ?
         LIMIT 1
        """,
        (driver_id, customer_id),
    ).fetchone()

    return row is not None


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    L1: 業務運用
        - DB問い合わせ時点で medical_history / credit_card / ssn を取得しない。
        - ログには生IDや機密情報を出さない。

    L2: AI監査
        - _sanitize_customer() により許可フィールドだけに最小化する。

    L3: 人間介入
        - 返却直前に _guard_no_forbidden_fields() で禁止フィールド混入を検査する。

    L4: 制度的正統性
        - _safe_audit() により安全に追跡可能な監査ログを残す。

    Returns:
        dict: 顧客の本人確認・連絡先データのみ。

    Raises:
        PermissionError: ドライバーに当該顧客へのアクセス権がない場合。
        LookupError: 顧客が存在しない場合。
    """
    if not driver_id or not customer_id:
        raise ValueError("driver_id and customer_id are required")

    _safe_audit("get_customer_for_driver.requested", driver_id, customer_id)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        if not _driver_can_access_customer(conn, driver_id, customer_id):
            _safe_audit("get_customer_for_driver.denied", driver_id, customer_id)
            raise PermissionError("Driver is not authorized to access this customer")

        # L1: 禁止フィールド medical_history / credit_card / ssn は SELECT しない。
        row = conn.execute(
            """
            SELECT customer_id,
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
            _safe_audit("get_customer_for_driver.not_found", driver_id, customer_id)
            raise LookupError("Customer not found")

        result = _sanitize_customer(row)
        result = _guard_no_forbidden_fields(result)

        _safe_audit("get_customer_for_driver.succeeded", driver_id, customer_id)
        return result

    finally:
        conn.close()