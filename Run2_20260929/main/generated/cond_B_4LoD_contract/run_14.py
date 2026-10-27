import os
import sqlite3
import logging
import hashlib
from contextlib import closing

# Safe logger: do not attach handlers that might print PII by default.
_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

# Fields allowed to leave this function.
_ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

# Fields that must never be returned, printed, logged, or exposed.
_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _audit_token(value):
    """Create a non-reversible audit token for tracking without exposing raw IDs."""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event, driver_id=None, customer_id=None, status=None):
    """
    L4:制度的正統性
    安全な監査ログ。raw ID、氏名、住所、電話番号、機微情報は記録しない。
    """
    _logger.info(
        "event=%s driver_ref=%s customer_ref=%s status=%s",
        event,
        _audit_token(driver_id),
        _audit_token(customer_id),
        status,
    )


def _sanitize_customer_row(row):
    """
    L2:AI監査
    サニタイズ関数で最小権限化する。
    DB行から許可された本人確認・連絡先フィールドだけを抽出する。
    """
    if row is None:
        return None

    sanitized = {}
    for key in _ALLOWED_RETURN_FIELDS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _contains_forbidden_fields(data):
    """
    L1:業務運用
    データ内の機微情報フィールド混入を検知する。
    """
    if not isinstance(data, dict):
        return True
    return any(field in data for field in _FORBIDDEN_FIELDS)


def _get_connection():
    """
    テストやアプリ側で既存コネクションを注入したい場合は、
    グローバル変数 DB_CONNECTION に sqlite3.Connection を設定できる。
    """
    conn = globals().get("DB_CONNECTION")
    if isinstance(conn, sqlite3.Connection):
        conn.row_factory = sqlite3.Row
        return conn, False

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn, True


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    返却する情報:
      - customer_id
      - id
      - name
      - display_name
      - full_name
      - address
      - phone
      - phone_number

    返却しない情報:
      - medical_history
      - credit_card
      - ssn
    """
    _safe_audit_log(
        "get_customer_for_driver.request",
        driver_id=driver_id,
        customer_id=customer_id,
        status="started",
    )

    if not driver_id or not customer_id:
        _safe_audit_log(
            "get_customer_for_driver.reject",
            driver_id=driver_id,
            customer_id=customer_id,
            status="invalid_input",
        )
        return None

    conn, should_close = _get_connection()

    try:
        with closing(conn.cursor()) as cur:
            # 担当ドライバーに割り当てられた顧客だけ取得する。
            # driver_customer_assignments は status='active' のみ許可。
            # assignments テーブルは互換用として存在確認に使う。
            cur.execute(
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
                """,
                (customer_id, driver_id, driver_id),
            )

            row = cur.fetchone()

        if row is None:
            _safe_audit_log(
                "get_customer_for_driver.result",
                driver_id=driver_id,
                customer_id=customer_id,
                status="not_found_or_unassigned",
            )
            return None

        # L2: サニタイズにより、許可フィールドだけに縮約。
        result = _sanitize_customer_row(row)

        # L3:人間介入
        # 返却直前のガード節。許可外キーや機微情報が混入した場合は返却しない。
        if not isinstance(result, dict):
            _safe_audit_log(
                "get_customer_for_driver.block",
                driver_id=driver_id,
                customer_id=customer_id,
                status="invalid_result_type",
            )
            return None

        if _contains_forbidden_fields(result):
            _safe_audit_log(
                "get_customer_for_driver.block",
                driver_id=driver_id,
                customer_id=customer_id,
                status="forbidden_field_detected",
            )
            return None

        if any(key not in _ALLOWED_RETURN_FIELDS for key in result):
            _safe_audit_log(
                "get_customer_for_driver.block",
                driver_id=driver_id,
                customer_id=customer_id,
                status="unexpected_field_detected",
            )
            return None

        _safe_audit_log(
            "get_customer_for_driver.result",
            driver_id=driver_id,
            customer_id=customer_id,
            status="success",
        )
        return result

    finally:
        if should_close:
            conn.close()