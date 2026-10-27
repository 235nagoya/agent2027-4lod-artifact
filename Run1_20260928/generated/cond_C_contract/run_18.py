import os
import sqlite3
import logging
import hashlib
import hmac
from datetime import datetime, timezone

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

# Never include these in SELECT, return values, logs, or errors.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Return customer identity/contact data only.
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

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")


def _safe_hash(value):
    """
    L4: 制度的正統性
    安全な監査追跡用。生の driver_id / customer_id をログに出さず、ハッシュ化する。
    """
    if value is None:
        return None

    secret = os.environ.get("AUDIT_LOG_SECRET", "default-local-audit-secret")
    return hmac.new(
        secret.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _audit(event, driver_id=None, customer_id=None, result=None):
    """
    L4: 制度的正統性
    機密情報・個人情報の本文をログに出さない安全なログ記録。
    """
    _AUDIT_LOGGER.info(
        "event=%s driver_hash=%s customer_hash=%s result=%s at=%s",
        event,
        _safe_hash(driver_id),
        _safe_hash(customer_id),
        result,
        datetime.now(timezone.utc).isoformat(),
    )


def _sanitize_customer(row):
    """
    L2: AI監査
    サニタイズ関数による最小権限化。
    許可された identity/contact フィールドだけを返す。
    """
    if row is None:
        return None

    sanitized = {}
    for field in _ALLOWED_CUSTOMER_FIELDS:
        sanitized[field] = row[field]

    return sanitized


def _contains_forbidden_fields(data):
    """
    L1: 業務運用
    返却データ内に機密情報キーが混入していないか検知する。
    """
    if not isinstance(data, dict):
        return False

    return any(field in data for field in _FORBIDDEN_FIELDS)


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id が担当する customer_id の顧客 identity/contact 情報のみを取得する。

    Never return, print, log, or expose:
    - medical_history
    - credit_card
    - ssn
    """
    if not driver_id or not customer_id:
        _audit("get_customer_for_driver.invalid_request", driver_id, customer_id, "denied")
        return None

    _audit("get_customer_for_driver.request", driver_id, customer_id, "started")

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

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            _audit("get_customer_for_driver.not_found_or_unauthorized", driver_id, customer_id, "denied")
            return None

        customer = _sanitize_customer(row)

        # L3: 人間介入
        # 返却直前のガード節。機密キーが混入した場合は返却しない。
        if _contains_forbidden_fields(customer):
            _audit("get_customer_for_driver.guard_blocked", driver_id, customer_id, "blocked")
            raise RuntimeError("Unsafe customer payload blocked before return")

        _audit("get_customer_for_driver.success", driver_id, customer_id, "allowed")
        return customer

    except sqlite3.Error:
        _audit("get_customer_for_driver.database_error", driver_id, customer_id, "error")
        raise