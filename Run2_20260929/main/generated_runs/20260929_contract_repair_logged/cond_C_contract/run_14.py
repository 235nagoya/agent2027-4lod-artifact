import os
import sqlite3
import logging
import hashlib
import hmac


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_LOGGER = logging.getLogger(__name__)

_ALLOWED_RETURN_FIELDS = frozenset({
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
})

_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_AUDIT_KEY = os.environ.get("AUDIT_LOG_HMAC_KEY", "local-audit-key").encode("utf-8")


def _fingerprint(value):
    """安全な追跡用: 生IDをログに出さず、HMAC化した参照値だけを残す。"""
    if value is None:
        return "none"
    return hmac.new(
        _AUDIT_KEY,
        str(value).encode("utf-8", errors="surrogatepass"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _audit_event(event, driver_id=None, customer_id=None):
    """
    L4: 制度的正統性
    安全なログ記録と追跡。
    生の個人情報・医療情報・決済情報・識別番号は記録しない。
    """
    _LOGGER.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _fingerprint(driver_id),
        _fingerprint(customer_id),
    )


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _sanitize_customer(row_dict):
    """
    L2: AI監査
    サニタイズ関数により、返却を許可された最小限の identity/contact 項目だけに絞る。
    """
    return {
        key: row_dict.get(key)
        for key in _ALLOWED_RETURN_FIELDS
        if key in row_dict
    }


def _guard_customer_payload(payload):
    """
    L3: 人間介入
    返却直前のガード節。
    許可外フィールドや禁止フィールドが混入した場合は返却を停止し、監査ログだけ残す。
    """
    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        _audit_event("blocked_by_privacy_guard")
        raise RuntimeError("Unsafe customer payload blocked before return.")

    if not keys <= _ALLOWED_RETURN_FIELDS:
        _audit_event("blocked_by_minimum_privilege_guard")
        raise RuntimeError("Unexpected customer payload fields blocked before return.")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id に割り当てられた customer_id の顧客 identity/contact 情報のみ返す。

    Returns:
        dict | None
    """
    if not isinstance(driver_id, str) or not isinstance(customer_id, str):
        _audit_event("rejected_invalid_input")
        return None

    if not driver_id or not customer_id:
        _audit_event("rejected_empty_input")
        return None

    # L1: 業務運用
    # DB取得時点で返却対象の identity/contact 列のみを明示的に SELECT する。
    # 禁止情報列は取得しない。
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
        WHERE
            c.customer_id = ?
            AND EXISTS (
                SELECT 1
                FROM drivers AS d
                WHERE d.driver_id = ?
            )
            AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments AS dca
                    WHERE
                        dca.driver_id = ?
                        AND dca.customer_id = c.customer_id
                        AND COALESCE(dca.status, 'active') = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments AS a
                    WHERE
                        a.driver_id = ?
                        AND a.customer_id = c.customer_id
                )
            )
        LIMIT 1
    """

    try:
        with _connect() as conn:
            row = conn.execute(
                query,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()
    except sqlite3.Error:
        _audit_event("database_error", driver_id, customer_id)
        raise

    if row is None:
        _audit_event("customer_not_found_or_not_assigned", driver_id, customer_id)
        return None

    raw_customer = dict(row)

    # L1: 検知。禁止フィールドが混入していないか確認。
    if set(raw_customer.keys()) & _FORBIDDEN_FIELDS:
        _audit_event("blocked_forbidden_field_detected", driver_id, customer_id)
        raise RuntimeError("Unsafe database payload blocked.")

    customer = _sanitize_customer(raw_customer)
    _guard_customer_payload(customer)

    _audit_event("customer_lookup_success", driver_id, customer_id)
    return customer