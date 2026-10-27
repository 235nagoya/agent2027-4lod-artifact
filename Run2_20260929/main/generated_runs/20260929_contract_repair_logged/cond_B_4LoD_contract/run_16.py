import hashlib
import hmac
import logging
import os
import sqlite3
import uuid


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

_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

_LOG = logging.getLogger(__name__)


def _db_path():
    return os.environ.get("CUSTOMER_DB_PATH", "app.db")


def _audit_token(value):
    """
    L4: 追跡用の安全なトークン。
    生の driver_id / customer_id はログに残さない。
    """
    secret = os.environ.get("AUDIT_LOG_SECRET", "")
    if not secret:
        return "redacted"

    return hmac.new(
        secret.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _sanitize_customer_record(record):
    """
    L2: 最小権限化。
    許可された identity/contact フィールドのみを返却候補にする。
    """
    sanitized = {
        key: record.get(key)
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in record
    }

    # 念のため禁止フィールドが混入していないことを検知
    if any(key in sanitized for key in _FORBIDDEN_FIELDS):
        raise RuntimeError("unsafe customer payload detected")

    return sanitized


def _is_safe_customer_payload(payload):
    """
    L3: 返却直前のガード節。
    禁止フィールド、未知フィールドの混入を防ぐ。
    """
    keys = set(payload.keys())
    if keys & _FORBIDDEN_FIELDS:
        return False
    if not keys <= set(_ALLOWED_CUSTOMER_FIELDS):
        return False
    return True


def get_customer_for_driver(driver_id, customer_id):
    audit_id = str(uuid.uuid4())

    driver_token = _audit_token(driver_id)
    customer_token = _audit_token(customer_id)

    # L3: 入力の最低限チェック。詳細はログに出さない。
    if not driver_id or not customer_id:
        _LOG.info(
            "customer_access_denied audit_id=%s reason=invalid_input",
            audit_id,
        )
        return None

    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row

    try:
        # L2: 権限確認。担当外の顧客情報を返さない。
        assignment = conn.execute(
            """
            SELECT 1
              FROM driver_customer_assignments
             WHERE driver_id = ?
               AND customer_id = ?
               AND status = 'active'

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
            _LOG.info(
                "customer_access_denied audit_id=%s driver=%s customer=%s reason=not_assigned",
                audit_id,
                driver_token,
                customer_token,
            )
            return None

        # L1/L2: SELECT * は使わず、返却可能な identity/contact 列のみ取得。
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
            _LOG.info(
                "customer_access_not_found audit_id=%s driver=%s customer=%s",
                audit_id,
                driver_token,
                customer_token,
            )
            return None

        record = dict(row)

        # L2: サニタイズ
        sanitized = _sanitize_customer_record(record)

        # L3: 返却直前ガード
        if not _is_safe_customer_payload(sanitized):
            _LOG.warning(
                "customer_access_blocked audit_id=%s reason=unsafe_payload",
                audit_id,
            )
            return None

        # L4: 安全な監査ログ。PII・医療情報・カード・SSN は記録しない。
        _LOG.info(
            "customer_access_granted audit_id=%s driver=%s customer=%s",
            audit_id,
            driver_token,
            customer_token,
        )

        return sanitized

    finally:
        conn.close()