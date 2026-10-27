import hashlib
import hmac
import logging
import os
import sqlite3
import uuid


# Set this in the runtime environment as needed.
# Example: export CUSTOMER_DB_PATH=/path/to/app.sqlite3
DATABASE_PATH = os.environ.get("CUSTOMER_DB_PATH", "customers.sqlite3")

_LOGGER = logging.getLogger(__name__ + ".customer_access")
_LOGGER.addHandler(logging.NullHandler())

_AUDIT_KEY = os.environ.get("CUSTOMER_AUDIT_SALT", "customer-audit-salt").encode("utf-8")

_SAFE_CUSTOMER_FIELDS = (
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


def _hash_for_audit(value):
    """安全な追跡用: driver_id/customer_id をログへ直接出さず、HMAC化する。"""
    if value is None:
        value = ""
    digest = hmac.new(
        _AUDIT_KEY,
        str(value).encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:16]


def _audit(event, trace_id, driver_id, customer_id):
    """
    L4: 制度的正統性
    個人情報や機微情報をログに出さず、追跡可能な監査ログのみ残す。
    """
    _LOGGER.info(
        "customer_access_audit event=%s trace_id=%s driver_ref=%s customer_ref=%s",
        event,
        trace_id,
        _hash_for_audit(driver_id),
        _hash_for_audit(customer_id),
    )


def _open_connection():
    """
    テストやアプリ側で DB_CONNECTION を注入している場合はそれを使う。
    なければ DATABASE_PATH へ接続する。
    """
    injected = globals().get("DB_CONNECTION")
    if isinstance(injected, sqlite3.Connection):
        return injected, False

    connection_factory = globals().get("get_db_connection")
    if callable(connection_factory):
        return connection_factory(), False

    return sqlite3.connect(DATABASE_PATH), True


def _contains_forbidden_fields(record):
    """
    L1: 業務運用
    返却候補内に禁止フィールドが混入していないか検知する。
    """
    return any(str(key).lower() in _FORBIDDEN_FIELDS for key in record.keys())


def _sanitize_customer(record):
    """
    L2: AI監査
    サニタイズ関数で最小権限化し、本人確認・連絡先に必要な列だけ残す。
    """
    return {
        field: record[field]
        for field in _SAFE_CUSTOMER_FIELDS
        if field in record
    }


def _guard_return(record, requested_customer_id):
    """
    L3: 人間介入相当
    返却直前のガード節。許可列以外や禁止列が混入していれば返さない。
    """
    if not isinstance(record, dict):
        return False

    keys = set(record.keys())

    if not keys.issubset(set(_SAFE_CUSTOMER_FIELDS)):
        return False

    if keys.intersection(_FORBIDDEN_FIELDS):
        return False

    if record.get("customer_id") != requested_customer_id:
        return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    """
    指定 driver_id に割り当てられている customer_id の顧客情報を取得する。

    返却するのは identity/contact data のみ:
      customer_id, id, name, display_name, full_name,
      address, phone, phone_number

    medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """
    trace_id = str(uuid.uuid4())

    if not isinstance(driver_id, str) or not driver_id.strip():
        _audit("invalid_driver_id", trace_id, driver_id, customer_id)
        return None

    if not isinstance(customer_id, str) or not customer_id.strip():
        _audit("invalid_customer_id", trace_id, driver_id, customer_id)
        return None

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
                      FROM driver_customer_assignments AS dca_any
                      WHERE dca_any.driver_id = ?
                        AND dca_any.customer_id = c.customer_id
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

    conn = None
    should_close = False

    try:
        conn, should_close = _open_connection()
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(
            sql,
            (
                customer_id,
                driver_id,
                driver_id,
                driver_id,
                driver_id,
            ),
        )
        row = cursor.fetchone()
        cursor.close()

        if row is None:
            _audit("not_found_or_unauthorized", trace_id, driver_id, customer_id)
            return None

        raw_record = dict(row)

        if _contains_forbidden_fields(raw_record):
            _audit("forbidden_field_detected_before_sanitize", trace_id, driver_id, customer_id)
            return None

        sanitized = _sanitize_customer(raw_record)

        if not _guard_return(sanitized, customer_id):
            _audit("return_guard_blocked", trace_id, driver_id, customer_id)
            return None

        _audit("success", trace_id, driver_id, customer_id)
        return sanitized

    except sqlite3.Error as exc:
        _LOGGER.warning(
            "customer_access_db_error trace_id=%s error_type=%s",
            trace_id,
            type(exc).__name__,
        )
        _audit("db_error", trace_id, driver_id, customer_id)
        return None

    finally:
        if should_close and conn is not None:
            conn.close()