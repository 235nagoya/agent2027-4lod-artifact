import hashlib
import hmac
import logging
import os
import sqlite3


_LOG = logging.getLogger(__name__)

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
_ALLOWED_CUSTOMER_FIELD_SET = frozenset(_ALLOWED_CUSTOMER_FIELDS)

_NEVER_EXPOSE_FIELDS = frozenset(("medical_history", "credit_card", "ssn"))

_AUDIT_HMAC_KEY = os.environ.get("CUSTOMER_AUDIT_HMAC_KEY")
if _AUDIT_HMAC_KEY is None:
    _AUDIT_HMAC_KEY_BYTES = os.urandom(32)
else:
    _AUDIT_HMAC_KEY_BYTES = _AUDIT_HMAC_KEY.encode("utf-8")


def _database_path():
    return (
        os.environ.get("CUSTOMER_APP_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )


def _audit_token(value):
    """
    L4: 制度的正統性
    監査・追跡用に、driver_id / customer_id は生値ではなくHMAC化してログへ記録する。
    """
    message = str(value).encode("utf-8")
    return hmac.new(_AUDIT_HMAC_KEY_BYTES, message, hashlib.sha256).hexdigest()[:16]


def _audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録。
    顧客レコード本体や機密列の値は一切ログ出力しない。
    """
    _LOG.info(
        "customer_access event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _audit_token(driver_id),
        _audit_token(customer_id),
        outcome,
    )


def _sanitize_customer_row(row):
    """
    L2: AI監査
    allowlist方式のサニタイズにより、運転者に必要な本人確認・連絡先情報だけに最小化する。
    """
    raw = dict(row)

    # L1: 業務運用
    # DB取得結果に禁止列が混入した場合は、返却前に検知して遮断する。
    if any(str(key).lower() in _NEVER_EXPOSE_FIELDS for key in raw.keys()):
        raise RuntimeError("Unsafe customer payload blocked")

    return {
        field: raw[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in raw
    }


def _guard_return_payload(payload):
    """
    L3: 人間介入
    返却直前のガード節。禁止列・未知列が混入した場合はフェイルクローズする。
    """
    keys = set(payload.keys())

    if keys - _ALLOWED_CUSTOMER_FIELD_SET:
        raise RuntimeError("Unsafe customer payload blocked")

    if any(str(key).lower() in _NEVER_EXPOSE_FIELDS for key in keys):
        raise RuntimeError("Unsafe customer payload blocked")


def get_customer_for_driver(driver_id, customer_id):
    if not isinstance(driver_id, str) or not driver_id.strip():
        _audit("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        return None

    if not isinstance(customer_id, str) or not customer_id.strip():
        _audit("get_customer_for_driver", driver_id, customer_id, "invalid_request")
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
        with sqlite3.connect(_database_path()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                sql,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()
    except sqlite3.Error:
        _LOG.error(
            "customer_access event=db_error driver_ref=%s customer_ref=%s outcome=error",
            _audit_token(driver_id),
            _audit_token(customer_id),
        )
        raise

    if row is None:
        _audit("get_customer_for_driver", driver_id, customer_id, "not_found_or_unauthorized")
        return None

    try:
        payload = _sanitize_customer_row(row)
        _guard_return_payload(payload)
    except RuntimeError:
        _LOG.critical(
            "customer_access event=return_guard_block driver_ref=%s customer_ref=%s outcome=blocked",
            _audit_token(driver_id),
            _audit_token(customer_id),
        )
        raise

    _audit("get_customer_for_driver", driver_id, customer_id, "returned")
    return payload