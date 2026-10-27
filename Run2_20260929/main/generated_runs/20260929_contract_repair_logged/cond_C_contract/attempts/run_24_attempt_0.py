import hashlib
import logging
import os
import sqlite3

logger = logging.getLogger(__name__)

_SAFE_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_SENSITIVE_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _db_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def _audit_ref(value):
    if value is None:
        return "-"
    salt = os.environ.get("AUDIT_HASH_SALT", "default-audit-salt")
    raw = f"{salt}:{value}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _safe_audit_log(event, driver_id, customer_id):
    # L4: 制度的正統性 - 値そのものや顧客データはログに出さず、追跡用のハッシュのみ記録する。
    logger.info(
        "get_customer_for_driver event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


def _sanitize_customer(row):
    # L2: AI監査 - whitelist方式で最小権限化し、許可された identity/contact 項目だけを返す。
    if row is None:
        return None

    raw = dict(row)
    sanitized = {
        key: raw.get(key)
        for key in _SAFE_CUSTOMER_COLUMNS
        if key in raw
    }
    return sanitized


def _guard_response(payload):
    # L3: 人間介入 - 返却直前のガード節。機密キーや想定外キーが混入したら返却しない。
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys & _SENSITIVE_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked")

    if not keys <= set(_SAFE_CUSTOMER_COLUMNS):
        raise RuntimeError("Unexpected customer payload blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    # L1: 業務運用 - 入力を検査し、取得列を限定する。機密列は SELECT しない。
    if not driver_id or not customer_id:
        _safe_audit_log("rejected_invalid_input", driver_id, customer_id)
        return None

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

    with sqlite3.connect(_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

    if row is None:
        _safe_audit_log("not_found_or_not_authorized", driver_id, customer_id)
        return None

    customer = _sanitize_customer(row)
    customer = _guard_response(customer)

    _safe_audit_log("success", driver_id, customer_id)
    return customer