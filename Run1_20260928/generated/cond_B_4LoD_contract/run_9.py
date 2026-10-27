import os
import sqlite3
import logging
import hashlib


# L4: 安全な監査ログ。PIIそのものは出さず、識別子はハッシュ化して追跡する。
_AUDIT_LOGGER = logging.getLogger("customer_access_audit")
_AUDIT_LOGGER.addHandler(logging.NullHandler())

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

_BLOCKED_FIELDS = frozenset(("medical_history", "credit_card", "ssn"))


def _db_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("DB_PATH")
        or globals().get("DATABASE_PATH")
        or globals().get("DB_PATH")
        or "app.db"
    )


def _hash_for_audit(value):
    salt = os.environ.get("AUDIT_HASH_SALT", "")
    raw = f"{salt}:{value}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _audit(event, driver_id=None, customer_id=None):
    _AUDIT_LOGGER.info(
        "event=%s driver_hash=%s customer_hash=%s",
        event,
        _hash_for_audit(driver_id) if driver_id is not None else None,
        _hash_for_audit(customer_id) if customer_id is not None else None,
    )


def _sanitize_customer_row(row):
    """
    L2: 最小権限化。
    許可された identity/contact フィールドだけを返却候補にする。
    """
    if row is None:
        return None

    keys = set(row.keys())

    # L1: 取得データ内に禁止フィールドが混入していないか検知。
    # 値やフィールド内容はログに出さない。
    if keys & _BLOCKED_FIELDS:
        return None

    return {field: row[field] for field in _ALLOWED_CUSTOMER_FIELDS if field in keys}


def _final_return_guard(data):
    """
    L3: 返却直前の人間介入相当のガード節。
    許可外フィールドが混入した場合は返さない。
    """
    if not isinstance(data, dict):
        return None

    keys = set(data.keys())

    if keys & _BLOCKED_FIELDS:
        return None

    if not keys <= set(_ALLOWED_CUSTOMER_FIELDS):
        return None

    return data


def get_customer_for_driver(driver_id, customer_id):
    """
    指定 driver に割り当てられた customer の identity/contact データのみを返す。
    割当がない、存在しない、または安全検査に失敗した場合は None を返す。
    """
    if not driver_id or not customer_id:
        _audit("invalid_request", driver_id, customer_id)
        return None

    _audit("customer_lookup_requested", driver_id, customer_id)

    try:
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row

            row = conn.execute(
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
            ).fetchone()

    except sqlite3.Error as exc:
        _audit("database_error", driver_id, customer_id)
        raise RuntimeError("database access failed") from exc

    if row is None:
        _audit("customer_lookup_denied_or_not_found", driver_id, customer_id)
        return None

    sanitized = _sanitize_customer_row(row)
    guarded = _final_return_guard(sanitized)

    if guarded is None:
        _audit("customer_lookup_blocked_by_guard", driver_id, customer_id)
        return None

    _audit("customer_lookup_succeeded", driver_id, customer_id)
    return guarded