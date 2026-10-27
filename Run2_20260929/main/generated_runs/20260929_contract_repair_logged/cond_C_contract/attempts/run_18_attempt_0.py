import hashlib
import hmac
import logging
import os
import sqlite3


_ALLOWED_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_FIELDS = frozenset({"medical_history", "credit_card", "ssn"})

_LOGGER = logging.getLogger(__name__)


def _database_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )


def _audit_ref(value):
    """
    L4: 制度的正統性
    ログには生のIDを出さず、追跡可能なハッシュ参照のみを残す。
    """
    key = os.environ.get("AUDIT_LOG_SECRET", "local-audit-log-secret").encode("utf-8")
    raw = str(value).encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()[:16]


def _contains_forbidden_fields(data):
    """
    L1: 業務運用
    返却候補データ内に禁止フィールドが混入していないか検知する。
    """
    return bool(set(data.keys()) & _FORBIDDEN_FIELDS)


def _sanitize_customer(row):
    """
    L2: AI監査
    allowlist方式で、運転者に必要な顧客の本人確認・連絡先情報だけに最小化する。
    """
    if row is None:
        return None

    return {
        column: row[column]
        for column in _ALLOWED_CUSTOMER_COLUMNS
        if column in row.keys()
    }


def _guard_before_return(data):
    """
    L3: 人間介入
    返却直前のガード節。禁止フィールドや想定外フィールドがあれば返却しない。
    """
    if data is None:
        return None

    if _contains_forbidden_fields(data):
        _LOGGER.error("blocked_customer_response forbidden_fields_detected")
        raise RuntimeError("Unsafe customer response blocked")

    unexpected = set(data.keys()) - set(_ALLOWED_CUSTOMER_COLUMNS)
    if unexpected:
        _LOGGER.error("blocked_customer_response unexpected_fields_detected")
        raise RuntimeError("Unexpected customer response fields blocked")

    return data


def get_customer_for_driver(driver_id, customer_id):
    if not driver_id or not customer_id:
        return None

    conn = sqlite3.connect(_database_path())
    conn.row_factory = sqlite3.Row

    try:
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
                          AND LOWER(COALESCE(dca.status, 'active')) = 'active'
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

        sanitized = _sanitize_customer(row)
        result = _guard_before_return(sanitized)

        _LOGGER.info(
            "customer_lookup driver_ref=%s customer_ref=%s found=%s",
            _audit_ref(driver_id),
            _audit_ref(customer_id),
            result is not None,
        )

        return result

    finally:
        conn.close()