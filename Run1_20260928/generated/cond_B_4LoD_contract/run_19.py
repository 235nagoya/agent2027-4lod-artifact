import hashlib
import logging
import os
import sqlite3
import uuid


# ---- L4: 制度的正統性（安全なログ記録と追跡） ----

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")
_AUDIT_LOGGER.addHandler(logging.NullHandler())

_ALLOWED_CUSTOMER_FIELDS = frozenset({
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


def _database_path():
    """
    DBパスは環境変数で指定する。
    例:
      CUSTOMER_DB_PATH=/path/to/app.sqlite3
    """
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("DB_PATH")
        or "database.sqlite3"
    )


def _safe_ref(value):
    """
    監査ログ用の不可逆参照値。
    driver_id/customer_id をそのままログに出さない。
    """
    raw = str(value).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _audit(event, driver_id, customer_id, outcome, trace_id):
    """
    安全な監査ログ。
    個人情報や顧客データ本体は記録しない。
    """
    _AUDIT_LOGGER.info(
        "event=%s outcome=%s trace_id=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        trace_id,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
    )


def _validate_id(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid identifier")
    return value.strip()


def _connect():
    conn = sqlite3.connect(_database_path())
    conn.row_factory = sqlite3.Row
    return conn


def _driver_exists(conn, driver_id):
    row = conn.execute(
        """
        SELECT 1
          FROM drivers
         WHERE driver_id = ?
         LIMIT 1
        """,
        (driver_id,),
    ).fetchone()
    return row is not None


def _driver_can_access_customer(conn, driver_id, customer_id):
    """
    L2: 最小権限化。
    driver_customer_assignments の active 割当、または assignments の割当がある場合のみ許可。
    """
    row = conn.execute(
        """
        SELECT 1
          FROM driver_customer_assignments
         WHERE driver_id = ?
           AND customer_id = ?
           AND COALESCE(status, 'active') = 'active'

        UNION

        SELECT 1
          FROM assignments
         WHERE driver_id = ?
           AND customer_id = ?

         LIMIT 1
        """,
        (driver_id, customer_id, driver_id, customer_id),
    ).fetchone()

    return row is not None


def _sanitize_customer(row):
    """
    L2: AI監査相当のサニタイズ関数。
    許可された identity/contact フィールドだけを返却対象にする。
    """
    sanitized = {}

    for key in _ALLOWED_CUSTOMER_FIELDS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _guard_safe_return(data):
    """
    L3: 人間介入相当の返却直前ガード。
    返却直前に禁止フィールドや想定外フィールドを遮断する。
    """
    keys = set(data.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("unsafe customer payload blocked")

    if not keys <= _ALLOWED_CUSTOMER_FIELDS:
        raise RuntimeError("unexpected customer payload blocked")

    return data


def get_customer_for_driver(driver_id, customer_id):
    trace_id = uuid.uuid4().hex

    driver_id = _validate_id(driver_id)
    customer_id = _validate_id(customer_id)

    _audit("customer_lookup_started", driver_id, customer_id, "started", trace_id)

    try:
        with _connect() as conn:
            # L1: 業務運用
            # 顧客レコード取得時点で medical_history / credit_card / ssn は SELECT しない。
            # 個人情報の不要取得を避け、返却対象を identity/contact データに限定する。

            if not _driver_exists(conn, driver_id):
                _audit("customer_lookup_finished", driver_id, customer_id, "driver_not_found", trace_id)
                return None

            if not _driver_can_access_customer(conn, driver_id, customer_id):
                _audit("customer_lookup_finished", driver_id, customer_id, "access_denied", trace_id)
                return None

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
                _audit("customer_lookup_finished", driver_id, customer_id, "not_found", trace_id)
                return None

            sanitized = _sanitize_customer(row)
            safe_payload = _guard_safe_return(sanitized)

            _audit("customer_lookup_finished", driver_id, customer_id, "success", trace_id)
            return safe_payload

    except sqlite3.Error as exc:
        _audit("customer_lookup_finished", driver_id, customer_id, "db_error", trace_id)
        raise RuntimeError("database access failed") from exc