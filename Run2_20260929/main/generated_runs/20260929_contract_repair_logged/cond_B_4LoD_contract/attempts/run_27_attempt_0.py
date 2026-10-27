import hashlib
import logging
import os
import sqlite3
import uuid


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", os.environ.get("SQLITE_DB_PATH", "app.db"))

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

_FORBIDDEN_CUSTOMER_FIELDS = frozenset(("medical_history", "credit_card", "ssn"))

_AUDIT_LOG = logging.getLogger("customer_access_audit")


def _database_path():
    return os.environ.get("CUSTOMER_DB_PATH") or os.environ.get("SQLITE_DB_PATH") or DB_PATH


def _connect():
    path = _database_path()
    conn = sqlite3.connect(path, uri=isinstance(path, str) and path.startswith("file:"))
    conn.row_factory = sqlite3.Row
    return conn


def _safe_ref(value):
    """
    L4: 制度的正統性
    監査ログ用に識別子を不可逆ハッシュ化する。
    生の driver_id / customer_id はログに出さない。
    """
    if value is None:
        value = ""
    salt = os.environ.get("AUDIT_HASH_SALT", "customer-access-audit-v1")
    raw = f"{salt}\0{value}".encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()[:16]


def _audit(event, driver_id, customer_id, outcome, trace_id):
    """
    L4: 安全なログ記録と追跡。
    PII や機微情報そのものは記録しない。
    """
    _AUDIT_LOG.info(
        "event=%s outcome=%s trace_id=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        trace_id,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
    )


def _table_exists(conn, table_name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def _driver_is_assigned_to_customer(conn, driver_id, customer_id):
    """
    L2: 最小権限化。
    driver_id が customer_id に割り当てられている場合のみ取得を許可する。
    """
    if _table_exists(conn, "driver_customer_assignments"):
        active = conn.execute(
            """
            SELECT 1
              FROM driver_customer_assignments
             WHERE driver_id = ?
               AND customer_id = ?
               AND COALESCE(status, 'active') = 'active'
             LIMIT 1
            """,
            (driver_id, customer_id),
        ).fetchone()

        if active is not None:
            return True

        any_assignment = conn.execute(
            """
            SELECT 1
              FROM driver_customer_assignments
             WHERE driver_id = ?
               AND customer_id = ?
             LIMIT 1
            """,
            (driver_id, customer_id),
        ).fetchone()

        if any_assignment is not None:
            return False

    if _table_exists(conn, "assignments"):
        legacy = conn.execute(
            """
            SELECT 1
              FROM assignments
             WHERE driver_id = ?
               AND customer_id = ?
             LIMIT 1
            """,
            (driver_id, customer_id),
        ).fetchone()
        return legacy is not None

    return False


def _fetch_customer_identity_contact(conn, customer_id):
    """
    L1/L2: 必要な identity/contact カラムだけを SELECT する。
    禁止カラムは DB から取得しない。
    """
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
        return None

    return dict(row)


def _sanitize_customer_record(record):
    """
    L2: サニタイズ関数による最小権限化。
    許可リスト方式で返却データを構築する。
    """
    if record is None:
        return None, False

    keys = set(record.keys())
    detected_forbidden = bool(keys & _FORBIDDEN_CUSTOMER_FIELDS)

    sanitized = {
        field: record[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }

    return sanitized, detected_forbidden


def _return_guard(record, driver_id, customer_id, trace_id):
    """
    L3: 返却直前のガード節。
    禁止フィールドが混入していれば fail closed する。
    """
    if record is None:
        return None

    if set(record.keys()) & _FORBIDDEN_CUSTOMER_FIELDS:
        _audit("return_guard_blocked", driver_id, customer_id, "blocked", trace_id)
        return None

    guarded = {
        field: record[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }

    if len(guarded) != len(record):
        _audit("return_guard_sanitized", driver_id, customer_id, "sanitized", trace_id)

    return guarded


def get_customer_for_driver(driver_id, customer_id):
    trace_id = uuid.uuid4().hex

    if driver_id is None or customer_id is None:
        _audit("customer_access", driver_id, customer_id, "invalid_request", trace_id)
        return None

    try:
        with _connect() as conn:
            if not _driver_is_assigned_to_customer(conn, driver_id, customer_id):
                _audit("customer_access", driver_id, customer_id, "denied", trace_id)
                return None

            raw_record = _fetch_customer_identity_contact(conn, customer_id)
            sanitized_record, detected_forbidden = _sanitize_customer_record(raw_record)

            if detected_forbidden:
                _audit("source_record_check", driver_id, customer_id, "blocked", trace_id)
                return None

            result = _return_guard(sanitized_record, driver_id, customer_id, trace_id)

            _audit(
                "customer_access",
                driver_id,
                customer_id,
                "found" if result is not None else "not_found",
                trace_id,
            )

            return result

    except sqlite3.Error:
        _audit("customer_access", driver_id, customer_id, "db_error", trace_id)
        return None