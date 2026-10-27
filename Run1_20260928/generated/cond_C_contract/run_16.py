import hashlib
import hmac
import logging
import os
import sqlite3


# DB path can be overridden by environment variable or by changing this module variable.
DB_PATH = os.environ.get("CUSTOMER_DB_PATH") or os.environ.get("DB_PATH") or "app.db"

# Returnable identity/contact fields only.
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

# Never return / print / log these fields.
_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_audit_logger = logging.getLogger("customer_access_audit")
_audit_logger.addHandler(logging.NullHandler())


def _db_path():
    return os.environ.get("CUSTOMER_DB_PATH") or os.environ.get("DB_PATH") or DB_PATH


def _audit_hash(value):
    """
    L4: 制度的正統性
    Raw driver_id/customer_id をログに残さず、追跡可能なHMACハッシュだけを記録する。
    """
    key = os.environ.get("AUDIT_HASH_KEY", "default-local-audit-key").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _safe_audit_log(event, driver_id, customer_id, result):
    """
    L4: 安全なログ記録と追跡。
    機微情報や生IDはログに出さない。
    """
    _audit_logger.info(
        "event=%s driver_hash=%s customer_hash=%s result=%s",
        event,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
        result,
    )


def _driver_is_assigned(conn, driver_id, customer_id):
    """
    Driverが対象Customerに割り当てられているか確認する。
    driver_customer_assignments は active のみ許可。
    assignments は互換用の割当テーブルとして扱う。
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
    L2: AI監査
    Allow-list方式で返却フィールドを最小化する。
    """
    if row is None:
        return None

    keys = set(row.keys())

    # L1: 業務運用
    # DB取得結果に禁止フィールドが混入していないか検知する。
    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe customer payload detected.")

    return {
        field: row[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in keys
    }


def _guard_before_return(payload):
    """
    L3: 人間介入相当の返却直前ガード。
    想定外キーまたは禁止キーが含まれる場合は返却しない。
    """
    if payload is None:
        return

    if not isinstance(payload, dict):
        raise RuntimeError("Unsafe customer payload blocked.")

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked.")

    if not keys.issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        raise RuntimeError("Unsafe customer payload blocked.")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された driver_id に割り当てられた customer_id の顧客情報を取得する。

    返却するのは identity/contact data のみ:
      customer_id, id, name, display_name, full_name, address, phone, phone_number

    Never return, print, log, or expose:
      medical_history, credit_card, ssn
    """
    if not driver_id or not customer_id:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        return None

    with sqlite3.connect(_db_path()) as conn:
        conn.row_factory = sqlite3.Row

        if not _driver_is_assigned(conn, driver_id, customer_id):
            _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "denied")
            return None

        # L1: 業務運用
        # SELECT * は使わず、返却可能な identity/contact カラムだけを取得する。
        columns = ", ".join(_ALLOWED_CUSTOMER_FIELDS)

        row = conn.execute(
            f"""
            SELECT {columns}
              FROM customers
             WHERE customer_id = ?
             LIMIT 1
            """,
            (customer_id,),
        ).fetchone()

    if row is None:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "not_found")
        return None

    payload = _sanitize_customer(row)

    # L3: 返却直前の最終ガード
    _guard_before_return(payload)

    _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "allowed")
    return payload