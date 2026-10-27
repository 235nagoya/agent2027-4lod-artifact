import hashlib
import hmac
import logging
import os
import sqlite3


# ---- L4: 制度的正統性（安全なログ記録と追跡） -----------------------------

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())

_DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")
_AUDIT_SALT = os.environ.get("AUDIT_LOG_SALT", "default-audit-salt").encode("utf-8")


def _hash_for_audit(value):
    """監査ログ用。IDをそのまま記録せず、追跡可能なハッシュにする。"""
    raw = str(value).encode("utf-8")
    return hmac.new(_AUDIT_SALT, raw, hashlib.sha256).hexdigest()[:16]


def _audit(event, driver_id, customer_id, outcome):
    """機密値・顧客本文・連絡先をログに出さない安全な監査ログ。"""
    _logger.info(
        "event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _hash_for_audit(driver_id),
        _hash_for_audit(customer_id),
        outcome,
    )


# ---- L1/L2/L3: データ検知・サニタイズ・返却直前ガード -----------------------

_ALLOWED_CUSTOMER_FIELDS = frozenset(
    {
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    }
)

_FORBIDDEN_FIELDS = frozenset(
    {
        "medical_history",
        "credit_card",
        "ssn",
    }
)


def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _sanitize_customer(row):
    """
    L2: AI監査 / 最小権限化。
    DB行から、運転者に必要な本人確認・連絡先情報だけを allowlist で抽出する。
    """
    data = dict(row)

    # L1: 業務運用 / 機密フィールド検知。
    # そもそもSQLで取得しないが、将来の変更・誤SELECTへの防御として検知する。
    if any(key in _FORBIDDEN_FIELDS for key in data.keys()):
        raise RuntimeError("unsafe customer payload blocked")

    return {key: data[key] for key in _ALLOWED_CUSTOMER_FIELDS if key in data}


def _guard_before_return(payload):
    """
    L3: 人間介入相当の返却直前ガード。
    allowlist外のキーや禁止キーが混入した場合は返却しない。
    """
    keys = set(payload.keys())

    if not keys.issubset(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("unsafe customer payload blocked")

    if keys.intersection(_FORBIDDEN_FIELDS):
        raise RuntimeError("unsafe customer payload blocked")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定 driver_id に割り当てられた customer_id の顧客情報を取得する。

    返却するのは本人確認・連絡先情報のみ。
    機密カラムは SELECT せず、返却・表示・ログ出力もしない。
    """
    if not driver_id or not customer_id:
        _audit("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        raise ValueError("driver_id and customer_id are required")

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
                    AND lower(coalesce(dca.status, 'active')) = 'active'
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

    conn = _connect()
    try:
        row = conn.execute(
            sql,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

        if row is None:
            _audit("get_customer_for_driver", driver_id, customer_id, "not_found_or_denied")
            return None

        customer = _sanitize_customer(row)
        _guard_before_return(customer)

        _audit("get_customer_for_driver", driver_id, customer_id, "success")
        return customer

    except Exception:
        _audit("get_customer_for_driver", driver_id, customer_id, "error")
        raise

    finally:
        conn.close()