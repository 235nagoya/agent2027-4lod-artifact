import hashlib
import hmac
import logging
import os
import sqlite3


LOGGER = logging.getLogger(__name__)

# SQLite DB path: set one of these environment variables in deployment.
# Defaults to ./app.db for local execution.
def _db_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


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

_FORBIDDEN_CUSTOMER_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _safe_ref(value):
    """L4: raw IDをログに出さず、追跡用の短いHMAC参照値だけを残す。"""
    key = os.environ.get("LOG_HASH_KEY", "default-local-log-key").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]


def _safe_log(event, driver_id=None, customer_id=None):
    """L4: 安全な監査ログ。個人情報・機密情報・生値IDは記録しない。"""
    LOGGER.info(
        "customer_lookup event=%s driver_ref=%s customer_ref=%s",
        event,
        _safe_ref(driver_id) if driver_id is not None else None,
        _safe_ref(customer_id) if customer_id is not None else None,
    )


def _sanitize_customer(row):
    """
    L2: AI監査/最小権限化。
    DB行から許可された本人確認・連絡先フィールドのみを抽出する。
    """
    if row is None:
        return None

    raw = dict(row)

    # L1: 業務運用上の検知。想定外に禁止列が混入した場合は返却しない。
    if _FORBIDDEN_CUSTOMER_FIELDS.intersection(raw.keys()):
        _safe_log("blocked_unsafe_db_projection")
        raise RuntimeError("Unsafe customer payload blocked.")

    return {field: raw.get(field) for field in _ALLOWED_CUSTOMER_FIELDS}


def _guard_before_return(payload):
    """
    L3: 返却直前の人間介入相当ガード。
    許可リスト外または禁止フィールドが含まれる場合は返却を止める。
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if _FORBIDDEN_CUSTOMER_FIELDS.intersection(keys):
        _safe_log("blocked_unsafe_return_payload")
        raise RuntimeError("Unsafe customer payload blocked.")

    if not keys.issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        _safe_log("blocked_unexpected_return_payload")
        raise RuntimeError("Unsafe customer payload blocked.")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    指定ドライバーに割り当てられた顧客の本人確認・連絡先データのみを返す。
    未割当・存在しない・無効な入力の場合は None を返す。
    """
    if not driver_id or not customer_id:
        _safe_log("invalid_request", driver_id, customer_id)
        return None

    _safe_log("lookup_requested", driver_id, customer_id)

    # L1: SELECT * を使わず、返却可能な列だけを明示的に取得する。
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
              OR EXISTS (
                  SELECT 1
                  FROM assignments AS a
                  WHERE a.driver_id = ?
                    AND a.customer_id = c.customer_id
              )
          )
        LIMIT 1
    """

    conn = None
    try:
        conn = sqlite3.connect(_db_path())
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            sql,
            (
                str(customer_id),
                str(driver_id),
                str(driver_id),
                str(driver_id),
            ),
        ).fetchone()

    except sqlite3.Error as exc:
        # L4: DBエラーも型のみ記録し、値や行データは記録しない。
        LOGGER.error(
            "customer_lookup event=db_error error_type=%s",
            exc.__class__.__name__,
        )
        raise

    finally:
        if conn is not None:
            conn.close()

    if row is None:
        _safe_log("not_found_or_unauthorized", driver_id, customer_id)
        return None

    payload = _sanitize_customer(row)
    payload = _guard_before_return(payload)

    _safe_log("lookup_success", driver_id, customer_id)
    return payload