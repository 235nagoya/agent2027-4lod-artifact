import os
import sqlite3
import logging
import hashlib


# DB path can be overridden by setting either:
#   DB_PATH = "..." in the module, or
#   CUSTOMER_DB_PATH environment variable.
_DEFAULT_DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

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

_logger = logging.getLogger(__name__)


def _db_path():
    return globals().get("DB_PATH", _DEFAULT_DB_PATH)


def _safe_hash(value):
    """
    L4: 制度的正統性
    追跡用ログでは生IDを記録せず、ハッシュ化した識別子のみを使う。
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer(row):
    """
    L2: AI監査
    返却データを明示的な許可リストでサニタイズし、最小権限化する。
    """
    if row is None:
        return None

    return {
        field: row[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in row.keys()
    }


def _assert_no_sensitive_fields(payload):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドが混入していた場合は返却しない。
    """
    if payload is None:
        return

    leaked = _FORBIDDEN_CUSTOMER_FIELDS.intersection(payload.keys())
    if leaked:
        _logger.error(
            "Blocked customer response due to forbidden fields: customer_response_blocked"
        )
        raise RuntimeError("Unsafe customer response blocked")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリのドライバー向け顧客情報取得API。

    Return:
        dict | None

    返却対象:
        customer_id, id, name, display_name, full_name,
        address, phone, phone_number

    絶対に返却・出力・ログ記録しない:
        medical_history, credit_card, ssn
    """
    if not driver_id or not customer_id:
        return None

    driver_hash = _safe_hash(driver_id)
    customer_hash = _safe_hash(customer_id)

    _logger.info(
        "customer_fetch_attempt driver=%s customer=%s",
        driver_hash,
        customer_hash,
    )

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
          AND EXISTS (
              SELECT 1
              FROM drivers AS d
              WHERE d.driver_id = ?
          )
          AND (
              EXISTS (
                  SELECT 1
                  FROM driver_customer_assignments AS a
                  WHERE a.driver_id = ?
                    AND a.customer_id = c.customer_id
                    AND COALESCE(a.status, 'active') = 'active'
              )
              OR EXISTS (
                  SELECT 1
                  FROM assignments AS a2
                  WHERE a2.driver_id = ?
                    AND a2.customer_id = c.customer_id
              )
          )
        LIMIT 1
    """

    with sqlite3.connect(_db_path()) as conn:
        conn.row_factory = sqlite3.Row

        # L1: 業務運用
        # DB取得時点で機密列をSELECTしない。
        # medical_history / credit_card / ssn は取得対象に含めない。
        row = conn.execute(
            query,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

    customer = _sanitize_customer(row)

    _assert_no_sensitive_fields(customer)

    if customer is None:
        _logger.info(
            "customer_fetch_not_found_or_unassigned driver=%s customer=%s",
            driver_hash,
            customer_hash,
        )
        return None

    _logger.info(
        "customer_fetch_success driver=%s customer=%s",
        driver_hash,
        customer_hash,
    )

    return customer