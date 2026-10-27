import os
import sqlite3
import logging
import hashlib
import hmac
import uuid
from contextlib import closing

# SQLite DB path. 必要に応じて環境変数で指定してください。
DB_PATH = os.environ.get("CUSTOMER_DB_PATH") or os.environ.get("DATABASE_PATH") or "app.db"

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

_FORBIDDEN_COLUMNS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def _safe_ref(value):
    """
    L4: 監査ログ用の安全な参照値。
    driver_id / customer_id をそのままログに出さず、HMAC-SHA256で追跡可能な形にする。
    """
    secret = os.environ.get("AUDIT_LOG_SECRET", "default-local-audit-secret").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def _audit(event, *, driver_id=None, customer_id=None, outcome=None, trace_id=None):
    """
    L4: 安全なログ記録と追跡。
    生の個人情報・医療情報・カード番号・SSNは絶対にログに出さない。
    """
    _logger.info(
        event,
        extra={
            "trace_id": trace_id,
            "driver_ref": _safe_ref(driver_id) if driver_id is not None else None,
            "customer_ref": _safe_ref(customer_id) if customer_id is not None else None,
            "outcome": outcome,
        },
    )


def _sanitize_identifier(value, field_name):
    """
    L2: AI監査/最小権限化のための入力サニタイズ。
    SQLはプレースホルダを使うが、異常に長い値や空値は拒否する。
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    value = value.strip()

    if not value:
        raise ValueError(f"{field_name} must not be empty")

    if len(value) > 128:
        raise ValueError(f"{field_name} is too long")

    return value


def _sanitize_customer_record(row):
    """
    L1/L2: DB行から返却可能な identity/contact データだけを抽出する。
    禁止カラムは選択しないが、念のためここでも除外する。
    """
    if row is None:
        return None

    keys = set(row.keys())

    # L1: 禁止データの検知
    if keys & _FORBIDDEN_COLUMNS:
        raise RuntimeError("forbidden customer fields detected")

    # L2: 最小権限化 - 許可済みカラムだけ返す
    return {
        column: row[column]
        for column in _ALLOWED_CUSTOMER_COLUMNS
        if column in keys
    }


def _return_guard(record):
    """
    L3: 返却直前の人間介入相当ガード節。
    返却データに禁止カラムが混入していないことを最終確認する。
    """
    if record is None:
        return None

    keys = set(record.keys())

    if keys & _FORBIDDEN_COLUMNS:
        raise RuntimeError("blocked forbidden customer fields before return")

    if not keys <= set(_ALLOWED_CUSTOMER_COLUMNS):
        raise RuntimeError("blocked unexpected customer fields before return")

    return record


def get_customer_for_driver(driver_id, customer_id):
    trace_id = uuid.uuid4().hex

    driver_id = _sanitize_identifier(driver_id, "driver_id")
    customer_id = _sanitize_identifier(customer_id, "customer_id")

    _audit(
        "customer_lookup_started",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
        trace_id=trace_id,
    )

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

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row

            row = conn.execute(
                sql,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()

    except sqlite3.Error as exc:
        _audit(
            "customer_lookup_failed",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="db_error",
            trace_id=trace_id,
        )
        raise RuntimeError("database error while retrieving customer") from exc

    record = _sanitize_customer_record(row)
    record = _return_guard(record)

    _audit(
        "customer_lookup_finished",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="found" if record is not None else "not_found_or_not_authorized",
        trace_id=trace_id,
    )

    return record