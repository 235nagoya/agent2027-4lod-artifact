import hashlib
import logging
import os
import sqlite3
from contextlib import closing


# DB path is intentionally not part of the API contract.
# Set CUSTOMER_DB_PATH in the execution environment.
_DEFAULT_DB_PATH = "customers.db"

_ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

# Never select / return / log these fields.
_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def _db_path():
    return os.environ.get("CUSTOMER_DB_PATH", _DEFAULT_DB_PATH)


def _audit_token(value):
    """
    L4: 制度的正統性
    Raw identifiers / PII are not logged. Hash-based token only.
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None, outcome=None):
    """
    L4: 安全なログ記録と追跡。
    Never logs names, address, phone, medical_history, credit_card, ssn,
    or raw driver_id/customer_id.
    """
    _logger.info(
        "customer_access event=%s outcome=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        _audit_token(driver_id),
        _audit_token(customer_id),
    )


def _sanitize_customer_row(row):
    """
    L2: AI監査 / サニタイズ関数による最小権限化。
    Only identity/contact fields are allowed through.
    """
    if row is None:
        return None

    row_keys = set(row.keys())

    # Detect forbidden fields if a future query is accidentally expanded.
    if row_keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked")

    return {
        key: row[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in row_keys
    }


def _guard_before_return(payload):
    """
    L3: 人間介入相当の返却直前ガード節。
    If unexpected or forbidden fields appear, block the response.
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked")

    if not keys <= _ALLOWED_CUSTOMER_FIELDS:
        raise RuntimeError("Unexpected customer fields blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver に割り当てられている customer の本人確認・連絡先情報のみ返す。

    Returns:
        dict | None

    Never returns, prints, or logs:
        medical_history, credit_card, ssn
    """
    if not driver_id or not customer_id:
        _safe_audit(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_input",
        )
        return None

    # L1/L2:
    # - Forbidden columns are not selected.
    # - Parameterized SQL prevents injection.
    # - Assignment check limits access to the driver's permitted customers.
    sql = """
        SELECT
            c.customer_id  AS customer_id,
            c.id           AS id,
            c.name         AS name,
            c.display_name AS display_name,
            c.full_name    AS full_name,
            c.address      AS address,
            c.phone        AS phone,
            c.phone_number AS phone_number
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

    try:
        with closing(sqlite3.connect(_db_path())) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                sql,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    driver_id,
                ),
            ).fetchone()

    except sqlite3.Error:
        _safe_audit(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="db_error",
        )
        raise

    if row is None:
        _safe_audit(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="not_found_or_unauthorized",
        )
        return None

    sanitized = _sanitize_customer_row(row)
    result = _guard_before_return(sanitized)

    _safe_audit(
        "get_customer_for_driver",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="success",
    )

    return result