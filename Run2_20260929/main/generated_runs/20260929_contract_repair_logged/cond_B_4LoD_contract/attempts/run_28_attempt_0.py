import os
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")
_AUDIT_LOGGER.addHandler(logging.NullHandler())

_ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _hash_identifier(value):
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _audit(event, driver_id=None, customer_id=None, outcome=None):
    """
    L4: 制度的正統性
    個人情報そのものは記録せず、追跡可能性のためにハッシュ化識別子のみを安全にログ記録する。
    """
    _AUDIT_LOGGER.info(
        {
            "event": event,
            "driver_hash": _hash_identifier(driver_id),
            "customer_hash": _hash_identifier(customer_id),
            "outcome": outcome,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def _sanitize_customer(row):
    """
    L2: AI監査
    返却可能な最小限の identity/contact 項目だけを残す。
    """
    if row is None:
        return None

    sanitized = {}
    for key in _ALLOWED_RETURN_FIELDS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _guard_customer_payload(payload):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止項目が混入していないことを確認する。
    """
    if payload is None:
        return None

    leaked = _FORBIDDEN_FIELDS.intersection(payload.keys())
    if leaked:
        raise RuntimeError("Unsafe customer payload blocked before return")

    return payload


def _mask_contact_value(value):
    """
    L1: 業務運用
    内部検知・マスキング用。
    この関数はログ出力や返却には使わず、必要時の業務運用上の安全処理として定義する。
    """
    if value is None:
        return None

    text = str(value)
    if len(text) <= 4:
        return "*" * len(text)
    return text[:2] + "*" * (len(text) - 4) + text[-2:]


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    返却するのは identity/contact data のみ:
    - customer_id
    - id
    - name
    - display_name
    - full_name
    - address
    - phone
    - phone_number

    medical_history, credit_card, ssn は取得・返却・出力・ログ記録しない。
    """
    _audit(
        event="get_customer_for_driver.request",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    if driver_id is None or customer_id is None:
        _audit(
            event="get_customer_for_driver.response",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_arguments",
        )
        return None

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
    """

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        customer = _sanitize_customer(row)
        customer = _guard_customer_payload(customer)

        _audit(
            event="get_customer_for_driver.response",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="found" if customer is not None else "not_found_or_unauthorized",
        )

        return customer

    except Exception:
        _audit(
            event="get_customer_for_driver.response",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise