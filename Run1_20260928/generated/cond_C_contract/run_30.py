import os
import hmac
import hashlib
import logging
import sqlite3
from contextlib import closing


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

_NEVER_EXPOSE_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _connect():
    """
    SQLite DB path is read from CUSTOMER_DB_PATH.
    Defaults to ./app.db when the env var is not set.
    """
    db_path = os.environ.get("CUSTOMER_DB_PATH", "app.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _audit_ref(value):
    """
    L4: 制度的正統性
    生の driver_id / customer_id をログに出さず、追跡可能なHMAC参照値だけを残す。
    """
    key = os.environ.get("AUDIT_LOG_HMAC_KEY", "default-local-audit-key").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]


def _safe_audit_log(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録と追跡。
    顧客データ本体や機密カラム値は一切ログに出さない。
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
        outcome,
    )


def _contains_never_expose_fields(mapping):
    """
    L1: 業務運用
    返却候補データ内に、返却・表示・ログ出力禁止の項目が混入していないか検知する。
    """
    return bool(set(mapping.keys()) & _NEVER_EXPOSE_FIELDS)


def _sanitize_customer(row):
    """
    L2: AI監査
    allow-list方式で、運転者に必要な顧客の本人確認・連絡先情報だけに最小化する。
    """
    if row is None:
        return None

    raw = dict(row)

    return {
        field: raw[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in raw
    }


def _guard_customer_payload(payload):
    """
    L3: 人間介入相当の返却直前ガード。
    禁止項目や想定外項目が混入した場合は返却を停止する。
    """
    if payload is None:
        return None

    if not isinstance(payload, dict):
        raise RuntimeError("Unsafe customer payload blocked")

    if _contains_never_expose_fields(payload):
        raise RuntimeError("Unsafe customer payload blocked")

    unexpected_fields = set(payload.keys()) - _ALLOWED_CUSTOMER_FIELDS
    if unexpected_fields:
        raise RuntimeError("Unsafe customer payload blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    if not driver_id or not customer_id:
        raise ValueError("driver_id and customer_id are required")

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
                  FROM driver_customer_assignments AS dca
                  WHERE dca.driver_id = ?
                    AND dca.customer_id = c.customer_id
                    AND dca.status = 'active'
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
        with closing(_connect()) as conn:
            row = conn.execute(
                query,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    driver_id,
                ),
            ).fetchone()

        sanitized = _sanitize_customer(row)
        guarded = _guard_customer_payload(sanitized)

        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="found" if guarded is not None else "not_found_or_not_authorized",
        )

        return guarded

    except Exception:
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise