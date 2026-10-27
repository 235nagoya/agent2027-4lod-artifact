import os
import sqlite3
import logging
import hashlib
import hmac
import uuid


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")

_ALLOWED_RETURN_FIELDS = frozenset({
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
})

_DENIED_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _audit_ref(value):
    """
    生IDをログに出さず、追跡可能な疑似IDに変換する。
    """
    key = os.environ.get("AUDIT_HASH_KEY", "local-audit-key").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:24]


def _audit_log(event, driver_id=None, customer_id=None, outcome=None):
    """
    L4: 制度的正統性
    安全な監査ログを残す。個人情報や生のIDは記録しない。
    """
    _AUDIT_LOGGER.info(
        "customer_access_event",
        extra={
            "event": event,
            "trace_id": str(uuid.uuid4()),
            "driver_ref": _audit_ref(driver_id) if driver_id is not None else None,
            "customer_ref": _audit_ref(customer_id) if customer_id is not None else None,
            "outcome": outcome,
        },
    )


def _sanitize_customer_record(record):
    """
    L2: AI監査
    allow-list方式で返却項目を最小権限化する。
    """
    if record is None:
        return None

    keys = set(record.keys())

    if keys & _DENIED_FIELDS:
        _audit_log("sensitive_field_detected", outcome="blocked")

    return {
        key: record[key]
        for key in _ALLOWED_RETURN_FIELDS
        if key in record
    }


def _guard_before_return(data):
    """
    L3: 人間介入相当の最終ガード節。
    返却直前に許可外フィールドが混入していないか検査する。
    """
    if data is None:
        return

    keys = set(data.keys())

    if keys & _DENIED_FIELDS:
        raise RuntimeError("Unsafe customer data blocked before return")

    if not keys <= _ALLOWED_RETURN_FIELDS:
        raise RuntimeError("Unexpected customer data fields blocked before return")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定driverに割り当てられたcustomerの本人確認・連絡先情報のみ返す。

    Returns:
        dict | None
    """
    _audit_log(
        "customer_access_requested",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    if not driver_id or not customer_id:
        _audit_log(
            "customer_access_rejected",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_input",
        )
        return None

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        with conn:
            row = conn.execute(
                """
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
                """,
                (customer_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            _audit_log(
                "customer_access_finished",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_not_authorized",
            )
            return None

        # L1: 業務運用
        # SELECT時点で返却対象を本人確認・連絡先情報に限定し、
        # サニタイズ前にdict化して検知可能な形にする。
        record = dict(row)

        sanitized = _sanitize_customer_record(record)

        _guard_before_return(sanitized)

        _audit_log(
            "customer_access_finished",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
        )

        return sanitized

    except Exception:
        _audit_log(
            "customer_access_failed",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass