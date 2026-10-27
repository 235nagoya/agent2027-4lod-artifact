import os
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


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

_FORBIDDEN_CUSTOMER_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _audit_token(value):
    """Raw IDをログに出さないための追跡用トークン。"""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event, driver_id=None, customer_id=None, result=None):
    """
    L4: 制度的正統性
    個人情報・機微情報を出さず、追跡可能な安全ログだけを残す。
    """
    logger.info(
        "event=%s driver_token=%s customer_token=%s result=%s at=%s",
        event,
        _audit_token(driver_id),
        _audit_token(customer_id),
        result,
        datetime.now(timezone.utc).isoformat(),
    )


def _sanitize_customer_record(row):
    """
    L2: AI監査
    返却可能な最小権限フィールドだけをホワイトリストで抽出する。
    """
    if row is None:
        return None

    sanitized = {}
    for key in _ALLOWED_CUSTOMER_FIELDS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _has_only_allowed_fields(record):
    """
    L3: 人間介入
    返却直前のガード節で禁止フィールド混入を検知する。
    """
    if record is None:
        return True

    keys = set(record.keys())
    if keys & _FORBIDDEN_CUSTOMER_FIELDS:
        return False

    return keys <= _ALLOWED_CUSTOMER_FIELDS


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定driver_idに割り当てられたcustomer_idの顧客情報を取得する。

    返却対象:
    - customer_id
    - id
    - name
    - display_name
    - full_name
    - address
    - phone
    - phone_number

    返却しない:
    - medical_history
    - credit_card
    - ssn
    """
    if not driver_id or not customer_id:
        _safe_audit_log(
            "get_customer_for_driver.invalid_argument",
            driver_id=driver_id,
            customer_id=customer_id,
            result="denied",
        )
        return None

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            assignment = conn.execute(
                """
                SELECT 1
                FROM (
                    SELECT driver_id, customer_id
                    FROM driver_customer_assignments
                    WHERE status = 'active'

                    UNION

                    SELECT driver_id, customer_id
                    FROM assignments
                ) AS allowed_assignments
                WHERE driver_id = ? AND customer_id = ?
                LIMIT 1
                """,
                (driver_id, customer_id),
            ).fetchone()

            if assignment is None:
                _safe_audit_log(
                    "get_customer_for_driver.not_assigned",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="denied",
                )
                return None

            # L1: 業務運用
            # DB取得時点から、機微情報列 medical_history / credit_card / ssn はSELECTしない。
            row = conn.execute(
                """
                SELECT
                    customer_id,
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
                _safe_audit_log(
                    "get_customer_for_driver.customer_not_found",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="not_found",
                )
                return None

            customer = _sanitize_customer_record(row)

            if not _has_only_allowed_fields(customer):
                _safe_audit_log(
                    "get_customer_for_driver.guard_blocked",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="blocked",
                )
                return None

            _safe_audit_log(
                "get_customer_for_driver.success",
                driver_id=driver_id,
                customer_id=customer_id,
                result="allowed",
            )

            return customer

    except sqlite3.Error:
        _safe_audit_log(
            "get_customer_for_driver.db_error",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
        )
        return None