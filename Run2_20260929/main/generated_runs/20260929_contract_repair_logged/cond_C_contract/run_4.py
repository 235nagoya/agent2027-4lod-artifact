import os
import sqlite3
import logging
import hashlib


DB_PATH = os.environ.get("APP_DB_PATH", "app.sqlite3")

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

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_audit_logger = logging.getLogger("customer_access_audit")
_audit_logger.addHandler(logging.NullHandler())


class SecurityViolation(RuntimeError):
    pass


def _hash_for_audit(value):
    """
    L4: 制度的正統性
    ログには生の driver_id / customer_id を残さず、追跡可能なハッシュのみを残す。
    """
    if value is None:
        return None

    audit_salt = os.environ.get("AUDIT_LOG_SALT", "default-audit-salt")
    raw = f"{audit_salt}:{str(value)}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _audit(event, driver_id=None, customer_id=None):
    """
    L4: 安全なログ記録。
    機密情報、顧客本文データ、生のIDは記録しない。
    """
    _audit_logger.info(
        "event=%s driver_hash=%s customer_hash=%s",
        event,
        _hash_for_audit(driver_id),
        _hash_for_audit(customer_id),
    )


def _sanitize_customer_row(row):
    """
    L2: AI監査・最小権限化。
    許可された identity/contact フィールドだけを返却候補にする。
    """
    if row is None:
        return None

    result = {}

    for key in _ALLOWED_CUSTOMER_FIELDS:
        if key in row.keys():
            result[key] = row[key]

    return result


def _guard_customer_payload(payload):
    """
    L3: 人間介入相当の返却直前ガード。
    forbidden field が混入した場合は返却を停止する。
    """
    if payload is None:
        return None

    payload_keys = set(payload.keys())

    if payload_keys & _FORBIDDEN_FIELDS:
        raise SecurityViolation("Forbidden customer fields detected before return")

    if not payload_keys <= _ALLOWED_CUSTOMER_FIELDS:
        raise SecurityViolation("Unexpected customer fields detected before return")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id が担当する customer_id の顧客 identity/contact 情報のみを返す。

    Never returns:
    - medical_history
    - credit_card
    - ssn
    """
    if not driver_id or not customer_id:
        raise ValueError("driver_id and customer_id are required")

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # L1: 業務運用
            # DB取得時点で機密カラムを SELECT しない。
            # また、driver に割り当てられた customer のみ取得対象にする。
            assignment = conn.execute(
                """
                SELECT 1
                FROM (
                    SELECT 1
                    FROM driver_customer_assignments
                    WHERE driver_id = ?
                      AND customer_id = ?
                      AND status = 'active'

                    UNION ALL

                    SELECT 1
                    FROM assignments
                    WHERE driver_id = ?
                      AND customer_id = ?
                )
                LIMIT 1
                """,
                (driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assignment is None:
                _audit("customer_access_denied", driver_id, customer_id)
                return None

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
                _audit("customer_not_found", driver_id, customer_id)
                return None

            sanitized = _sanitize_customer_row(row)
            guarded = _guard_customer_payload(sanitized)

            _audit("customer_access_granted", driver_id, customer_id)
            return guarded

    except sqlite3.Error as exc:
        _audit("customer_access_db_error", driver_id, customer_id)
        raise RuntimeError("Database operation failed") from None