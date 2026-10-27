import os
import sqlite3
import logging
import hashlib
import json


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")
_AUDIT_LOGGER.addHandler(logging.NullHandler())

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

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _hash_for_audit(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit(event, driver_id, customer_id, outcome):
    record = {
        "event": event,
        "driver_ref": _hash_for_audit(driver_id),
        "customer_ref": _hash_for_audit(customer_id),
        "outcome": outcome,
    }
    _AUDIT_LOGGER.info(json.dumps(record, ensure_ascii=False, sort_keys=True))


def _detect_personal_info_classes(record):
    return {
        "has_identity": any(record.get(k) for k in ("customer_id", "id", "name", "display_name", "full_name")),
        "has_contact": any(record.get(k) for k in ("address", "phone", "phone_number")),
    }


def _sanitize_customer_record(record):
    sanitized = {}

    for field in _ALLOWED_CUSTOMER_FIELDS:
        sanitized[field] = record.get(field)

    for forbidden in _FORBIDDEN_FIELDS:
        if forbidden in sanitized:
            del sanitized[forbidden]

    return sanitized


def _guard_before_return(record):
    if not isinstance(record, dict):
        raise PermissionError("Unsafe customer response blocked.")

    if any(field in record for field in _FORBIDDEN_FIELDS):
        raise PermissionError("Unsafe customer response blocked.")

    if any(field not in _ALLOWED_CUSTOMER_FIELDS for field in record):
        raise PermissionError("Unsafe customer response blocked.")


def get_customer_for_driver(driver_id, customer_id):
    if not driver_id or not customer_id:
        raise ValueError("driver_id and customer_id are required.")

    _safe_audit("customer_access.requested", driver_id, customer_id, "started")

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
                OR (
                    NOT EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca2
                        WHERE dca2.driver_id = ?
                          AND dca2.customer_id = c.customer_id
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
                )
          )
        LIMIT 1
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            query,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

    if row is None:
        _safe_audit("customer_access.completed", driver_id, customer_id, "not_found_or_denied")
        return None

    raw_record = dict(row)

    # L1: 個人情報の存在クラスのみ検知。値はログ出力しない。
    _detect_personal_info_classes(raw_record)

    # L2: 最小権限の返却データへサニタイズ。
    result = _sanitize_customer_record(raw_record)

    # L3: 返却直前のガード。
    _guard_before_return(result)

    # L4: 安全な監査ログ。
    _safe_audit("customer_access.completed", driver_id, customer_id, "allowed")

    return result