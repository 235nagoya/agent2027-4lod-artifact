import hashlib
import logging
import os
import sqlite3


_DB_PATH = (
    os.environ.get("CUSTOMER_DB_PATH")
    or os.environ.get("SQLITE_DB_PATH")
    or os.environ.get("DB_PATH")
    or "app.db"
)

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

_NEVER_EXPOSE_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_logger = logging.getLogger(__name__)


def _audit_ref(value):
    """L4: 追跡用にIDを不可逆ハッシュ化する。"""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録。
    個人情報や機微情報そのものは記録せず、追跡用ハッシュのみを残す。
    """
    _logger.info(
        "event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
        outcome,
    )


def _detect_and_mask_forbidden_fields(record):
    """
    L1: 業務運用層。
    万一、禁止フィールドが混入した場合に検知し、値を保持しない。
    """
    detected = False
    masked = {}

    for key, value in record.items():
        if key in _NEVER_EXPOSE_FIELDS:
            detected = True
            masked[key] = None
        else:
            masked[key] = value

    return masked, detected


def _sanitize_customer_record(record):
    """
    L2: AI監査層。
    最小権限化として、返却可能な identity/contact フィールドだけに絞る。
    """
    return {
        key: record.get(key)
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in record
    }


def _final_return_guard(record):
    """
    L3: 人間介入層。
    返却直前に、禁止フィールドや想定外フィールドがないことを確認する。
    """
    if not isinstance(record, dict):
        return False

    keys = set(record.keys())

    if keys & _NEVER_EXPOSE_FIELDS:
        return False

    if not keys <= _ALLOWED_CUSTOMER_FIELDS:
        return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # driver が customer に割り当てられている場合のみ取得する。
        assignment_row = conn.execute(
            """
            SELECT 1
            WHERE EXISTS (
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND status = 'active'
            )
            OR EXISTS (
                SELECT 1
                FROM assignments
                WHERE driver_id = ?
                  AND customer_id = ?
            )
            LIMIT 1
            """,
            (driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assignment_row is None:
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "denied")
            return None

        # 最小限の identity/contact カラムのみ取得する。
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
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "not_found")
            return None

        raw_record = dict(row)

        masked_record, detected_forbidden = _detect_and_mask_forbidden_fields(raw_record)
        if detected_forbidden:
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "blocked")
            return None

        customer = _sanitize_customer_record(masked_record)

        if not _final_return_guard(customer):
            _safe_audit("get_customer_for_driver", driver_id, customer_id, "blocked")
            return None

        _safe_audit("get_customer_for_driver", driver_id, customer_id, "success")
        return customer

    finally:
        conn.close()