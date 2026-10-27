import hashlib
import logging
import os
import sqlite3
import uuid


DATABASE_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

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
_logger.addHandler(logging.NullHandler())


def _audit_token(value):
    """ログ追跡用。生のIDや個人情報はログに出さない。"""
    text = "" if value is None else str(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _validate_id(value, field_name):
    """L2: 入力を最小限の識別子として扱う。"""
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid {field_name}")
    if len(value) > 256:
        raise ValueError(f"invalid {field_name}")
    return value


def _sanitize_customer_row(row):
    """
    L2: 最小権限化。
    DB行から返却許可された identity/contact フィールドのみを抽出する。
    """
    if row is None:
        return None

    return {
        field: row[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in row.keys()
    }


def _guard_payload_before_return(payload):
    """
    L3: 返却直前のガード。
    禁止フィールドが混入していないことを確認する。
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys & _FORBIDDEN_CUSTOMER_FIELDS:
        raise RuntimeError("unsafe customer payload blocked")

    if not keys <= set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("unexpected customer payload field blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    trace_id = uuid.uuid4().hex

    driver_id = _validate_id(driver_id, "driver_id")
    customer_id = _validate_id(customer_id, "customer_id")

    audit_driver = _audit_token(driver_id)
    audit_customer = _audit_token(customer_id)

    _logger.info(
        "customer_lookup_started trace_id=%s driver=%s customer=%s",
        trace_id,
        audit_driver,
        audit_customer,
    )

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # L2: driver が担当する customer のみ取得可能にする。
        assigned = conn.execute(
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

        if assigned is None:
            _logger.warning(
                "customer_lookup_denied trace_id=%s driver=%s customer=%s",
                trace_id,
                audit_driver,
                audit_customer,
            )
            return None

        # L1/L2: 必要な identity/contact カラムだけを明示的に取得する。
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

    payload = _sanitize_customer_row(row)
    payload = _guard_payload_before_return(payload)

    _logger.info(
        "customer_lookup_finished trace_id=%s driver=%s customer=%s found=%s",
        trace_id,
        audit_driver,
        audit_customer,
        payload is not None,
    )

    return payload