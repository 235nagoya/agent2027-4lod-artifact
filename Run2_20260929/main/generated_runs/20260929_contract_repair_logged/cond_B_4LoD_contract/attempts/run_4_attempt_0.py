import hashlib
import hmac
import logging
import os
import sqlite3


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", os.environ.get("DATABASE_PATH", "app.db"))

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

_LOGGER = logging.getLogger(__name__)
if not _LOGGER.handlers:
    _LOGGER.addHandler(logging.NullHandler())


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _audit_ref(value):
    secret = os.environ.get("AUDIT_LOG_SECRET", "local-audit-secret").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:16]


def _safe_audit(event, driver_id, customer_id, outcome, pii_field_count=None):
    # L4: raw IDや個人情報を出さず、追跡用の疑似匿名IDだけを記録する。
    _LOGGER.info(
        "customer_access_audit event=%s outcome=%s driver_ref=%s customer_ref=%s pii_field_count=%s",
        event,
        outcome,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
        pii_field_count,
    )


def _mask_value(key, value):
    if value is None:
        return None

    text = str(value)
    if not text:
        return text

    if key in ("phone", "phone_number"):
        return "****" + text[-4:] if len(text) > 4 else "****"

    if key in ("name", "display_name", "full_name"):
        return text[0] + "***"

    if key == "address":
        return text[:3] + "***" if len(text) > 3 else "***"

    if key in ("customer_id", "id"):
        return "***"

    return "***"


def _detect_and_mask_identity_contact(payload):
    # L1: 個人情報を検知し、ログ・監査向けにはマスク済みビューのみを作る。
    detected_keys = [
        key for key in _ALLOWED_CUSTOMER_FIELDS
        if key in payload and payload[key] not in (None, "")
    ]

    masked_view = {
        key: _mask_value(key, value) if key in detected_keys else value
        for key, value in payload.items()
    }

    return len(detected_keys), masked_view


def _sanitize_customer_record(row):
    # L2: 最小権限化。許可列だけを抽出する。
    source = {key: row[key] for key in row.keys()}
    return {
        key: source[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in source
    }


def _guard_customer_payload(payload):
    # L3: 返却直前のガード節。
    if not isinstance(payload, dict):
        raise RuntimeError("customer payload failed safety guard")

    keys = set(payload.keys())

    if keys & _FORBIDDEN_CUSTOMER_FIELDS:
        raise RuntimeError("customer payload failed safety guard")

    if not keys <= set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("customer payload failed safety guard")

    return dict(payload)


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _safe_audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_request",
        )
        return None

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
          AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments AS dca
                    WHERE dca.driver_id = ?
                      AND dca.customer_id = c.customer_id
                      AND (dca.status IS NULL OR dca.status = 'active')
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

    try:
        with _connect() as conn:
            conn.execute("PRAGMA query_only = TRUE")
            row = conn.execute(
                sql,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            _safe_audit(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_not_authorized",
            )
            return None

        sanitized = _sanitize_customer_record(row)
        pii_field_count, _masked_view = _detect_and_mask_identity_contact(sanitized)
        result = _guard_customer_payload(sanitized)

        _safe_audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            pii_field_count=pii_field_count,
        )

        return result

    except sqlite3.Error:
        _LOGGER.error(
            "customer_access_audit event=%s outcome=%s driver_ref=%s customer_ref=%s error_type=%s",
            "get_customer_for_driver",
            "db_error",
            _audit_ref(driver_id),
            _audit_ref(customer_id),
            "sqlite3_error",
        )
        raise