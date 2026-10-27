import hashlib
import hmac
import logging
import os
import sqlite3
import uuid

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

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

_FORBIDDEN_FIELDS = frozenset({"medical_history", "credit_card", "ssn"})

_AUDIT_KEY = os.environ.get("AUDIT_HASH_KEY")
_AUDIT_KEY_BYTES = _AUDIT_KEY.encode("utf-8") if _AUDIT_KEY else os.urandom(32)

_logger = logging.getLogger("customer_access_audit")


def _audit_ref(value):
    """L4: raw IDをログに出さず、追跡可能な参照値だけを記録する。"""
    return hmac.new(
        _AUDIT_KEY_BYTES,
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _safe_audit(event, trace_id, driver_id, customer_id, detail=None):
    """L4: 安全な監査ログ。個人情報・禁止項目値は記録しない。"""
    _logger.info(
        "event=%s trace_id=%s driver_ref=%s customer_ref=%s detail=%s",
        event,
        trace_id,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
        detail or {},
    )


def _validate_identifier(value, field_name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _driver_can_access_customer(conn, driver_id, customer_id):
    cur = conn.execute(
        """
        SELECT 1
          WHERE EXISTS (
                SELECT 1
                  FROM driver_customer_assignments
                 WHERE driver_id = ?
                   AND customer_id = ?
                   AND LOWER(COALESCE(status, 'active')) = 'active'
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
    )
    return cur.fetchone() is not None


def _fetch_customer_minimal(conn, customer_id):
    """
    L2: 最小権限化。
    禁止カラム medical_history / credit_card / ssn はSELECTしない。
    """
    cur = conn.execute(
        """
        SELECT customer_id,
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
    )
    return cur.fetchone()


def _sanitize_customer_row(row):
    """
    L2: サニタイズ関数。
    許可済みの本人確認・連絡先フィールドだけに縮約する。
    """
    if row is None:
        return None

    return {field: row[field] for field in _ALLOWED_CUSTOMER_FIELDS}


def _mask_value(value):
    """L1: 運用上のPII検知・マスキング用。返却・ログ出力には使わない。"""
    if value is None:
        return None
    text = str(value)
    if len(text) <= 2:
        return "*" * len(text)
    return text[0] + ("*" * (len(text) - 2)) + text[-1]


def _l1_mask_and_detect_pii(payload):
    """
    L1: データ内の個人情報を検知し、内部確認用にマスクする。
    マスク済みデータ自体もログ・返却しない。
    """
    masked = {
        key: _mask_value(value)
        for key, value in payload.items()
        if value not in (None, "")
    }
    return {
        "pii_detected": bool(masked),
        "masked_field_count": len(masked),
    }


def _return_guard(payload, expected_customer_id, trace_id, driver_id):
    """
    L3: 返却直前のガード節。
    禁止項目・想定外項目・ID不整合を検知したら返却を止める。
    """
    if not isinstance(payload, dict):
        _safe_audit("return_blocked", trace_id, driver_id, expected_customer_id)
        raise RuntimeError("Customer payload blocked pending review")

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        _safe_audit(
            "return_blocked",
            trace_id,
            driver_id,
            expected_customer_id,
            {"reason": "disallowed_field_detected"},
        )
        raise RuntimeError("Customer payload blocked pending review")

    if keys - set(_ALLOWED_CUSTOMER_FIELDS):
        _safe_audit(
            "return_blocked",
            trace_id,
            driver_id,
            expected_customer_id,
            {"reason": "unexpected_field_detected"},
        )
        raise RuntimeError("Customer payload blocked pending review")

    if payload.get("customer_id") != expected_customer_id:
        _safe_audit(
            "return_blocked",
            trace_id,
            driver_id,
            expected_customer_id,
            {"reason": "customer_id_mismatch"},
        )
        raise RuntimeError("Customer payload blocked pending review")


def get_customer_for_driver(driver_id, customer_id):
    driver_id = _validate_identifier(driver_id, "driver_id")
    customer_id = _validate_identifier(customer_id, "customer_id")
    trace_id = str(uuid.uuid4())

    _safe_audit("customer_lookup_requested", trace_id, driver_id, customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            if not _driver_can_access_customer(conn, driver_id, customer_id):
                _safe_audit(
                    "customer_lookup_denied",
                    trace_id,
                    driver_id,
                    customer_id,
                    {"reason": "not_assigned"},
                )
                raise PermissionError("driver is not assigned to this customer")

            row = _fetch_customer_minimal(conn, customer_id)
            if row is None:
                _safe_audit("customer_lookup_not_found", trace_id, driver_id, customer_id)
                return None

            payload = _sanitize_customer_row(row)

            # L1: PII検知・マスキング確認。値は返却・ログ出力しない。
            l1_result = _l1_mask_and_detect_pii(payload)
            _safe_audit(
                "customer_payload_sanitized",
                trace_id,
                driver_id,
                customer_id,
                {
                    "pii_detected": l1_result["pii_detected"],
                    "masked_field_count": l1_result["masked_field_count"],
                },
            )

            # L3: 返却直前の最終チェック。
            _return_guard(payload, customer_id, trace_id, driver_id)

            _safe_audit("customer_lookup_granted", trace_id, driver_id, customer_id)
            return payload

    except sqlite3.DatabaseError as exc:
        _safe_audit(
            "customer_lookup_db_error",
            trace_id,
            driver_id,
            customer_id,
            {"reason": "database_error"},
        )
        raise RuntimeError("customer lookup failed") from exc