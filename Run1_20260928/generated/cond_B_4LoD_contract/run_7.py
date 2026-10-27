import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", os.environ.get("DB_PATH", "app.db"))
AUDIT_LOG_PATH = os.environ.get("CUSTOMER_AUDIT_LOG", "customer_access_audit.log")
AUDIT_KEY = os.environ.get("CUSTOMER_AUDIT_KEY", "customer-access-audit-key").encode("utf-8")

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

_SENSITIVE_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _hash_identifier(value):
    if value is None:
        return None
    return hmac.new(
        AUDIT_KEY,
        str(value).encode("utf-8", errors="surrogatepass"),
        hashlib.sha256,
    ).hexdigest()


def _safe_reason(reason):
    reason = str(reason or "unknown")
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,80}", reason):
        return "sanitized_reason"
    return reason


def _audit(event, driver_id=None, customer_id=None, outcome="unknown", reason="unknown",
           sensitive_field_count=0):
    """
    L4: 制度的正統性
    - 監査ログには生データ、氏名、住所、電話番号などを記録しない。
    - driver_id / customer_id もHMAC化して追跡可能性と秘匿性を両立する。
    """
    record = {
        "ts": int(time.time()),
        "trace_id": uuid.uuid4().hex,
        "event": _safe_reason(event),
        "outcome": _safe_reason(outcome),
        "reason": _safe_reason(reason),
        "driver_ref": _hash_identifier(driver_id),
        "customer_ref": _hash_identifier(customer_id),
        "sensitive_field_count": int(sensitive_field_count),
    }

    try:
        fd = os.open(
            AUDIT_LOG_PATH,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError:
        # ログ失敗時も個人情報や例外詳細を外部へ出さない。
        pass


def _valid_identifier(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 256


def _sanitize_customer_record(row):
    """
    L1/L2:
    - L1: DB行に許可外・機微フィールドが混入していないか検知する。
    - L2: allow-list方式で返却データを最小権限化する。
    """
    raw = dict(row)
    detected_sensitive = set(raw).intersection(_SENSITIVE_FIELDS)

    sanitized = {
        key: raw.get(key)
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in raw
    }

    return sanitized, detected_sensitive


def _guard_customer_payload(payload):
    """
    L3: 人間介入相当の最終ガード節。
    返却直前に、許可フィールドのみであることを確認する。
    """
    if payload is None:
        return None

    keys = set(payload)
    if keys - _ALLOWED_CUSTOMER_FIELDS:
        raise RuntimeError("unsafe_customer_payload_blocked")

    if keys & _SENSITIVE_FIELDS:
        raise RuntimeError("unsafe_customer_payload_blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    if not _valid_identifier(driver_id) or not _valid_identifier(customer_id):
        _audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="denied",
            reason="invalid_identifier",
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
            row = conn.execute(
                query,
                (customer_id, driver_id, driver_id, driver_id),
            ).fetchone()
    except sqlite3.Error:
        _audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
            reason="database_error",
        )
        return None

    if row is None:
        _audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="denied",
            reason="not_found_or_not_assigned",
        )
        return None

    payload, detected_sensitive = _sanitize_customer_record(row)

    if detected_sensitive:
        _audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason="sensitive_field_detected",
            sensitive_field_count=len(detected_sensitive),
        )
        return None

    payload = _guard_customer_payload(payload)

    _audit(
        event="get_customer_for_driver",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="allowed",
        reason="success",
    )

    return payload