import hashlib
import logging
import os
import sqlite3


_LOG = logging.getLogger("customer_access_audit")

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

_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _db_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or "app.db"
    )


def _safe_ref(value):
    """
    L4: 制度的正統性
    監査ログ用に、IDの実値ではなく短いハッシュ参照だけを残す。
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:16]


def _audit(event, driver_id=None, customer_id=None, outcome="unknown"):
    """
    L4: 安全なログ記録と追跡。
    顧客データ本体や機密列の値は一切ログに出さない。
    """
    driver_ref = _safe_ref(driver_id) if isinstance(driver_id, str) else "invalid"
    customer_ref = _safe_ref(customer_id) if isinstance(customer_id, str) else "invalid"

    _LOG.info(
        "event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        driver_ref,
        customer_ref,
        outcome,
    )


def _validate_id(value, field_name):
    if not isinstance(value, str) or not value.strip():
        _LOG.warning("event=get_customer_for_driver outcome=invalid_input")
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _contains_forbidden_fields(mapping):
    """
    L1: 業務運用
    返却候補データ内に禁止フィールドが混入していないか検知する。
    """
    if not isinstance(mapping, dict):
        return False
    return any(key in _FORBIDDEN_FIELDS for key in mapping.keys())


def _sanitize_customer_record(record):
    """
    L2: AI監査
    サニタイズ関数により、返却フィールドを最小権限に限定する。
    """
    if record is None:
        return None

    if _contains_forbidden_fields(record):
        raise RuntimeError("Forbidden field detected before sanitization")

    return {
        field: record[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in record
    }


def _guard_return_payload(payload):
    """
    L3: 人間介入
    返却直前のガード節。
    許可フィールド以外、または禁止フィールドがあれば返さない。
    """
    if payload is None:
        return None

    if _contains_forbidden_fields(payload):
        raise RuntimeError("Forbidden field detected before return")

    unexpected = set(payload.keys()) - set(_ALLOWED_CUSTOMER_FIELDS)
    if unexpected:
        raise RuntimeError("Unexpected field detected before return")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    driver_id = _validate_id(driver_id, "driver_id")
    customer_id = _validate_id(customer_id, "customer_id")

    _audit(
        event="get_customer_for_driver",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    columns = ", ".join(
        f"c.{field} AS {field}" for field in _ALLOWED_CUSTOMER_FIELDS
    )

    query = f"""
        SELECT {columns}
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
                        AND LOWER(COALESCE(dca.status, 'active')) = 'active'
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
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row

            row = conn.execute(
                query,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    driver_id,
                ),
            ).fetchone()

            if row is None:
                _audit(
                    event="get_customer_for_driver",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    outcome="not_found_or_not_authorized",
                )
                return None

            raw_record = dict(row)

            # L1: 取得データ内の禁止フィールド混入を検知
            if _contains_forbidden_fields(raw_record):
                _audit(
                    event="get_customer_for_driver",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    outcome="blocked_forbidden_field_detected",
                )
                raise RuntimeError("Forbidden field detected")

            # L2: 最小権限化
            sanitized = _sanitize_customer_record(raw_record)

            # L3: 返却直前ガード
            result = _guard_return_payload(sanitized)

            # L4: 安全な監査ログ
            _audit(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="success",
            )

            return result

    except sqlite3.Error:
        _audit(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="db_error",
        )
        raise