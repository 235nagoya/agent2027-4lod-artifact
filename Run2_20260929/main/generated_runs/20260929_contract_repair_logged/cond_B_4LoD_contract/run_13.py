import os
import sqlite3
import logging
import hashlib


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", os.environ.get("DB_PATH", "app.db"))

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")

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


def _safe_ref(value):
    """
    L4: 追跡用の安全な参照値。
    ログに生IDを残さず、ハッシュ化された参照のみを記録する。
    """
    if value is None:
        return None

    salt = os.environ.get("AUDIT_LOG_SALT", "local-audit-salt")
    raw = f"{salt}:{value}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def _audit(event, driver_id=None, customer_id=None, outcome=None):
    """
    L4: 安全なログ記録と追跡。
    個人情報やDB取得データそのものは記録しない。
    """
    _AUDIT_LOGGER.info(
        "customer_access_audit",
        extra={
            "audit_event": event,
            "driver_ref": _safe_ref(driver_id),
            "customer_ref": _safe_ref(customer_id),
            "outcome": outcome,
        },
    )


def _sanitize_customer_record(record):
    """
    L2: AI監査・最小権限化。
    返却可能な identity/contact 系フィールドだけを残す。
    """
    if not isinstance(record, dict):
        return {}

    sanitized = {}

    for field in _ALLOWED_CUSTOMER_FIELDS:
        if field in record:
            sanitized[field] = record[field]

    return sanitized


def _has_forbidden_fields(payload):
    """
    L1: 業務運用上の検知。
    返却対象に含めてはいけないフィールドが混入していないか検知する。
    """
    if not isinstance(payload, dict):
        return True

    return any(field in payload for field in _FORBIDDEN_CUSTOMER_FIELDS)


def _return_guard(payload):
    """
    L3: 人間介入前提の最終ガード節。
    返却直前に、許可フィールドのみで構成されていることを確認する。
    """
    if not isinstance(payload, dict):
        return False

    if _has_forbidden_fields(payload):
        return False

    if not set(payload.keys()).issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        return False

    if not payload.get("customer_id"):
        return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _audit(
            "customer_lookup_rejected",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_request",
        )
        return None

    driver_id = str(driver_id)
    customer_id = str(customer_id)

    if not driver_id or not customer_id:
        _audit(
            "customer_lookup_rejected",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_request",
        )
        return None

    selected_columns = ", ".join(f"c.{field}" for field in _ALLOWED_CUSTOMER_FIELDS)

    sql = f"""
        SELECT {selected_columns}
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
    """

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(sql, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            _audit(
                "customer_lookup_not_returned",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_not_assigned",
            )
            return None

        raw_record = dict(row)

        # L1 + L2: 検知後、許可フィールドのみにサニタイズ
        customer = _sanitize_customer_record(raw_record)

        # L3: 返却直前の最終ガード
        if not _return_guard(customer):
            _audit(
                "customer_lookup_blocked",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="return_guard_failed",
            )
            return None

        # L4: 成功監査ログ。顧客データ本体は記録しない。
        _audit(
            "customer_lookup_returned",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
        )

        return customer

    except sqlite3.Error:
        _audit(
            "customer_lookup_error",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="database_error",
        )
        raise

    finally:
        conn.close()