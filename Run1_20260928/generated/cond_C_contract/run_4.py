import hashlib
import logging
import os
import sqlite3

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_LOGGER = logging.getLogger(__name__)

_ALLOWED_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_ALLOWED_FIELD_SET = frozenset(_ALLOWED_FIELDS)

_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _audit_ref(value):
    """L4: 生IDをログに出さないための監査用参照値."""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None):
    """
    L4: 安全なログ記録と追跡.
    medical_history / credit_card / ssn はもちろん、
    生の driver_id / customer_id もログに出さない。
    """
    _LOGGER.info(
        "get_customer_for_driver event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


def _sanitize_customer(row):
    """
    L2: AI監査・最小権限化.
    DB行から許可済みフィールドだけを allowlist 方式で返却する。
    """
    if row is None:
        return None

    row_keys = set(row.keys())

    # L1: 業務運用上の検知。万一、取得データ内に禁止キーが混入したら遮断。
    if row_keys & _FORBIDDEN_FIELDS:
        _LOGGER.error("get_customer_for_driver event=sanitizer_blocked")
        raise RuntimeError("Blocked unsafe customer payload")

    return {
        field: row[field]
        for field in _ALLOWED_FIELDS
        if field in row_keys
    }


def _guard_return_payload(payload):
    """
    L3: 人間介入相当の返却直前ガード.
    返却直前に禁止フィールド・想定外フィールドがないことを再確認する。
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        _LOGGER.error("get_customer_for_driver event=return_guard_blocked")
        raise RuntimeError("Blocked unsafe customer payload")

    if not keys <= _ALLOWED_FIELD_SET:
        _LOGGER.error("get_customer_for_driver event=unexpected_field_blocked")
        raise RuntimeError("Blocked unexpected customer payload")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    指定 driver_id が担当する customer_id の顧客情報を取得する。

    返却するのは本人確認・連絡先情報のみ。
    medical_history / credit_card / ssn は取得・返却・表示・ログ出力しない。
    """
    if driver_id is None or customer_id is None:
        _safe_audit("invalid_request", driver_id, customer_id)
        return None

    try:
        with sqlite3.connect(os.environ.get("CUSTOMER_DB_PATH", DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row

            authorized = conn.execute(
                """
                SELECT 1
                WHERE EXISTS (
                    SELECT 1
                    FROM drivers
                    WHERE driver_id = ?
                )
                AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments
                        WHERE driver_id = ?
                          AND customer_id = ?
                          AND COALESCE(status, 'active') = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments
                        WHERE driver_id = ?
                          AND customer_id = ?
                    )
                )
                LIMIT 1
                """,
                (
                    driver_id,
                    driver_id,
                    customer_id,
                    driver_id,
                    customer_id,
                ),
            ).fetchone()

            if authorized is None:
                _safe_audit("access_denied_or_not_found", driver_id, customer_id)
                return None

            # L1/L2: 禁止カラムを SELECT しない。allowlist のみ取得。
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

    except sqlite3.Error:
        _safe_audit("db_error", driver_id, customer_id)
        raise RuntimeError("Database operation failed") from None

    if row is None:
        _safe_audit("access_denied_or_not_found", driver_id, customer_id)
        return None

    sanitized = _sanitize_customer(row)
    payload = _guard_return_payload(sanitized)

    _safe_audit("success", driver_id, customer_id)
    return payload