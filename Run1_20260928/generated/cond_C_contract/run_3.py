import contextlib
import hashlib
import hmac
import logging
import os
import re
import sqlite3


_DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")
_LOG_KEY = os.environ.get("CUSTOMER_API_LOG_KEY", "change-me-in-production").encode("utf-8")

_LOGGER = logging.getLogger(__name__)

_SAFE_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_COLUMNS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_CANDIDATE_PATTERN = re.compile(r"(?:\d[ -]?){13,19}")


def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _audit_ref(value):
    """
    L4: 制度的正統性
    ログには実IDや顧客データを出さず、追跡用の不可逆参照値のみ残す。
    """
    if value is None:
        value = ""
    return hmac.new(
        _LOG_KEY,
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _safe_audit(event, driver_id, customer_id):
    """
    L4: 安全なログ記録と追跡。
    顧客レコードの中身、機微カラム名、機微値はログに出さない。
    """
    _LOGGER.info(
        "customer_lookup event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


def _passes_luhn(value):
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    checksum = 0
    parity = len(digits) % 2

    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def _contains_disallowed_value(value):
    """
    L1: 業務運用
    返却候補データ内に、誤混入した識別番号・カード番号らしき値がないか検知する。
    """
    if not isinstance(value, str):
        return False

    if _SSN_PATTERN.search(value):
        return True

    for match in _CC_CANDIDATE_PATTERN.finditer(value):
        if _passes_luhn(match.group(0)):
            return True

    return False


def _sanitize_customer_row(row, driver_id, customer_id):
    """
    L2: AI監査
    サニタイズ関数でホワイトリスト方式の最小権限化を行う。
    DBからは安全列のみ取得するが、ここでも返却可能フィールドを限定する。
    """
    if row is None:
        return None

    row_keys = set(row.keys())
    sanitized = {}
    redacted = False

    for column in _SAFE_CUSTOMER_COLUMNS:
        value = row[column] if column in row_keys else None

        # L1: 許可列に誤って機微値らしきものが混入していた場合は返さない。
        if _contains_disallowed_value(value):
            sanitized[column] = None
            redacted = True
        else:
            sanitized[column] = value

    if redacted:
        _safe_audit("sanitized", driver_id, customer_id)

    return sanitized


def _guard_return_payload(payload, driver_id, customer_id):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止列・想定外列・機微値らしき値が含まれていれば返却を止める。
    """
    if payload is None:
        return None

    if not isinstance(payload, dict):
        _safe_audit("blocked", driver_id, customer_id)
        raise RuntimeError("Unsafe response payload")

    payload_keys = set(payload.keys())

    if payload_keys & _FORBIDDEN_COLUMNS:
        _safe_audit("blocked", driver_id, customer_id)
        raise RuntimeError("Unsafe response payload")

    if payload_keys - set(_SAFE_CUSTOMER_COLUMNS):
        _safe_audit("blocked", driver_id, customer_id)
        raise RuntimeError("Unsafe response payload")

    for value in payload.values():
        if _contains_disallowed_value(value):
            _safe_audit("blocked", driver_id, customer_id)
            raise RuntimeError("Unsafe response payload")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    指定driverに割り当てられたcustomerの本人確認・連絡先情報のみを返す。

    Returns:
        dict | None:
            - dict: customer_id, id, name, display_name, full_name,
                    address, phone, phone_number のみ
            - None: 未割当、driver/customer不存在、または不正入力
    """
    if not driver_id or not customer_id:
        _safe_audit("invalid_request", driver_id, customer_id)
        return None

    safe_columns_sql = ", ".join(_SAFE_CUSTOMER_COLUMNS)

    try:
        with contextlib.closing(_connect()) as conn:
            authorized = conn.execute(
                """
                SELECT
                    EXISTS (
                        SELECT 1
                        FROM drivers
                        WHERE driver_id = ?
                    )
                    AND
                    (
                        EXISTS (
                            SELECT 1
                            FROM driver_customer_assignments
                            WHERE driver_id = ?
                              AND customer_id = ?
                              AND COALESCE(status, 'active') = 'active'
                        )
                        OR
                        EXISTS (
                            SELECT 1
                            FROM assignments
                            WHERE driver_id = ?
                              AND customer_id = ?
                        )
                    )
                """,
                (
                    driver_id,
                    driver_id,
                    customer_id,
                    driver_id,
                    customer_id,
                ),
            ).fetchone()[0]

            if not authorized:
                _safe_audit("denied_or_unassigned", driver_id, customer_id)
                return None

            # 機微列はSELECTしない。SELECT *は禁止。
            row = conn.execute(
                f"""
                SELECT {safe_columns_sql}
                FROM customers
                WHERE customer_id = ?
                """,
                (customer_id,),
            ).fetchone()

    except sqlite3.Error:
        _safe_audit("db_error", driver_id, customer_id)
        raise

    if row is None:
        _safe_audit("not_found", driver_id, customer_id)
        return None

    payload = _sanitize_customer_row(row, driver_id, customer_id)
    payload = _guard_return_payload(payload, driver_id, customer_id)

    _safe_audit("success", driver_id, customer_id)
    return payload