import os
import re
import sqlite3
import hashlib
import logging

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "customers.db")

_ALLOWED_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_COLUMNS = {"medical_history", "credit_card", "ssn"}

_LOGGER = logging.getLogger(__name__)


def _db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _audit_ref(value):
    """
    L4: 安全なログ記録と追跡。
    driver_id / customer_id をそのままログに出さず、追跡用の短いハッシュだけを記録する。
    """
    salt = os.environ.get("AUDIT_LOG_SALT", "default-audit-salt")
    raw = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None, outcome=None):
    """
    L4: 個人情報・顧客レコード内容をログに出さない。
    """
    _LOGGER.info(
        "event=%s outcome=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        _audit_ref(driver_id) if driver_id is not None else None,
        _audit_ref(customer_id) if customer_id is not None else None,
    )


def _normalize_id(value, field_name):
    if value is None:
        raise ValueError(f"{field_name} is required")

    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"{field_name} is required")

    return normalized


def _luhn_valid(number):
    total = 0
    reverse_digits = list(map(int, reversed(number)))

    for index, digit in enumerate(reverse_digits):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def _contains_sensitive_pattern(value):
    """
    L1: データ内に誤混入した秘匿情報らしき値を検知する。
    """
    if not isinstance(value, str):
        return False

    # SSN-like pattern
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", value):
        return True

    # Credit-card-like pattern with Luhn check
    digit_groups = re.findall(r"(?:\d[ -]?){13,19}", value)
    for group in digit_groups:
        digits = re.sub(r"\D", "", group)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True

    return False


def _sanitize_customer_row(row):
    """
    L2: サニタイズ関数による最小権限化。
    許可された identity/contact カラムだけを返却候補にする。
    """
    if row is None:
        return None

    return {
        column: row[column]
        for column in _ALLOWED_CUSTOMER_COLUMNS
        if column in row.keys()
    }


def _guard_before_return(data):
    """
    L3: 返却直前のガード節。
    禁止カラムや秘匿情報らしき値が混入していれば返却しない。
    """
    if data is None:
        return None

    keys = set(data.keys())

    if keys & _FORBIDDEN_COLUMNS:
        raise RuntimeError("unsafe customer payload blocked")

    if not keys <= set(_ALLOWED_CUSTOMER_COLUMNS):
        raise RuntimeError("unexpected customer payload field blocked")

    for value in data.values():
        if _contains_sensitive_pattern(value):
            raise RuntimeError("sensitive-looking customer payload blocked")

    return data


def get_customer_for_driver(driver_id, customer_id):
    driver_id = _normalize_id(driver_id, "driver_id")
    customer_id = _normalize_id(customer_id, "customer_id")

    _safe_audit(
        "get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

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
        with _db_connect() as conn:
            row = conn.execute(sql, (customer_id, driver_id, driver_id)).fetchone()

        sanitized = _sanitize_customer_row(row)
        result = _guard_before_return(sanitized)

        _safe_audit(
            "get_customer_for_driver.finish",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="returned" if result is not None else "not_found_or_not_authorized",
        )

        return result

    except Exception:
        _safe_audit(
            "get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise