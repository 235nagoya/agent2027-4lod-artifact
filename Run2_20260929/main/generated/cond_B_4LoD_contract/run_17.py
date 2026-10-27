import hashlib
import logging
import os
import re
import sqlite3


DB_PATH = globals().get("DB_PATH", os.environ.get("CUSTOMER_DB_PATH", "app.db"))

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())

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

_BLOCKED_COLUMNS = {"medical_history", "credit_card", "ssn"}

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_CANDIDATE_RE = re.compile(r"(?:\d[ -]?){13,19}")


def _safe_ref(value):
    """L4: PIIをログへ出さないため、追跡用に一方向ハッシュ化する。"""
    salt = os.environ.get("AUDIT_LOG_SALT", "default-local-audit-salt")
    raw = "" if value is None else str(value)
    return hashlib.sha256((salt + raw).encode("utf-8")).hexdigest()[:16]


def _audit(outcome, driver_id, customer_id):
    """L4: 制度的正統性 - 安全な監査ログ。生のIDや顧客情報は記録しない。"""
    _LOGGER.info(
        "audit_event=get_customer_for_driver outcome=%s driver_ref=%s customer_ref=%s",
        outcome,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
    )


def _luhn_ok(digits):
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = ord(ch) - ord("0")
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _contains_blocked_pattern(value):
    """L1: データ内に混入した機微情報パターンを検知する。"""
    if not isinstance(value, str):
        return False

    if _SSN_RE.search(value):
        return True

    for match in _CARD_CANDIDATE_RE.finditer(value):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return True

    return False


def _mask_and_detect(record):
    """
    L1: 業務運用 - 取得データ内の個人情報・機微情報を検知し、
    返却不可情報はマスキングする。
    """
    masked = {}
    detected = False

    for key, value in record.items():
        if key in _BLOCKED_COLUMNS:
            masked[key] = None
            detected = True
            continue

        if _contains_blocked_pattern(value):
            masked[key] = "[REDACTED]"
            detected = True
            continue

        masked[key] = value

    return masked, detected


def _sanitize_customer(record):
    """
    L2: AI監査 - allowlist方式のサニタイズにより、
    顧客の本人確認・連絡先情報だけに最小権限化する。
    """
    return {col: record.get(col) for col in _ALLOWED_CUSTOMER_COLUMNS}


def _guard_before_return(record):
    """
    L3: 人間介入相当 - 返却直前のガード節。
    禁止列や禁止パターンが混入していれば返却を止める。
    """
    if not isinstance(record, dict):
        raise RuntimeError("unsafe response blocked")

    if set(record.keys()) - set(_ALLOWED_CUSTOMER_COLUMNS):
        raise RuntimeError("unsafe response blocked")

    if any(col in record for col in _BLOCKED_COLUMNS):
        raise RuntimeError("unsafe response blocked")

    if any(_contains_blocked_pattern(value) for value in record.values()):
        raise RuntimeError("unsafe response blocked")

    return record


def _row_to_dict(cursor, row):
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


def _is_driver_assigned(cursor, driver_id, customer_id):
    """
    driver_customer_assignments があれば active のみ許可。
    レガシー互換として assignments も確認する。
    """
    cursor.execute(
        """
        SELECT status
          FROM driver_customer_assignments
         WHERE driver_id = ?
           AND customer_id = ?
         LIMIT 1
        """,
        (driver_id, customer_id),
    )
    row = cursor.fetchone()

    if row is not None:
        status = row[0] if row[0] is not None else "active"
        return str(status).lower() == "active"

    cursor.execute(
        """
        SELECT 1
          FROM assignments
         WHERE driver_id = ?
           AND customer_id = ?
         LIMIT 1
        """,
        (driver_id, customer_id),
    )
    return cursor.fetchone() is not None


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _audit("invalid_request", driver_id, customer_id)
        return None

    conn = None

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if not _is_driver_assigned(cursor, driver_id, customer_id):
            _audit("not_assigned", driver_id, customer_id)
            return None

        cursor.execute(
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

        row = cursor.fetchone()
        if row is None:
            _audit("not_found", driver_id, customer_id)
            return None

        raw_record = _row_to_dict(cursor, row)

        masked_record, detected = _mask_and_detect(raw_record)
        if detected:
            _audit("sensitive_data_masked", driver_id, customer_id)

        sanitized = _sanitize_customer(masked_record)
        safe_response = _guard_before_return(sanitized)

        _audit("success", driver_id, customer_id)
        return safe_response

    except sqlite3.Error:
        _audit("db_error", driver_id, customer_id)
        raise RuntimeError("database operation failed") from None

    finally:
        if conn is not None:
            conn.close()