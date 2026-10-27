import hashlib
import logging
import os
import re
import sqlite3

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", os.environ.get("DB_PATH", "app.db"))

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}
_ALLOWED_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _audit_id(value):
    """L4: ログ追跡用にIDを不可逆ハッシュ化する。"""
    raw = str(value).encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:16]


def _looks_like_credit_card(value):
    """L1: クレジットカード番号らしき値を検知する。"""
    if not isinstance(value, str):
        return False

    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False

    # Luhn check
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def _mask_if_sensitive(value):
    """L1: 値の中に混入した機微情報らしきものをマスキングする。"""
    if not isinstance(value, str):
        return value

    masked = _SSN_RE.sub("[REDACTED_SSN]", value)

    if _looks_like_credit_card(masked):
        return "[REDACTED_CREDIT_CARD]"

    return masked


def _sanitize_customer(row):
    """
    L2: 最小権限化。
    DBから取得した行を、返却可能な identity/contact 情報だけに限定する。
    """
    result = {}

    for field in _ALLOWED_FIELDS:
        if field in row.keys():
            value = row[field]
            if value is not None:
                result[field] = _mask_if_sensitive(value)

    return result


def _assert_safe_response(payload):
    """
    L3: 返却直前のガード節。
    禁止フィールドが混入していないことを確認する。
    """
    if not isinstance(payload, dict):
        raise RuntimeError("unsafe response type")

    forbidden = _FORBIDDEN_FIELDS.intersection(payload.keys())
    if forbidden:
        raise RuntimeError("unsafe response contains forbidden fields")

    for key, value in payload.items():
        if key not in _ALLOWED_FIELDS:
            raise RuntimeError("unsafe response contains non-allowed fields")

        if isinstance(value, str):
            if _SSN_RE.search(value) or _looks_like_credit_card(value):
                raise RuntimeError("unsafe response contains sensitive-looking data")


def get_customer_for_driver(driver_id, customer_id):
    if not driver_id or not customer_id:
        logger.warning(
            "customer_fetch_rejected invalid_input driver=%s customer=%s",
            _audit_id(driver_id),
            _audit_id(customer_id),
        )
        return None

    driver_audit = _audit_id(driver_id)
    customer_audit = _audit_id(customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # ドライバーに割り当てられた顧客のみ取得可能にする。
            assigned = conn.execute(
                """
                SELECT 1
                  FROM driver_customer_assignments
                 WHERE driver_id = ?
                   AND customer_id = ?
                   AND COALESCE(status, 'active') = 'active'
                UNION
                SELECT 1
                  FROM assignments
                 WHERE driver_id = ?
                   AND customer_id = ?
                LIMIT 1
                """,
                (driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assigned is None:
                logger.info(
                    "customer_fetch_denied driver=%s customer=%s",
                    driver_audit,
                    customer_audit,
                )
                return None

            # 禁止カラム medical_history, credit_card, ssn は SELECT しない。
            row = conn.execute(
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
                """,
                (customer_id,),
            ).fetchone()

            if row is None:
                logger.info(
                    "customer_fetch_not_found driver=%s customer=%s",
                    driver_audit,
                    customer_audit,
                )
                return None

            customer = _sanitize_customer(row)
            _assert_safe_response(customer)

            logger.info(
                "customer_fetch_success driver=%s customer=%s",
                driver_audit,
                customer_audit,
            )

            return customer

    except sqlite3.Error:
        logger.exception(
            "customer_fetch_db_error driver=%s customer=%s",
            driver_audit,
            customer_audit,
        )
        raise