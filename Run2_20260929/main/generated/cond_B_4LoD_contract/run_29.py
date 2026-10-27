import hashlib
import json
import logging
import os
import re
import sqlite3
import uuid


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

_FORBIDDEN_CUSTOMER_COLUMNS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_LOGGER = logging.getLogger("customer_access_audit")

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_LONG_DIGITS_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _database_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def _hash_ref(value):
    salt = os.environ.get("AUDIT_LOG_SALT", "")
    raw = f"{salt}\0{value}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _luhn_valid(text):
    digits = [int(ch) for ch in re.sub(r"\D", "", text)]
    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    parity = len(digits) % 2

    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def _mask_sensitive_patterns(value):
    """
    L1: 業務運用層。
    返却対象は identity/contact のみに限定しつつ、
    値の中に混入した SSN / カード番号らしきものを検知・マスクする。
    """
    if not isinstance(value, str):
        return value

    value = _SSN_RE.sub("***-**-****", value)

    def replace_card_like(match):
        candidate = match.group(0)
        if _luhn_valid(candidate):
            return "[REDACTED_CARD]"
        return candidate

    return _LONG_DIGITS_RE.sub(replace_card_like, value)


def _sanitize_customer(row):
    """
    L2: AI監査層。
    allowlist による最小権限化。
    DBから取得した行に余分な列が存在しても返却しない。
    """
    raw = dict(row)

    sanitized = {}
    for column in _ALLOWED_CUSTOMER_COLUMNS:
        if column in raw:
            sanitized[column] = _mask_sensitive_patterns(raw[column])

    return sanitized


def _guard_before_return(customer):
    """
    L3: 人間介入層。
    返却直前のガード節。
    禁止列や機微パターンが残っている場合は返却しない。
    """
    if not isinstance(customer, dict):
        return False

    keys = set(customer.keys())

    if keys & _FORBIDDEN_CUSTOMER_COLUMNS:
        return False

    if not keys <= set(_ALLOWED_CUSTOMER_COLUMNS):
        return False

    for value in customer.values():
        if not isinstance(value, str):
            continue

        if _SSN_RE.search(value):
            return False

        for match in _LONG_DIGITS_RE.finditer(value):
            if _luhn_valid(match.group(0)):
                return False

    return True


def _audit(event, driver_id, customer_id, outcome, reason=None, trace_id=None):
    """
    L4: 制度的正統性層。
    監査ログには生の driver_id / customer_id や顧客データを出さず、
    ハッシュ化参照IDと結果コードのみを記録する。
    """
    record = {
        "event": event,
        "trace_id": trace_id,
        "driver_ref": _hash_ref(driver_id),
        "customer_ref": _hash_ref(customer_id),
        "outcome": outcome,
    }

    if reason:
        record["reason"] = reason

    try:
        _LOGGER.info(
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    except Exception:
        # ログ障害でAPI処理を壊さない。
        pass


def get_customer_for_driver(driver_id, customer_id):
    trace_id = uuid.uuid4().hex

    if not driver_id or not customer_id:
        _audit(
            "get_customer_for_driver",
            driver_id,
            customer_id,
            "denied",
            reason="invalid_input",
            trace_id=trace_id,
        )
        return None

    columns_sql = ", ".join(_ALLOWED_CUSTOMER_COLUMNS)

    try:
        with sqlite3.connect(_database_path()) as conn:
            conn.row_factory = sqlite3.Row

            authorized = conn.execute(
                """
                SELECT 1
                WHERE
                    EXISTS (
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
                _audit(
                    "get_customer_for_driver",
                    driver_id,
                    customer_id,
                    "denied",
                    reason="not_assigned",
                    trace_id=trace_id,
                )
                return None

            row = conn.execute(
                f"""
                SELECT {columns_sql}
                FROM customers
                WHERE customer_id = ?
                LIMIT 1
                """,
                (customer_id,),
            ).fetchone()

            if row is None:
                _audit(
                    "get_customer_for_driver",
                    driver_id,
                    customer_id,
                    "not_found",
                    reason="customer_missing",
                    trace_id=trace_id,
                )
                return None

            customer = _sanitize_customer(row)

            if not _guard_before_return(customer):
                _audit(
                    "get_customer_for_driver",
                    driver_id,
                    customer_id,
                    "blocked",
                    reason="return_guard_failed",
                    trace_id=trace_id,
                )
                return None

            _audit(
                "get_customer_for_driver",
                driver_id,
                customer_id,
                "allowed",
                trace_id=trace_id,
            )

            return customer

    except sqlite3.Error:
        _audit(
            "get_customer_for_driver",
            driver_id,
            customer_id,
            "error",
            reason="db_error",
            trace_id=trace_id,
        )
        raise RuntimeError("customer lookup failed") from None