import hashlib
import logging
import os
import re
import sqlite3


_LOG = logging.getLogger(__name__)

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

_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_CANDIDATE_PATTERN = re.compile(r"(?:\d[ -]?){13,19}")


def _db_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )


def _audit_token(value):
    """
    L4: 制度的正統性
    監査ログでは raw の driver_id/customer_id を出さず、不可逆トークン化する。
    """
    salt = os.environ.get("AUDIT_LOG_SALT", "customer-api-audit")
    raw = f"{salt}:{value}".encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(raw).hexdigest()[:16]


def _audit(event, driver_id, customer_id):
    """
    L4: 安全なログ記録と追跡。
    機密情報・顧客の氏名・住所・電話番号・生データIDはログに出さない。
    """
    _LOG.info(
        "customer_access event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_token(driver_id),
        _audit_token(customer_id),
    )


def _luhn_valid(digits):
    total = 0
    reverse_digits = digits[::-1]

    for index, ch in enumerate(reverse_digits):
        n = ord(ch) - ord("0")
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def _mask_sensitive_contamination(value):
    """
    L1: 業務運用
    本来返却対象である identity/contact フィールドに、誤ってカード番号やSSN形式の
    文字列が混入していた場合にマスキングする。
    """
    if not isinstance(value, str):
        return value

    value = _SSN_PATTERN.sub("[REDACTED]", value)

    def replace_cc_candidate(match):
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)

        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return "[REDACTED]"

        return candidate

    return _CC_CANDIDATE_PATTERN.sub(replace_cc_candidate, value)


def _sanitize_customer(row):
    """
    L2: AI監査
    allowlist 方式で最小権限化する。
    DBから取得した行に余計な列が含まれていても返却しない。
    """
    if row is None:
        return None

    raw = dict(row)

    sanitized = {}
    for field in _ALLOWED_CUSTOMER_FIELDS:
        if field in raw:
            sanitized[field] = _mask_sensitive_contamination(raw[field])

    return sanitized


def _guard_response(payload):
    """
    L3: 人間介入
    返却直前の最終ガード。
    禁止フィールド、または allowlist 外のフィールドが混入した場合は返却を止める。
    """
    if payload is None:
        return

    keys = set(payload.keys())

    if keys & _FORBIDDEN_CUSTOMER_FIELDS:
        raise RuntimeError("unsafe response blocked")

    if not keys <= set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("unsafe response blocked")


def get_customer_for_driver(driver_id, customer_id):
    if not isinstance(driver_id, str) or not isinstance(customer_id, str):
        _audit("invalid_request", driver_id, customer_id)
        return None

    if not driver_id.strip() or not customer_id.strip():
        _audit("invalid_request", driver_id, customer_id)
        return None

    try:
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row

            # 担当ドライバーに割り当てられた顧客のみ取得可能にする。
            assignment = conn.execute(
                """
                SELECT 1
                WHERE EXISTS (
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
                LIMIT 1
                """,
                (driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assignment is None:
                _audit("denied_or_not_assigned", driver_id, customer_id)
                return None

            # L1/L2: SELECT * は使わず、返却可能な identity/contact 列のみ射影する。
            columns = ", ".join(_ALLOWED_CUSTOMER_FIELDS)
            row = conn.execute(
                f"""
                SELECT {columns}
                FROM customers
                WHERE customer_id = ?
                LIMIT 1
                """,
                (customer_id,),
            ).fetchone()

            if row is None:
                _audit("not_found", driver_id, customer_id)
                return None

            payload = _sanitize_customer(row)

            # L3: 返却直前チェック
            _guard_response(payload)

            # L4: 安全な監査ログ
            _audit("success", driver_id, customer_id)

            return payload

    except sqlite3.Error:
        _audit("database_error", driver_id, customer_id)
        raise RuntimeError("database error") from None