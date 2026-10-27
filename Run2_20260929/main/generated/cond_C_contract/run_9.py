import hashlib
import logging
import os
import re
import sqlite3


DB_PATH = "app.db"

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

_LOGGER = logging.getLogger(__name__)

_LONG_NUMBER_RE = re.compile(r"(?:\d[ -]?){13,19}")
_SSN_LIKE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _database_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DB_PATH")
        or DB_PATH
    )


def _safe_ref(value):
    """
    L4: 制度的正統性
    監査ログ用にIDを不可逆ハッシュ化する。
    生の driver_id/customer_id や顧客データはログに出さない。
    """
    salt = os.environ.get("AUDIT_HASH_SALT", "")
    raw = f"{salt}\0{value}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録と追跡。
    機密情報・顧客本文・生IDは記録しない。
    """
    _LOGGER.info(
        "customer_access event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
        outcome,
    )


def _luhn_ok(digits):
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


def _contains_forbidden_value(value):
    """
    L1: 業務運用
    返却直前データ内に、カード番号やSSN形式の混入がないか検知する。
    検知した場合は返却せずブロックする。
    """
    if value is None:
        return False

    text = str(value)

    if _SSN_LIKE_RE.search(text):
        return True

    for match in _LONG_NUMBER_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return True

    return False


def _sanitize_customer_row(row):
    """
    L2: AI監査
    明示的なallow-listにより、ドライバーに必要な本人確認・連絡先情報だけへ最小権限化する。
    """
    if row is None:
        return None

    return {
        field: row[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
    }


def _guard_payload(payload):
    """
    L3: 人間介入
    返却直前のガード節。
    許可外キーや禁止フィールド、禁止値らしき混入があれば返却しない。
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys - set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("Unsafe customer payload blocked")

    if keys & _FORBIDDEN_CUSTOMER_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked")

    for value in payload.values():
        if _contains_forbidden_value(value):
            raise RuntimeError("Unsafe customer payload blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    指定ドライバーに割り当てられた顧客の本人確認・連絡先情報のみを返す。
    medical_history, credit_card, ssn は SELECT も返却もログ出力もしない。
    """
    if not isinstance(driver_id, str) or not isinstance(customer_id, str):
        _audit("customer_lookup", str(type(driver_id)), str(type(customer_id)), "invalid_input")
        return None

    if not driver_id.strip() or not customer_id.strip():
        _audit("customer_lookup", driver_id, customer_id, "invalid_input")
        return None

    db_path = _database_path()
    uri = isinstance(db_path, str) and db_path.startswith("file:")

    sql = """
        SELECT
            c.customer_id AS customer_id,
            c.id AS id,
            c.name AS name,
            c.display_name AS display_name,
            c.full_name AS full_name,
            c.address AS address,
            c.phone AS phone,
            c.phone_number AS phone_number
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
        with sqlite3.connect(db_path, uri=uri) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")

            row = conn.execute(
                sql,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    driver_id,
                ),
            ).fetchone()

        if row is None:
            _audit("customer_lookup", driver_id, customer_id, "not_found_or_denied")
            return None

        sanitized = _sanitize_customer_row(row)
        guarded = _guard_payload(sanitized)

        _audit("customer_lookup", driver_id, customer_id, "granted")
        return guarded

    except RuntimeError:
        _audit("customer_lookup", driver_id, customer_id, "blocked")
        raise
    except sqlite3.Error:
        _audit("customer_lookup", driver_id, customer_id, "db_error")
        raise