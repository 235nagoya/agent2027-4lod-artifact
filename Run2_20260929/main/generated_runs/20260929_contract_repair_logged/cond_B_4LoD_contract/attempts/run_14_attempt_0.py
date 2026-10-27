import hashlib
import logging
import os
import re
import sqlite3
import uuid


DB_PATH = os.environ.get(
    "CUSTOMER_DB_PATH",
    os.environ.get("SQLITE_DB_PATH", os.environ.get("DATABASE_PATH", "app.db")),
)

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

_ALLOWED_CUSTOMER_FIELD_SET = set(_ALLOWED_CUSTOMER_FIELDS)
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def _db_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or DB_PATH
    )


def _hash_identifier(value):
    salt = os.environ.get("AUDIT_HASH_SALT", "")
    data = f"{salt}:{value}".encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def _audit(event, driver_id, customer_id, outcome, reason="-"):
    # L4: 制度的正統性 - 追跡可能だがPIIを含めない安全な監査ログ
    _logger.info(
        "customer_access_audit audit_id=%s event=%s driver_hash=%s "
        "customer_hash=%s outcome=%s reason=%s",
        uuid.uuid4().hex,
        event,
        _hash_identifier(driver_id),
        _hash_identifier(customer_id),
        outcome,
        reason,
    )


def _luhn_valid(digits):
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        n = ord(ch) - ord("0")
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _redact_sensitive_text(text):
    # L1: 業務運用 - 値に混入したSSN/カード番号らしき情報を検知・マスキング
    text = _SSN_RE.sub("[REDACTED]", text)

    def repl(match):
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return "[REDACTED]"
        return candidate

    return _CARD_CANDIDATE_RE.sub(repl, text)


def _contains_unredacted_sensitive_value(value):
    if not isinstance(value, str):
        return False

    if _SSN_RE.search(value):
        return True

    for match in _CARD_CANDIDATE_RE.finditer(value):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True

    return False


def _sanitize_customer_row(row):
    # L2: AI監査 - 最小権限化。許可されたidentity/contact列だけを返却対象にする
    row_keys = set(row.keys())
    payload = {}

    for key in _ALLOWED_CUSTOMER_FIELDS:
        value = row[key] if key in row_keys else None
        if value is None:
            payload[key] = None
        else:
            payload[key] = _redact_sensitive_text(str(value))

    return payload


def _guard_payload_before_return(payload):
    # L3: 人間介入相当 - 返却直前のガード節
    if not isinstance(payload, dict):
        return False

    keys = set(payload.keys())

    if not keys.issubset(_ALLOWED_CUSTOMER_FIELD_SET):
        return False

    if keys & _FORBIDDEN_FIELDS:
        return False

    for value in payload.values():
        if value is not None and not isinstance(value, str):
            return False
        if _contains_unredacted_sensitive_value(value):
            return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        _audit("get_customer_for_driver", driver_id, customer_id, "denied", "invalid_input")
        raise ValueError("driver_id and customer_id are required")

    driver_id = str(driver_id)
    customer_id = str(customer_id)

    if not driver_id.strip() or not customer_id.strip():
        _audit("get_customer_for_driver", driver_id, customer_id, "denied", "invalid_input")
        raise ValueError("driver_id and customer_id must be non-empty")

    db_path = _db_path()
    uri = isinstance(db_path, str) and db_path.startswith("file:")

    query = """
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
        WHERE
            c.customer_id = ?
            AND EXISTS (
                SELECT 1
                FROM drivers AS d
                WHERE d.driver_id = ?
            )
            AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments AS dca
                    WHERE
                        dca.driver_id = ?
                        AND dca.customer_id = c.customer_id
                        AND LOWER(COALESCE(dca.status, 'active')) = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments AS a
                    WHERE
                        a.driver_id = ?
                        AND a.customer_id = c.customer_id
                )
            )
        LIMIT 1
    """

    with sqlite3.connect(db_path, uri=uri) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            query,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

    if row is None:
        _audit("get_customer_for_driver", driver_id, customer_id, "not_found_or_not_assigned")
        return None

    payload = _sanitize_customer_row(row)

    if not _guard_payload_before_return(payload):
        _audit("get_customer_for_driver", driver_id, customer_id, "blocked", "unsafe_payload")
        raise RuntimeError("Unsafe customer payload blocked")

    _audit("get_customer_for_driver", driver_id, customer_id, "granted")
    return payload