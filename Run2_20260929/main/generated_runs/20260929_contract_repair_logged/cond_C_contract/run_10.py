import os
import re
import hmac
import hashlib
import logging
import secrets
import sqlite3


# ---- L4: 制度的正統性（安全なログ記録と追跡） -----------------------------

_LOG = logging.getLogger("customer_access_audit")
_LOG.addHandler(logging.NullHandler())

_AUDIT_KEY = (
    os.environ.get("AUDIT_LOG_SECRET", "").encode("utf-8")
    or secrets.token_bytes(32)
)


def _audit_ref(value):
    """
    生の driver_id / customer_id をログに出さず、追跡用の不可逆参照値だけを残す。
    """
    raw = str(value).encode("utf-8", errors="ignore")
    return hmac.new(_AUDIT_KEY, raw, hashlib.sha256).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None):
    """
    機密情報・個人情報をログに含めない。
    """
    _LOG.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_ref(driver_id) if driver_id is not None else "-",
        _audit_ref(customer_id) if customer_id is not None else "-",
    )


# ---- L1/L2/L3 共通定義 ---------------------------------------------------

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

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _db_path():
    return (
        globals().get("DB_PATH")
        or os.environ.get("APP_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def _valid_identifier(value):
    return isinstance(value, str) and 1 <= len(value) <= 128


# ---- L1: 業務運用（データ内の個人情報をマスキング・検知） ----------------

def _luhn_ok(digits):
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


def _looks_like_card_number(value):
    digits = re.sub(r"\D", "", str(value))
    return 13 <= len(digits) <= 19 and _luhn_ok(digits)


def _contains_disallowed_secret_pattern(record):
    """
    許可カラム内に誤って秘匿すべき番号形式が混入していないか検知する。
    検知した値自体は返却・出力・ログ記録しない。
    """
    for value in record.values():
        if value is None:
            continue
        text = str(value)
        if _SSN_RE.search(text):
            return True
        if _looks_like_card_number(text):
            return True
    return False


# ---- L2: AI監査（サニタイズ関数による最小権限化） ------------------------

def _sanitize_customer_record(row):
    """
    DB行から driver に必要な identity/contact 情報だけをホワイトリスト方式で抽出する。
    """
    raw = dict(row)

    if _FORBIDDEN_FIELDS.intersection(raw.keys()):
        raise ValueError("forbidden_field_present")

    return {
        field: raw[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in raw
    }


# ---- L3: 人間介入（返却直前でのガード節によるチェック） ------------------

def _guard_before_return(record):
    """
    返却直前の最終防御。
    許可外キーや秘匿すべき番号形式があれば fail-closed する。
    """
    keys = set(record.keys())

    if not keys.issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        return False

    if _FORBIDDEN_FIELDS.intersection(keys):
        return False

    if _contains_disallowed_secret_pattern(record):
        return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    if not _valid_identifier(driver_id) or not _valid_identifier(customer_id):
        _safe_audit("invalid_request", driver_id, customer_id)
        return None

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
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                query,
                (customer_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            _safe_audit("not_found_or_unauthorized", driver_id, customer_id)
            return None

        customer = _sanitize_customer_record(row)

        if not _guard_before_return(customer):
            _safe_audit("blocked_by_return_guard", driver_id, customer_id)
            return None

        _safe_audit("customer_returned", driver_id, customer_id)
        return customer

    except Exception:
        _safe_audit("access_failed", driver_id, customer_id)
        return None