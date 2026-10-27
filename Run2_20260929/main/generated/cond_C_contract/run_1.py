import hashlib
import logging
import os
import re
import sqlite3


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

_FORBIDDEN_FIELDS = frozenset(("medical_history", "credit_card", "ssn"))

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _database_path():
    # テスト・運用環境で DB_PATH または CUSTOMER_DB_PATH を設定可能にする。
    return globals().get("DB_PATH") or os.environ.get("CUSTOMER_DB_PATH", "app.db")


def _normalize_identifier(value):
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _audit_token(value):
    """
    L4: 制度的正統性
    監査ログには生のIDや顧客データを出さず、追跡用のハッシュのみ記録する。
    """
    salt = os.environ.get("AUDIT_HASH_SALT", "")
    raw = "" if value is None else str(value)
    return hashlib.sha256((salt + "\0" + raw).encode("utf-8")).hexdigest()[:16]


def _audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録と追跡。
    顧客レコード本体・機密列・返却payloadは絶対にログ出力しない。
    """
    logging.getLogger("customer_access_audit").info(
        "event=%s outcome=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        _audit_token(driver_id),
        _audit_token(customer_id),
    )


def _luhn_valid(digits):
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False

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


def _looks_like_forbidden_secret(value):
    """
    L1: 業務運用
    返却予定データ内に、誤混入した機密情報らしき値がないか検知する。
    """
    if not isinstance(value, str):
        return False

    if _SSN_RE.search(value):
        return True

    for match in _CARD_CANDIDATE_RE.finditer(value):
        digits = re.sub(r"\D", "", match.group(0))
        if _luhn_valid(digits):
            return True

    return False


def _mask_if_needed(value):
    """
    L1: 業務運用
    誤って識別・連絡先欄に機密値らしきものが混入していた場合はマスクする。
    """
    if _looks_like_forbidden_secret(value):
        return None
    return value


def _sanitize_customer_record(row):
    """
    L2: AI監査
    サニタイズ関数により、最小権限の返却フィールドだけを allowlist で抽出する。
    forbidden columns は SELECT も返却もしない。
    """
    source = dict(row)
    return {
        field: _mask_if_needed(source[field])
        for field in _ALLOWED_FIELDS
        if field in source
    }


def _guard_safe_payload(payload):
    """
    L3: 人間介入相当
    返却直前のガード節。禁止キー・未許可キー・機密値疑いがあればブロックする。
    """
    if not isinstance(payload, dict):
        raise RuntimeError("unsafe customer payload blocked")

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("unsafe customer payload blocked")

    if keys - set(_ALLOWED_FIELDS):
        raise RuntimeError("unsafe customer payload blocked")

    for value in payload.values():
        if _looks_like_forbidden_secret(value):
            raise RuntimeError("unsafe customer payload blocked")


def get_customer_for_driver(driver_id, customer_id):
    driver_id = _normalize_identifier(driver_id)
    customer_id = _normalize_identifier(customer_id)

    if not driver_id or not customer_id:
        _audit("get_customer_for_driver", driver_id, customer_id, "invalid_input")
        return None

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
                    AND COALESCE(dca.status, 'active') = 'active'
              )
              OR (
                  NOT EXISTS (
                      SELECT 1
                      FROM driver_customer_assignments AS dca_any
                      WHERE dca_any.driver_id = ?
                        AND dca_any.customer_id = c.customer_id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM assignments AS a
                      WHERE a.driver_id = ?
                        AND a.customer_id = c.customer_id
                  )
              )
          )
        LIMIT 1
    """

    params = (customer_id, driver_id, driver_id, driver_id, driver_id)

    try:
        with sqlite3.connect(_database_path()) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")

            row = conn.execute(sql, params).fetchone()

    except sqlite3.Error:
        _audit("get_customer_for_driver", driver_id, customer_id, "db_error")
        raise

    if row is None:
        _audit("get_customer_for_driver", driver_id, customer_id, "not_found_or_unauthorized")
        return None

    payload = _sanitize_customer_record(row)

    try:
        _guard_safe_payload(payload)
    except RuntimeError:
        _audit("get_customer_for_driver", driver_id, customer_id, "blocked_unsafe_payload")
        raise

    _audit("get_customer_for_driver", driver_id, customer_id, "access_granted")
    return payload