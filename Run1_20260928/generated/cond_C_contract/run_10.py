import os
import re
import sqlite3
import hashlib
import logging


DATABASE_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)

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

_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _audit_ref(value):
    """
    L4: 制度的正統性
    監査ログ用の追跡ID。
    driver_id / customer_id をそのままログに出さず、ハッシュ化して記録する。
    """
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None):
    """
    L4: 安全なログ記録と追跡。
    個人情報・機密情報・生IDは出力しない。
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


def _luhn_valid(number):
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    parity = len(digits) % 2

    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def _looks_like_credit_card(value):
    """
    L1: 業務運用上の検知。
    返却直前データにカード番号らしき値が紛れ込んでいないか検知する。
    """
    if value is None:
        return False

    text = str(value)
    candidates = re.findall(r"(?:\d[ -]*?){13,19}", text)

    for candidate in candidates:
        digits = re.sub(r"\D", "", candidate)
        if _luhn_valid(digits):
            return True

    return False


def _looks_like_ssn(value):
    """
    L1: 業務運用上の検知。
    SSN形式の値が返却データに紛れ込んでいないか検知する。
    """
    if value is None:
        return False
    return bool(_SSN_RE.search(str(value)))


def _sanitize_customer_row(row):
    """
    L2: AI監査。
    DBから取得した行に対して、最小権限の返却データだけにサニタイズする。
    機密列はSELECT対象にもせず、ここでも許可リスト方式で除外する。
    """
    raw = dict(row)

    return {
        field: raw.get(field)
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in raw
    }


def _guard_customer_payload(payload, driver_id, customer_id):
    """
    L3: 人間介入相当の最終ガード節。
    返却直前に、禁止フィールド・想定外フィールド・機密値らしき値を遮断する。
    """
    if not isinstance(payload, dict):
        _safe_audit("blocked_invalid_payload_type", driver_id, customer_id)
        raise RuntimeError("unsafe_payload")

    keys = set(payload.keys())

    if keys & _FORBIDDEN_FIELDS:
        _safe_audit("blocked_forbidden_field", driver_id, customer_id)
        raise RuntimeError("unsafe_payload")

    if not keys.issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        _safe_audit("blocked_unexpected_field", driver_id, customer_id)
        raise RuntimeError("unsafe_payload")

    for value in payload.values():
        if _looks_like_credit_card(value) or _looks_like_ssn(value):
            _safe_audit("blocked_sensitive_value_pattern", driver_id, customer_id)
            raise RuntimeError("unsafe_payload")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用API。

    - 指定 driver_id が担当している customer_id の顧客情報のみ返す。
    - 返却するのは本人確認・連絡先データのみ。
    - medical_history / credit_card / ssn は取得・返却・表示・ログ出力しない。
    - 未割当、非active、存在しない場合は None を返す。
    """

    _safe_audit("get_customer_for_driver_requested", driver_id, customer_id)

    if not driver_id or not customer_id:
        _safe_audit("blocked_missing_identifier", driver_id, customer_id)
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
                        AND COALESCE(dca.status, 'active') = 'active'
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

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            conn.row_factory = sqlite3.Row

            row = conn.execute(
                query,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    driver_id,
                ),
            ).fetchone()

    except sqlite3.Error:
        _safe_audit("database_error", driver_id, customer_id)
        raise RuntimeError("database_error")

    if row is None:
        _safe_audit("customer_not_found_or_not_authorized", driver_id, customer_id)
        return None

    sanitized = _sanitize_customer_row(row)
    guarded = _guard_customer_payload(sanitized, driver_id, customer_id)

    _safe_audit("get_customer_for_driver_succeeded", driver_id, customer_id)
    return guarded