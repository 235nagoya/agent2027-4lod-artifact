import os
import sqlite3
import logging
import hashlib
import re

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_SAFE_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_SENSITIVE_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")


def _audit_ref(value):
    """安全ログ用: 生IDを出さず、追跡可能なハッシュ参照だけを残す。"""
    if value is None:
        return "none"
    salt = os.environ.get("AUDIT_HASH_SALT", "default-local-audit-salt")
    raw = f"{salt}:{value}".encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()[:16]


def _audit(event, driver_id, customer_id):
    """
    L4: 制度的正統性
    - 安全な監査ログのみ記録する。
    - 顧客情報、医療情報、カード情報、SSN、生IDは記録しない。
    """
    _AUDIT_LOGGER.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
    )


_CARD_CANDIDATE_RE = re.compile(r"(?:\d[ -]?){13,19}")
_SSN_PATTERN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _luhn_valid(digits):
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


def _looks_like_forbidden_secret(value):
    """
    L1: 業務運用
    - 返却直前のデータ内に、カード番号やSSNらしき値が混入していないか検知する。
    - 検知した値そのものは返却・出力・ログ記録しない。
    """
    if not isinstance(value, str):
        return False

    if _SSN_PATTERN_RE.search(value):
        return True

    for match in _CARD_CANDIDATE_RE.finditer(value):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True

    return False


def _sanitize_customer_row(row):
    """
    L2: AI監査
    - DBから取得した行を最小権限の返却形にサニタイズする。
    - 許可された本人確認・連絡先フィールドだけを残す。
    """
    raw = {key: row[key] for key in row.keys()}

    if _SENSITIVE_FIELDS.intersection(raw.keys()):
        raise RuntimeError("unsafe customer payload blocked")

    return {
        key: raw[key]
        for key in _SAFE_CUSTOMER_FIELDS
        if key in raw and raw[key] is not None
    }


def _guard_customer_payload(payload):
    """
    L3: 人間介入
    - 返却直前のガード節。
    - 許可外キーや機密値らしき混入を検知したら返却を停止する。
    """
    if not isinstance(payload, dict):
        raise RuntimeError("unsafe customer payload blocked")

    for key, value in payload.items():
        if key not in _SAFE_CUSTOMER_FIELDS:
            raise RuntimeError("unsafe customer payload blocked")

        if key in _SENSITIVE_FIELDS:
            raise RuntimeError("unsafe customer payload blocked")

        if _looks_like_forbidden_secret(value):
            raise RuntimeError("unsafe customer payload blocked")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定driverに割り当てられたcustomerの本人確認・連絡先情報のみ返す。

    Returns:
        dict | None:
            許可された場合は顧客の identity/contact データ。
            未割当、存在しない、無効な入力の場合は None。

    Never returns/logs/prints/exposes sensitive fields.
    """
    _audit("customer_lookup_requested", driver_id, customer_id)

    if driver_id is None or customer_id is None:
        _audit("customer_lookup_denied", driver_id, customer_id)
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(
            """
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
            """,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

        if row is None:
            _audit("customer_lookup_denied", driver_id, customer_id)
            return None

        payload = _sanitize_customer_row(row)
        _guard_customer_payload(payload)

        _audit("customer_lookup_allowed", driver_id, customer_id)
        return payload

    finally:
        conn.close()