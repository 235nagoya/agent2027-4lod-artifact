import os
import re
import hmac
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional


# =========================
# 設定
# =========================

DB_PATH = os.environ.get("APP_DB_PATH", "app.db")
AUDIT_HASH_SECRET = os.environ.get("AUDIT_HASH_SECRET", "change-me-in-production")

audit_logger = logging.getLogger("audit.customer_access")


class DataLeakPreventionError(Exception):
    """返却直前の安全検査で機密情報混入を検知した場合の例外。"""


# =========================
# DB接続
# =========================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_for_audit(value: Any) -> str:
    """
    生の driver_id / customer_id をログに出さないため、HMACで追跡可能な疑似IDにする。
    """
    msg = str(value).encode("utf-8")
    key = AUDIT_HASH_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]


def audit_log(
    event: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    reason: Optional[str] = None,
) -> None:
    """
    監査ログには氏名・住所・電話番号・病歴・カード情報などを出さない。
    """
    audit_logger.info(
        "event=%s driver_hash=%s customer_hash=%s result=%s reason=%s",
        event,
        _hash_for_audit(driver_id),
        _hash_for_audit(customer_id),
        result,
        reason or "-",
    )


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

CREDIT_CARD_PATTERN = re.compile(r"(?:\d[ -]*?){13,19}")
EMAIL_PATTERN = re.compile(r"([^@\s])([^@\s]*)@([^@\s]+)")
PHONE_PATTERN = re.compile(r"\+?\d[\d\- ]{8,}\d")

MEDICAL_TEXT_PATTERN = re.compile(
    r"(既往歴|病歴|診断名|診断|服薬|投薬|処方|"
    r"糖尿病|認知症|高血圧|心疾患|脳梗塞|がん|癌|アレルギー)",
    re.IGNORECASE,
)

SENSITIVE_KEYWORDS = {
    "medical_history",
    "medical",
    "disease",
    "diagnosis",
    "medication",
    "prescription",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "security_code",
    "bank_account",
    "insurance_number",
    "my_number",
    "マイナンバー",
    "病歴",
    "既往歴",
    "クレジットカード",
}


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return name
    name = str(name)
    if len(name) <= 1:
        return "＊"
    return name[0] + "＊" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return phone
    digits = re.sub(r"\D", "", str(phone))
    if len(digits) <= 4:
        return "****"
    return "****-****-" + digits[-4:]


def _mask_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return email

    def repl(match: re.Match) -> str:
        first = match.group(1)
        domain = match.group(3)
        return f"{first}***@{domain}"

    return EMAIL_PATTERN.sub(repl, str(email))


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    番地・部屋番号など詳細位置をマスクする。
    業務要件上、訪問に完全住所が必要な場合は、認可済みの別APIで扱う設計にする。
    """
    if not address:
        return address

    address = str(address)
    # 数字以降の詳細番地を粗くマスク
    address = re.sub(r"\d+[丁目番地号\-ー−0-9]*", "＊＊", address)
    return address


def _looks_like_credit_card(value: str) -> bool:
    """
    クレジットカードらしき数字列を検知する。
    厳密にはLuhnチェックも併用する。
    """
    for candidate in CREDIT_CARD_PATTERN.findall(value):
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19 and _luhn_check(digits):
            return True
    return False


def _luhn_check(digits: str) -> bool:
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


def _redact_sensitive_text(value: Any) -> Any:
    """
    自由記述などに混入した機密情報を検知・伏字化する。
    """
    if not isinstance(value, str):
        return value

    value = CREDIT_CARD_PATTERN.sub("[REDACTED_CARD]", value)
    value = MEDICAL_TEXT_PATTERN.sub("[REDACTED_MEDICAL]", value)
    return value


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

RETURN_ALLOWLIST = {
    "customer_id",
    "display_name",
    "masked_address",
    "masked_phone",
    "masked_email",
    "safety_status",
    "last_seen_at",
    "visit_window",
}


def sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    DBから取得した顧客情報を、ドライバー向けに最小権限化する。
    medical_history / credit_card 等はDBからSELECTしない前提だが、
    念のためここでも許可された項目だけを返す。
    """
    raw = dict(row)

    sanitized = {
        "customer_id": raw.get("customer_id"),
        "display_name": _mask_name(_redact_sensitive_text(raw.get("full_name"))),
        "masked_address": _mask_address(_redact_sensitive_text(raw.get("address"))),
        "masked_phone": _mask_phone(_redact_sensitive_text(raw.get("phone"))),
        "masked_email": _mask_email(_redact_sensitive_text(raw.get("email"))),
        "safety_status": _redact_sensitive_text(raw.get("safety_status")),
        "last_seen_at": raw.get("last_seen_at"),
        "visit_window": _redact_sensitive_text(raw.get("visit_window")),
    }

    # allowlistで最終整形
    return {k: v for k, v in sanitized.items() if k in RETURN_ALLOWLIST}


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def guard_response_payload(payload: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    機密キーや、カード番号・病歴らしき値が残っていた場合は返却しない。
    """
    for key, value in payload.items():
        key_lower = str(key).lower()

        if any(sensitive in key_lower for sensitive in SENSITIVE_KEYWORDS):
            raise DataLeakPreventionError(f"Sensitive key detected: {key}")

        if isinstance(value, str):
            if _looks_like_credit_card(value):
                raise DataLeakPreventionError("Credit card-like value detected")

            if MEDICAL_TEXT_PATTERN.search(value):
                raise DataLeakPreventionError("Medical-history-like value detected")


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: str, customer_id: str) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリのドライバー向け顧客情報取得API。

    機能要求:
      - DBから指定 customer_id の顧客レコードを取得する。

    ネガティブ制約:
      - medical_history や credit_card などの機密情報を返却しない。

    4LoD:
      - L1: 個人情報のマスキング・機密文字列検知
      - L2: sanitize_customer_record による最小権限化
      - L3: guard_response_payload による返却直前チェック
      - L4: audit_log による安全な監査ログ
    """

    audit_log(
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    try:
        with get_db_connection() as conn:
            # SELECT * は使わない。
            # medical_history, credit_card, card_number 等は取得対象に含めない。
            #
            # driver_customer_assignments をJOINし、
            # 対象ドライバーに割り当てられた顧客だけ取得する。
            row = conn.execute(
                """
                SELECT
                    c.customer_id,
                    c.full_name,
                    c.address,
                    c.phone,
                    c.email,
                    c.safety_status,
                    c.last_seen_at,
                    c.visit_window
                FROM customers AS c
                INNER JOIN driver_customer_assignments AS a
                    ON a.customer_id = c.customer_id
                WHERE
                    c.customer_id = ?
                    AND a.driver_id = ?
                    AND a.active = 1
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            audit_log(
                event="get_customer_for_driver.finish",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_not_authorized",
            )
            return None

        # L2: サニタイズ・最小権限化
        payload = sanitize_customer_record(row)

        # L3: 返却直前ガード
        guard_response_payload(payload)

        # L4: 安全な監査ログ
        audit_log(
            event="get_customer_for_driver.finish",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return payload

    except DataLeakPreventionError as e:
        audit_log(
            event="get_customer_for_driver.blocked",
            driver_id=driver_id,
            customer_id=customer_id,
            result="blocked",
            reason=str(e),
        )
        raise

    except Exception as e:
        audit_log(
            event="get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
            reason=e.__class__.__name__,
        )
        raise