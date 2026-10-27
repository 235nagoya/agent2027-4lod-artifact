import hmac
import hashlib
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4


logger = logging.getLogger(__name__)

# ============================================================
# 共通定義
# ============================================================

AUDIT_SALT = os.environ.get("AUDIT_SALT", "change-me-in-production").encode()

# 返却してよいフィールドのみ定義
ALLOWED_OUTPUT_KEYS = {
    "customer_id",
    "display_name",
    "phone",
    "address_area",
    "visit_window",
    "last_checkin_at",
    "status",
    "emergency_contact_name",
    "emergency_contact_phone",
    "driver_note",
}

# DB上・返却データ上で絶対に出してはいけないキー
SENSITIVE_KEYS = {
    "medical_history",
    "medical_records",
    "diagnosis",
    "medication",
    "allergy",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "cvc",
    "insurance_number",
    "my_number",
    "ssn",
}

# クレジットカードらしき連続数字
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# 医療情報が自由記述欄に混入した場合の簡易検知
MEDICAL_KEYWORDS_PATTERN = re.compile(
    r"(病歴|既往歴|診断|糖尿病|認知症|高血圧|心疾患|服薬|薬|アレルギー|手術歴)"
)


class SensitiveDataLeakError(Exception):
    """返却直前に機密情報混入を検知した場合の例外。"""


# ============================================================
# L4: 制度的正統性 — 安全なログ記録と追跡
# ============================================================

def _hash_id(value: Any) -> str:
    """
    監査ログ用にIDをHMACで匿名化する。
    生の driver_id / customer_id はログに出さない。
    """
    msg = str(value).encode()
    return hmac.new(AUDIT_SALT, msg, hashlib.sha256).hexdigest()[:16]


def audit_log(
    event: str,
    *,
    driver_id: Any,
    customer_id: Any,
    trace_id: str,
    level: str = "INFO",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    PIIや機密情報を含まない安全な監査ログ。
    """
    payload = {
        "event": event,
        "driver_hash": _hash_id(driver_id),
        "customer_hash": _hash_id(customer_id),
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "extra": extra or {},
    }

    if level == "WARNING":
        logger.warning("audit=%s", payload)
    elif level == "ERROR":
        logger.error("audit=%s", payload)
    else:
        logger.info("audit=%s", payload)


def notify_human_review(
    *,
    driver_id: Any,
    customer_id: Any,
    trace_id: str,
    reason: str,
) -> None:
    """
    L3: 人間介入用の通知。
    実運用ではチケット発行、Slack通知、SOC連携などに置き換える。
    生PIIは含めない。
    """
    audit_log(
        "human_review_required",
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
        level="WARNING",
        extra={"reason": reason},
    )


# ============================================================
# L1: 業務運用 — データ内の個人情報をマスキング・検知
# ============================================================

def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = str(name).strip()
    if len(name) <= 1:
        return "＊"

    return name[0] + "＊" * (len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    電話番号は下4桁のみ残す。
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) <= 4:
        return "＊" * len(digits)

    return "＊" * (len(digits) - 4) + digits[-4:]


def mask_address_area(address: Optional[str]) -> Optional[str]:
    """
    住所は詳細番地を返さず、地域レベルに丸める簡易実装。
    例:
      東京都新宿区西新宿2-8-1 -> 東京都新宿区
    """
    if not address:
        return None

    address = str(address).strip()

    # 市区町村まで残す簡易パターン
    match = re.search(r"(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1)

    # パターンに合わない場合は先頭だけに制限
    return address[:8] + "..." if len(address) > 8 else address


def redact_sensitive_text(text: Optional[str]) -> Optional[str]:
    """
    自由記述欄にクレカ番号や医療情報が混入していた場合に検知・伏せ字化する。
    """
    if not text:
        return None

    value = str(text)

    value = CREDIT_CARD_PATTERN.sub("[REDACTED_CREDIT_CARD]", value)
    value = MEDICAL_KEYWORDS_PATTERN.sub("[REDACTED_MEDICAL]", value)

    return value


# ============================================================
# L2: AI監査 — サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    DBレコードから返却可能な最小限の情報だけを生成する。

    重要:
    - medical_history, credit_card などはここで扱わない。
    - SELECT句でも取得しない。
    - 自由記述欄は必ずredactする。
    """
    raw = dict(row)

    sanitized = {
        "customer_id": raw.get("customer_id"),
        "display_name": mask_name(raw.get("full_name")),
        "phone": mask_phone(raw.get("phone")),
        "address_area": mask_address_area(raw.get("address")),
        "visit_window": raw.get("visit_window"),
        "last_checkin_at": raw.get("last_checkin_at"),
        "status": raw.get("status"),
        "emergency_contact_name": mask_name(raw.get("emergency_contact_name")),
        "emergency_contact_phone": mask_phone(raw.get("emergency_contact_phone")),
        "driver_note": redact_sensitive_text(raw.get("driver_note")),
    }

    # 許可リスト外のキーを返さない
    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_OUTPUT_KEYS
    }


# ============================================================
# L3: 人間介入 — 返却直前でのガード節によるチェック
# ============================================================

def guard_no_sensitive_data(
    data: Dict[str, Any],
    *,
    driver_id: Any,
    customer_id: Any,
    trace_id: str,
) -> None:
    """
    返却直前の最終防衛線。
    機密キーやクレカ番号、医療情報らしき文字列を検知したら返却を止める。
    """
    keys = set(data.keys())

    # 禁止キーが混入していたら即ブロック
    leaked_keys = keys.intersection(SENSITIVE_KEYS)
    if leaked_keys:
        reason = f"sensitive_keys_detected:{sorted(leaked_keys)}"
        notify_human_review(
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            reason=reason,
        )
        raise SensitiveDataLeakError(reason)

    # 許可リスト外のキーがある場合もブロック
    unexpected_keys = keys - ALLOWED_OUTPUT_KEYS
    if unexpected_keys:
        reason = f"unexpected_keys_detected:{sorted(unexpected_keys)}"
        notify_human_review(
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            reason=reason,
        )
        raise SensitiveDataLeakError(reason)

    # 値の中に機密情報が混入していないか確認
    for key, value in data.items():
        if value is None:
            continue

        text = str(value)

        if CREDIT_CARD_PATTERN.search(text):
            reason = f"credit_card_pattern_detected_in:{key}"
            notify_human_review(
                driver_id=driver_id,
                customer_id=customer_id,
                trace_id=trace_id,
                reason=reason,
            )
            raise SensitiveDataLeakError(reason)

        if MEDICAL_KEYWORDS_PATTERN.search(text):
            reason = f"medical_keyword_detected_in:{key}"
            notify_human_review(
                driver_id=driver_id,
                customer_id=customer_id,
                trace_id=trace_id,
                reason=reason,
            )
            raise SensitiveDataLeakError(reason)


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(
    db: sqlite3.Connection,
    driver_id: int,
    customer_id: int,
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリのドライバー向け顧客情報取得API。

    - 指定された customer_id の顧客レコードをDBから取得する。
    - driver_id に割り当てられている顧客のみ取得可能。
    - medical_history / credit_card などの機密情報はSELECTしない。
    - 返却前にサニタイズとガードチェックを行う。
    """

    trace_id = str(uuid4())

    audit_log(
        "get_customer_for_driver_requested",
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
    )

    db.row_factory = sqlite3.Row

    # ------------------------------------------------------------
    # DB取得
    # ------------------------------------------------------------
    # medical_history, credit_card などは意図的にSELECTしない。
    # driver_customer_assignments で driver_id と customer_id の対応を確認し、
    # 最小権限で取得する。
    query = """
        SELECT
            c.customer_id,
            c.full_name,
            c.phone,
            c.address,
            c.visit_window,
            c.last_checkin_at,
            c.status,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.driver_note
        FROM customers AS c
        INNER JOIN driver_customer_assignments AS a
            ON a.customer_id = c.customer_id
        WHERE
            c.customer_id = ?
            AND a.driver_id = ?
            AND a.active = 1
            AND c.deleted_at IS NULL
        LIMIT 1
    """

    row = db.execute(query, (customer_id, driver_id)).fetchone()

    if row is None:
        audit_log(
            "get_customer_for_driver_not_found_or_forbidden",
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            level="WARNING",
        )
        return None

    # L2: 最小権限化・サニタイズ
    sanitized = sanitize_customer_record(row)

    # L3: 返却直前の最終チェック
    guard_no_sensitive_data(
        sanitized,
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
    )

    # L4: 安全ログ
    audit_log(
        "get_customer_for_driver_succeeded",
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
        extra={"returned_fields": sorted(sanitized.keys())},
    )

    return sanitized