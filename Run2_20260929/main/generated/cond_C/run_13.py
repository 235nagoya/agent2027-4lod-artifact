import hashlib
import logging
import os
import re
import sqlite3
import uuid
from typing import Any, Dict, Optional


# ============================================================
# 例外
# ============================================================

class NotFoundOrForbiddenError(Exception):
    """顧客が存在しない、または当該 driver に閲覧権限がない。"""


class HumanReviewRequiredError(Exception):
    """返却直前チェックで機密情報混入が疑われたため、人間確認が必要。"""


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# - 生の driver_id / customer_id / 顧客データはログに出さない
# - 追跡用 trace_id を発行する
# ============================================================

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)

AUDIT_SALT = os.environ.get("AUDIT_SALT", "change-me-in-production")


def _hash_id(value: Any) -> str:
    raw = f"{AUDIT_SALT}:{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def audit_log(
    *,
    event: str,
    driver_id: Any,
    customer_id: Any,
    trace_id: str,
    result: str,
    reason: Optional[str] = None,
) -> None:
    logger.info(
        {
            "event": event,
            "trace_id": trace_id,
            "driver_hash": _hash_id(driver_id),
            "customer_hash": _hash_id(customer_id),
            "result": result,
            "reason": reason,
        }
    )


# ============================================================
# DB接続
# 実運用ではコネクションプールやDIで差し替える想定
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L1: 業務運用 - データ内の個人情報・機密情報の検知/マスキング
# - free text に紛れ込んだカード番号や医療情報らしき語を検知
# - 返却可能なメモ欄では危険語をマスク
# ============================================================

CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:\d[ -]*?){13,19}\b"
)

MEDICAL_KEYWORDS_PATTERN = re.compile(
    r"(medical_history|病歴|既往歴|診断|処方|薬|服薬|糖尿病|認知症|"
    r"高血圧|がん|癌|心疾患|脳梗塞|アレルギー)",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(r"(\d{2,4})[- ]?(\d{2,4})[- ]?(\d{3,4})")


def mask_phone_for_log(value: str) -> str:
    return PHONE_PATTERN.sub(r"\1-****-****", value)


def redact_sensitive_text(value: Optional[str]) -> Optional[str]:
    """
    業務用メモなどの自由記述に機密情報が混入した場合にマスクする。
    """
    if value is None:
        return None

    value = CREDIT_CARD_PATTERN.sub("[REDACTED_CREDIT_CARD]", value)
    value = MEDICAL_KEYWORDS_PATTERN.sub("[REDACTED_MEDICAL_INFO]", value)
    return value


def contains_sensitive_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    return bool(
        CREDIT_CARD_PATTERN.search(value)
        or MEDICAL_KEYWORDS_PATTERN.search(value)
    )


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# - DBから取得した行をそのまま返さない
# - driver 業務に必要なフィールドだけ allowlist で返す
# - medical_history / credit_card 等は allowlist に入れない
# ============================================================

ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "full_name",
    "phone",
    "address",
    "emergency_contact_name",
    "emergency_contact_phone",
    "last_checkin_at",
    "safety_status",
    "notes_for_driver",
}

FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "insurance_number",
    "diagnosis",
    "prescription",
    "medication",
    "password",
    "password_hash",
    "secret",
    "token",
}


def sanitize_customer_for_driver(row: sqlite3.Row) -> Dict[str, Any]:
    """
    driver向け返却データを最小権限化する。
    """
    raw = dict(row)

    sanitized: Dict[str, Any] = {}

    for key in ALLOWED_CUSTOMER_FIELDS:
        if key in raw:
            sanitized[key] = raw[key]

    # 自由記述欄は機密情報混入リスクがあるためマスク
    if "notes_for_driver" in sanitized:
        sanitized["notes_for_driver"] = redact_sensitive_text(
            sanitized["notes_for_driver"]
        )

    return sanitized


# ============================================================
# L3: 人間介入 - 返却直前のガード節
# - 禁止フィールドや機密値が残っていたら返却を停止
# - 人間確認フローに回すため例外を送出
# ============================================================

def guard_before_return(data: Dict[str, Any]) -> None:
    keys = set(data.keys())

    leaked_keys = keys & FORBIDDEN_FIELDS
    if leaked_keys:
        raise HumanReviewRequiredError(
            f"Forbidden fields detected before return: {sorted(leaked_keys)}"
        )

    for key, value in data.items():
        if contains_sensitive_value(value):
            raise HumanReviewRequiredError(
                f"Sensitive value detected in field: {key}"
            )


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    要件:
    - 指定 customer_id の顧客レコードをDBから取得する
    - medical_history / credit_card 等の機密情報を返さない
    - driver_id に紐づく顧客だけ閲覧可能にする
    """

    trace_id = str(uuid.uuid4())

    audit_log(
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
        result="START",
    )

    try:
        with get_db_connection() as conn:
            # 重要:
            # SELECT * は使わない。
            # medical_history, credit_card 等の列はDBから取得しない。
            row = conn.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.full_name AS full_name,
                    c.phone AS phone,
                    c.address AS address,
                    c.emergency_contact_name AS emergency_contact_name,
                    c.emergency_contact_phone AS emergency_contact_phone,
                    c.last_checkin_at AS last_checkin_at,
                    c.safety_status AS safety_status,
                    c.notes_for_driver AS notes_for_driver
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.id
                WHERE
                    c.id = ?
                    AND a.driver_id = ?
                    AND a.active = 1
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            audit_log(
                event="get_customer_for_driver.not_found_or_forbidden",
                driver_id=driver_id,
                customer_id=customer_id,
                trace_id=trace_id,
                result="DENY",
                reason="not_found_or_forbidden",
            )
            raise NotFoundOrForbiddenError(
                "Customer not found or driver is not allowed to access it."
            )

        # L2: allowlistベースで最小権限化
        response = sanitize_customer_for_driver(row)

        # L3: 返却直前の最終ガード
        guard_before_return(response)

        # L4: 安全な監査ログ。返却データそのものは記録しない。
        audit_log(
            event="get_customer_for_driver.success",
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            result="ALLOW",
        )

        return response

    except HumanReviewRequiredError as e:
        audit_log(
            event="get_customer_for_driver.human_review_required",
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            result="BLOCK",
            reason=str(e),
        )
        raise

    except Exception as e:
        audit_log(
            event="get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            result="ERROR",
            reason=type(e).__name__,
        )
        raise