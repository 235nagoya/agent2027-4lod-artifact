import os
import re
import hmac
import hashlib
import logging
from datetime import date, datetime
from typing import Any, Mapping

from sqlalchemy import create_engine, text


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)

DATABASE_URL = os.environ["DATABASE_URL"]
AUDIT_HASH_SECRET = os.environ.get("AUDIT_HASH_SECRET", "change-me-in-production")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


class SecurityError(Exception):
    """返却直前の安全検査で機密情報混入を検知した場合に送出する例外。"""


def _hash_for_audit(value: Any) -> str:
    """
    監査ログ用の不可逆ハッシュ。
    driver_id/customer_id を平文でログに残さない。
    """
    msg = str(value).encode("utf-8")
    key = AUDIT_HASH_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def audit_log(
    *,
    action: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: str | None = None,
) -> None:
    """
    安全な監査ログ。
    個人情報・医療情報・カード情報・住所・電話番号などは記録しない。
    """
    logger.info(
        "customer_access_audit",
        extra={
            "action": action,
            "driver_hash": _hash_for_audit(driver_id),
            "customer_hash": _hash_for_audit(customer_id),
            "outcome": outcome,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        },
    )


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

def mask_phone(phone: str | None) -> str | None:
    """
    電話番号をマスキングする。
    例: 090-1234-5678 -> ***-****-5678
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "***"

    return "***-****-" + digits[-4:]


def to_age_band(birth_date: date | datetime | None) -> str | None:
    """
    生年月日は返さず、年代に丸める。
    例: 82歳 -> 80代
    """
    if not birth_date:
        return None

    if isinstance(birth_date, datetime):
        birth_date = birth_date.date()

    today = date.today()
    age = today.year - birth_date.year - (
        (today.month, today.day) < (birth_date.month, birth_date.day)
    )

    decade = age // 10 * 10
    return f"{decade}代"


def looks_like_credit_card(value: str) -> bool:
    """
    文字列内にクレジットカード番号らしき13〜19桁の数字列が含まれるか簡易検知する。
    """
    candidates = re.findall(r"(?:\d[ -]?){13,19}", value)

    for candidate in candidates:
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19 and _luhn_check(digits):
            return True

    return False


def _luhn_check(number: str) -> bool:
    """
    クレジットカード番号検知用の Luhn チェック。
    """
    total = 0
    reverse_digits = number[::-1]

    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

SENSITIVE_KEYS = {
    "medical_history",
    "medicalhistory",
    "diagnosis",
    "disease",
    "medication",
    "medicine",
    "allergy",
    "allergies",
    "doctor_note",
    "nursing_note",
    "care_record",
    "credit_card",
    "creditcard",
    "card_number",
    "cardnumber",
    "cvv",
    "cvc",
    "security_code",
    "bank_account",
    "my_number",
    "mynumber",
    "social_security_number",
    "ssn",
}

RETURN_ALLOWLIST = {
    "customer_id",
    "display_name",
    "age_band",
    "masked_phone",
    "visit_address",
    "last_seen_at",
    "checkin_status",
}


def sanitize_customer_for_driver(row: Mapping[str, Any]) -> dict[str, Any]:
    """
    ドライバーに必要な最小限の顧客情報だけを返す。

    注意:
    - medical_history, credit_card などはそもそも SELECT しない。
    - 念のためここでも allowlist 方式で返却項目を限定する。
    - 電話番号や生年月日はマスキング・丸め処理をする。
    """

    sanitized = {
        "customer_id": row.get("customer_id"),
        "display_name": row.get("full_name"),
        "age_band": to_age_band(row.get("birth_date")),
        "masked_phone": mask_phone(row.get("phone")),
        "visit_address": row.get("visit_address"),
        "last_seen_at": (
            row.get("last_seen_at").isoformat()
            if row.get("last_seen_at") is not None
            else None
        ),
        "checkin_status": row.get("checkin_status"),
    }

    # allowlist に存在するキーだけ返す
    sanitized = {
        key: value
        for key, value in sanitized.items()
        if key in RETURN_ALLOWLIST
    }

    return sanitized


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def assert_safe_to_return(payload: Mapping[str, Any]) -> None:
    """
    返却直前の最終防衛線。

    - 禁止キーが含まれていないか
    - クレジットカード番号らしき値が混入していないか
    - allowlist 外の項目が含まれていないか

    問題があれば SecurityError を出し、返却をブロックする。
    実運用ではこの例外を拾って、管理者レビューやセキュリティ通知に回す。
    """
    for key, value in payload.items():
        normalized_key = key.lower().replace("_", "")

        if key not in RETURN_ALLOWLIST:
            raise SecurityError(f"返却許可されていないキーを検知しました: {key}")

        if normalized_key in SENSITIVE_KEYS:
            raise SecurityError(f"機密キーを検知しました: {key}")

        if isinstance(value, str) and looks_like_credit_card(value):
            raise SecurityError("クレジットカード番号らしき値を検知しました")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> dict[str, Any] | None:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    指定された customer_id の顧客レコードをDBから取得し、
    ドライバーに必要な最小限の情報だけを返す。

    機密情報:
    - medical_history
    - credit_card
    - diagnosis
    - medication
    - cvv
    などは返却しない。
    """

    if not isinstance(driver_id, int) or not isinstance(customer_id, int):
        audit_log(
            action="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="rejected",
            reason="invalid_id_type",
        )
        raise ValueError("driver_id and customer_id must be integers")

    try:
        with engine.begin() as conn:
            # ------------------------------------------------------------
            # L1/L2:
            # DB取得時点で必要最小限のカラムだけ SELECT する。
            # medical_history, credit_card などの機密カラムは取得しない。
            #
            # driver_customer_assignments により、
            # 担当ドライバーに割り当てられた顧客だけ取得可能にしている。
            # ------------------------------------------------------------
            result = conn.execute(
                text(
                    """
                    SELECT
                        c.id AS customer_id,
                        c.full_name AS full_name,
                        c.birth_date AS birth_date,
                        c.phone AS phone,
                        c.address AS visit_address,
                        c.last_seen_at AS last_seen_at,
                        c.checkin_status AS checkin_status
                    FROM customers c
                    INNER JOIN driver_customer_assignments a
                        ON a.customer_id = c.id
                    WHERE
                        c.id = :customer_id
                        AND a.driver_id = :driver_id
                        AND a.active = TRUE
                    LIMIT 1
                    """
                ),
                {
                    "driver_id": driver_id,
                    "customer_id": customer_id,
                },
            ).mappings().first()

        if result is None:
            audit_log(
                action="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_unauthorized",
            )
            return None

        # L2: サニタイズ関数による最小権限化
        payload = sanitize_customer_for_driver(result)

        # L3: 返却直前のガード節
        assert_safe_to_return(payload)

        # L4: 安全な監査ログ
        audit_log(
            action="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
        )

        return payload

    except SecurityError as e:
        # L3/L4:
        # 機密情報混入を検知した場合は返却せず、
        # セキュリティレビュー対象として追跡可能にする。
        audit_log(
            action="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked_for_human_review",
            reason=str(e),
        )
        raise

    except Exception as e:
        audit_log(
            action="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
            reason=type(e).__name__,
        )
        raise