import os
import re
import hmac
import json
import hashlib
import logging
import sqlite3
from datetime import date, datetime
from typing import Any, Dict, Optional


logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)

# 本番では環境変数やSecret Managerから取得する
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "change-me-in-production")


# ============================================================
# DB接続
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    """
    実環境ではコネクションプール等に置き換えてください。
    """
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

def _hash_for_audit(value: Any) -> str:
    """
    監査ログ用の不可逆ハッシュ。
    driver_id / customer_id をそのままログに出さない。
    """
    return hmac.new(
        AUDIT_SECRET.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def _audit_log(
    *,
    action: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    returned_keys: Optional[list[str]] = None,
    reason: Optional[str] = None,
) -> None:
    """
    個人情報・医療情報・カード情報をログに出さない安全な監査ログ。
    """
    record = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "action": action,
        "driver_hash": _hash_for_audit(driver_id),
        "customer_hash": _hash_for_audit(customer_id),
        "outcome": outcome,
        "returned_keys": returned_keys or [],
        "reason": reason,
    }

    logger.info(json.dumps(record, ensure_ascii=False))


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PHONE_PATTERN = re.compile(r"(\+?\d[\d\-\s]{8,}\d)")
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CREDIT_CARD_LIKE_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)

    if len(digits) < 4:
        return "***"

    return "***-****-" + digits[-4:]


def _mask_name(name: Optional[str]) -> Optional[str]:
    """
    ドライバー側にフルネームが不要な想定で最小化。
    業務上フルネームが必要な場合は、権限に応じて別途制御してください。
    """
    if not name:
        return None

    return name[0] + "＊＊"


def _calculate_age_band(birth_date: Optional[str]) -> Optional[str]:
    """
    生年月日そのものは返さず、年代に丸める。
    birth_date は 'YYYY-MM-DD' 形式を想定。
    """
    if not birth_date:
        return None

    try:
        born = datetime.strptime(birth_date, "%Y-%m-%d").date()
    except ValueError:
        return None

    today = date.today()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    decade = age // 10 * 10

    return f"{decade}代"


def _contains_raw_pii_or_sensitive_value(value: Any) -> bool:
    """
    L1用の簡易検知。
    ここでは生メール、生電話番号、カード番号らしき値を検知する。
    """
    if value is None:
        return False

    text = str(value)

    if EMAIL_PATTERN.search(text):
        return True

    if PHONE_PATTERN.search(text):
        return True

    if CREDIT_CARD_LIKE_PATTERN.search(text):
        return True

    return False


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

SENSITIVE_FIELD_NAMES = {
    "medical_history",
    "medicalHistory",
    "diagnosis",
    "medication",
    "allergy",
    "insurance_number",
    "credit_card",
    "creditCard",
    "card_number",
    "cardNumber",
    "cvv",
    "cvc",
    "ssn",
    "my_number",
    "mynumber",
    "bank_account",
}

# ドライバーに返してよいフィールドだけを明示する
ALLOWED_RESPONSE_FIELDS = {
    "customer_id",
    "display_name",
    "age_band",
    "visit_address",
    "phone_masked",
    "emergency_contact_name",
    "emergency_contact_phone_masked",
    "last_checkin_at",
}


def _sanitize_customer_for_driver(row: sqlite3.Row) -> Dict[str, Any]:
    """
    DBから取得した顧客情報を、ドライバーに必要な最小限の情報へ変換する。

    medical_history / credit_card などは、そもそもSELECTしない。
    さらにここでも許可リスト方式で返却項目を制限する。
    """

    candidate = {
        "customer_id": row["customer_id"],
        "display_name": _mask_name(row["full_name"]),
        "age_band": _calculate_age_band(row["birth_date"]),
        # 訪問業務に必要なため住所は返す想定。
        # 不要な運用なら丁目以降をマスクする等に変更してください。
        "visit_address": row["address"],
        "phone_masked": _mask_phone(row["phone"]),
        "emergency_contact_name": _mask_name(row["emergency_contact_name"]),
        "emergency_contact_phone_masked": _mask_phone(row["emergency_contact_phone"]),
        "last_checkin_at": row["last_checkin_at"],
    }

    # 許可リスト方式で最終整形
    sanitized = {
        key: value
        for key, value in candidate.items()
        if key in ALLOWED_RESPONSE_FIELDS
    }

    return sanitized


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def _guard_response_payload(payload: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    問題があれば例外を投げ、APIレスポンスを止める。
    """

    keys = set(payload.keys())

    # 禁止フィールド名が混入していないか
    forbidden_keys = keys & SENSITIVE_FIELD_NAMES
    if forbidden_keys:
        raise ValueError(f"Forbidden sensitive fields detected: {sorted(forbidden_keys)}")

    # 許可されていないフィールドが混入していないか
    unexpected_keys = keys - ALLOWED_RESPONSE_FIELDS
    if unexpected_keys:
        raise ValueError(f"Unexpected fields detected: {sorted(unexpected_keys)}")

    # 値にカード番号・生電話番号・メール等が混入していないか
    # phoneは必ず mask 済みの phone_masked として返す想定。
    for key, value in payload.items():
        if key in {"visit_address"}:
            # 住所は業務上必要なPIIとして許可。
            # ログには絶対に出さない。
            continue

        if _contains_raw_pii_or_sensitive_value(value):
            raise ValueError(f"Raw PII or sensitive value detected in field: {key}")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    指定された customer_id の顧客情報をDBから取得し、
    driver_id に割り当てられている場合のみ返却する。

    medical_history や credit_card などの機密情報は返却しない。
    """

    action = "get_customer_for_driver"

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # SELECT * は使わない。
            # medical_history, credit_card 等は取得対象に含めない。
            #
            # driver_customer_assignments により、
            # ドライバーが担当する顧客のみ取得できるようにする。
            cursor.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.full_name AS full_name,
                    c.birth_date AS birth_date,
                    c.address AS address,
                    c.phone AS phone,
                    c.emergency_contact_name AS emergency_contact_name,
                    c.emergency_contact_phone AS emergency_contact_phone,
                    c.last_checkin_at AS last_checkin_at
                FROM customers c
                INNER JOIN driver_customer_assignments dca
                    ON dca.customer_id = c.id
                WHERE
                    c.id = ?
                    AND dca.driver_id = ?
                    AND dca.active = 1
                LIMIT 1
                """,
                (customer_id, driver_id),
            )

            row = cursor.fetchone()

        if row is None:
            _audit_log(
                action=action,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_not_authorized",
                reason="no active assignment",
            )
            return None

        # L2: サニタイズ
        response = _sanitize_customer_for_driver(row)

        # L3: 返却直前チェック
        _guard_response_payload(response)

        # L4: 安全な監査ログ
        _audit_log(
            action=action,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            returned_keys=list(response.keys()),
        )

        return response

    except Exception as exc:
        # 例外内容にPIIが含まれる可能性があるため、
        # raw exception message はログに出さない。
        _audit_log(
            action=action,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked_or_error",
            reason=exc.__class__.__name__,
        )
        raise