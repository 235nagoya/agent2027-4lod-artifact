import sqlite3
import logging
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

logger = logging.getLogger("customer_access_audit")
logger.setLevel(logging.INFO)

# 本番ではファイル/監査基盤/SIEM等へ送る
handler = logging.StreamHandler()
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(name)s %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


AUDIT_SALT = "replace-with-secure-env-specific-salt"


def hash_id(value: Any) -> str:
    """
    ログに生IDを出さないためのハッシュ化。
    本番ではソルトは環境変数やKMS管理値を利用する。
    """
    raw = f"{AUDIT_SALT}:{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def audit_log(event: str, driver_id: Any, customer_id: Any, result: str) -> None:
    """
    個人情報・機密情報を含めない安全な監査ログ。
    """
    logger.info(
        {
            "event": event,
            "driver_id_hash": hash_id(driver_id),
            "customer_id_hash": hash_id(customer_id),
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PHONE_PATTERN = re.compile(r"\b0\d{1,4}-?\d{1,4}-?\d{3,4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b", re.ASCII)

# あくまで例。実運用では辞書・ML・DLP製品などを併用する。
MEDICAL_KEYWORDS = [
    "病歴",
    "既往歴",
    "診断",
    "糖尿病",
    "高血圧",
    "認知症",
    "服薬",
    "薬",
    "アレルギー",
    "medical",
    "diagnosis",
    "medicine",
]


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    電話番号の部分マスキング。
    ドライバー業務上、全桁が不要な画面・用途ではマスクして返す。
    必要な場合は権限別APIに分けるのが望ましい。
    """
    if not phone:
        return phone

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    return "*" * (len(digits) - 4) + digits[-4:]


def redact_sensitive_text(text: Optional[str]) -> Optional[str]:
    """
    自由記述欄に紛れ込んだ機微情報を検知・マスキングする。
    """
    if not text:
        return text

    redacted = CREDIT_CARD_PATTERN.sub("[REDACTED_CREDIT_CARD]", text)
    redacted = PHONE_PATTERN.sub("[REDACTED_PHONE]", redacted)

    for keyword in MEDICAL_KEYWORDS:
        redacted = re.sub(
            re.escape(keyword),
            "[REDACTED_MEDICAL]",
            redacted,
            flags=re.IGNORECASE,
        )

    return redacted


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

# 返却を許可するキーのみ。
# medical_history, credit_card 等は絶対に含めない。
ALLOWED_RESPONSE_FIELDS = {
    "customer_id",
    "name",
    "address",
    "phone_masked",
    "emergency_contact_name",
    "emergency_contact_phone_masked",
    "last_checkin_at",
    "safety_status",
    "visit_note",
}

FORBIDDEN_FIELDS = {
    "medical_history",
    "medical_info",
    "diagnosis",
    "prescription",
    "medicine",
    "allergy",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "security_code",
    "bank_account",
}


def sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    DBから取得した行を、ドライバーに必要な最小項目だけに変換する。
    """
    sanitized = {
        "customer_id": row["id"],
        "name": row["name"],
        "address": row["address"],
        "phone_masked": mask_phone(row["phone"]),
        "emergency_contact_name": row["emergency_contact_name"],
        "emergency_contact_phone_masked": mask_phone(row["emergency_contact_phone"]),
        "last_checkin_at": row["last_checkin_at"],
        "safety_status": row["safety_status"],
        "visit_note": redact_sensitive_text(row["visit_note"]),
    }

    # allowlistで最終的に余計なキーを落とす
    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_RESPONSE_FIELDS
    }


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def assert_safe_response(payload: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    禁止フィールドや機密パターンが残っていれば例外にする。
    """

    keys = set(payload.keys())

    forbidden_key_hits = keys & FORBIDDEN_FIELDS
    if forbidden_key_hits:
        raise ValueError(
            f"Unsafe response: forbidden fields detected: {forbidden_key_hits}"
        )

    unexpected_keys = keys - ALLOWED_RESPONSE_FIELDS
    if unexpected_keys:
        raise ValueError(
            f"Unsafe response: unexpected fields detected: {unexpected_keys}"
        )

    serialized_values = " ".join(
        str(v) for v in payload.values() if v is not None
    )

    if CREDIT_CARD_PATTERN.search(serialized_values):
        raise ValueError("Unsafe response: possible credit card data detected")

    for keyword in MEDICAL_KEYWORDS:
        if re.search(re.escape(keyword), serialized_values, flags=re.IGNORECASE):
            raise ValueError("Unsafe response: possible medical data detected")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    conn: sqlite3.Connection,
) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリにおいて、
    指定ドライバーが担当する指定顧客の情報を取得するAPI。

    機密情報である medical_history や credit_card は返却しない。
    """

    audit_log(
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    conn.row_factory = sqlite3.Row

    try:
        # ------------------------------------------------------------
        # DB取得時点でSELECT対象を最小化する。
        # medical_history, credit_card などはSELECTしない。
        #
        # driver_customer_assignments により、
        # ドライバーが担当する顧客だけ取得可能にする。
        # ------------------------------------------------------------
        query = """
            SELECT
                c.id,
                c.name,
                c.address,
                c.phone,
                c.emergency_contact_name,
                c.emergency_contact_phone,
                c.last_checkin_at,
                c.safety_status,
                c.visit_note
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.id
            WHERE
                a.driver_id = ?
                AND c.id = ?
                AND a.active = 1
            LIMIT 1
        """

        row = conn.execute(query, (driver_id, customer_id)).fetchone()

        if row is None:
            audit_log(
                event="get_customer_for_driver.not_found_or_unauthorized",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
            )
            raise PermissionError("Customer not found or not assigned to driver")

        # L2: サニタイズ
        response = sanitize_customer_record(row)

        # L3: 返却直前ガード
        assert_safe_response(response)

        # L4: 安全な監査ログ
        audit_log(
            event="get_customer_for_driver.success",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return response

    except Exception:
        audit_log(
            event="get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
        )
        raise