import os
import re
import hmac
import hashlib
import logging
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


# =========================
# Exceptions
# =========================

class NotFoundError(Exception):
    pass


class SecurityViolationError(Exception):
    pass


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

AUDIT_SECRET = os.getenv("AUDIT_SECRET", "change-this-secret-in-production").encode()


def pseudonymize_id(value: Any) -> str:
    """
    監査ログ用にIDを仮名化する。
    生の driver_id / customer_id をログに出さない。
    """
    msg = str(value).encode()
    return hmac.new(AUDIT_SECRET, msg, hashlib.sha256).hexdigest()[:16]


def audit_log(event: str, *, driver_id: Any, customer_id: Any, extra: Optional[Dict[str, Any]] = None) -> None:
    """
    PIIや機密情報を含めずに監査ログを記録する。
    """
    payload = {
        "event": event,
        "driver_ref": pseudonymize_id(driver_id),
        "customer_ref": pseudonymize_id(customer_id),
    }

    if extra:
        payload.update(extra)

    logger.info("audit_event=%s", payload)


# =========================
# L1: 業務運用
# データ内の個人情報・機密情報をマスキング・検知
# =========================

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"medical", re.IGNORECASE),
    re.compile(r"history", re.IGNORECASE),
    re.compile(r"credit", re.IGNORECASE),
    re.compile(r"card", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"ssn", re.IGNORECASE),
    re.compile(r"diagnosis", re.IGNORECASE),
    re.compile(r"prescription", re.IGNORECASE),
]


EXPLICIT_SENSITIVE_KEYS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "password",
    "access_token",
    "refresh_token",
    "diagnosis",
    "prescription",
}


def detect_sensitive_keys(record: Dict[str, Any]) -> list[str]:
    """
    レコード内に機密情報と思われるキーが含まれていないか検知する。
    """
    detected = []

    for key in record.keys():
        normalized_key = str(key).lower()

        if normalized_key in EXPLICIT_SENSITIVE_KEYS:
            detected.append(key)
            continue

        if any(pattern.search(normalized_key) for pattern in SENSITIVE_KEY_PATTERNS):
            detected.append(key)

    return detected


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return name

    name = str(name).strip()

    if len(name) <= 1:
        return "*"

    if len(name) == 2:
        return name[0] + "*"

    return name[0] + "*" * (len(name) - 2) + name[-1]


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return phone

    digits = re.sub(r"\D", "", str(phone))

    if len(digits) < 4:
        return "****"

    return "***-****-" + digits[-4:]


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    詳細住所は返さず、市区町村程度までに抑える想定。
    実運用では住所正規化ライブラリや住所DBで処理するのが望ましい。
    """
    if not address:
        return address

    address = str(address)

    # 例: "東京都新宿区西新宿1-2-3" -> "東京都新宿区付近"
    match = re.match(r"(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "付近"

    return "住所詳細は非表示"


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

RETURN_ALLOWLIST = {
    "customer_id",
    "display_name",
    "phone",
    "address_area",
    "safety_status",
    "last_confirmed_at",
}


def sanitize_customer_for_driver(raw_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー向けに返してよい最小限の情報だけを返却する。

    medical_history / credit_card などは、
    DBから取得しない・allowlistに入れない・返却前に検査する。
    """
    sanitized = {
        "customer_id": raw_record.get("customer_id"),
        "display_name": mask_name(raw_record.get("full_name")),
        "phone": mask_phone(raw_record.get("phone")),
        "address_area": mask_address(raw_record.get("address")),
        "safety_status": raw_record.get("safety_status"),
        "last_confirmed_at": raw_record.get("last_confirmed_at"),
    }

    # allowlist外の項目を除去
    return {k: v for k, v in sanitized.items() if k in RETURN_ALLOWLIST}


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def guard_response_is_safe(response: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    機密情報らしきキーが含まれていれば返却を停止する。
    """
    detected = detect_sensitive_keys(response)

    if detected:
        raise SecurityViolationError(
            f"Unsafe response blocked. Sensitive keys detected: {detected}"
        )

    unexpected_keys = set(response.keys()) - RETURN_ALLOWLIST
    if unexpected_keys:
        raise SecurityViolationError(
            f"Unsafe response blocked. Unexpected keys detected: {sorted(unexpected_keys)}"
        )


# =========================
# Main API
# =========================

def get_customer_for_driver(driver_id: int, customer_id: int, db_conn) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Args:
        driver_id:
            顧客を担当するドライバーID。
        customer_id:
            取得対象の顧客ID。
        db_conn:
            DB-API互換のコネクション。
            例: sqlite3, psycopg2等。

    Returns:
        ドライバー向けにサニタイズされた顧客情報。

    Raises:
        NotFoundError:
            対象顧客が存在しない、またはそのドライバーに紐づいていない場合。
        SecurityViolationError:
            返却データに機密情報が混入しそうな場合。
    """

    audit_log(
        "customer_fetch_requested",
        driver_id=driver_id,
        customer_id=customer_id,
    )

    # DBから必要な列だけ取得する。
    # medical_history, credit_card 等は SELECT しない。
    #
    # driver_id で絞ることで、担当外顧客の情報取得を防ぐ。
    sql = """
        SELECT
            customer_id,
            full_name,
            phone,
            address,
            safety_status,
            last_confirmed_at
        FROM customers
        WHERE customer_id = ?
          AND assigned_driver_id = ?
        LIMIT 1
    """

    cursor = db_conn.cursor()
    cursor.execute(sql, (customer_id, driver_id))
    row = cursor.fetchone()

    if row is None:
        audit_log(
            "customer_fetch_not_found_or_forbidden",
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise NotFoundError("Customer not found or access denied.")

    columns = [desc[0] for desc in cursor.description]
    raw_record = dict(zip(columns, row))

    # L1: 取得直後に機密キー混入を検知
    detected_sensitive_keys = detect_sensitive_keys(raw_record)
    if detected_sensitive_keys:
        audit_log(
            "customer_fetch_blocked_sensitive_raw_record",
            driver_id=driver_id,
            customer_id=customer_id,
            extra={
                "detected_keys": detected_sensitive_keys,
            },
        )
        raise SecurityViolationError("Sensitive data detected in raw DB record.")

    # L2: サニタイズして最小限の情報だけにする
    response = sanitize_customer_for_driver(raw_record)

    # L3: 返却直前のガード節
    guard_response_is_safe(response)

    # L4: 安全な監査ログ
    audit_log(
        "customer_fetch_succeeded",
        driver_id=driver_id,
        customer_id=customer_id,
        extra={
            "returned_fields": sorted(response.keys()),
        },
    )

    return response