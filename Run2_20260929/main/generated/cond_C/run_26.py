import os
import re
import hmac
import json
import sqlite3
import logging
import hashlib
from typing import Any, Dict, Optional


DB_PATH = os.getenv("DB_PATH", "app.db")
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "change-me-in-production")

logger = logging.getLogger("audit.customer_access")


class AccessDeniedOrNotFound(Exception):
    """顧客が存在しない、またはdriverにアクセス権がない場合の例外"""
    pass


class SecurityViolation(Exception):
    """返却直前の安全検査で機密情報が検出された場合の例外"""
    pass


# medical_history / credit_card などは返却禁止
FORBIDDEN_KEYWORDS = {
    "medical_history",
    "medical",
    "diagnosis",
    "disease",
    "medication",
    "prescription",
    "allergy",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "my_number",
    "password",
    "secret",
    "token",
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# -------------------------
# L4: 制度的正統性
# 安全なログ記録と追跡
# -------------------------

def _hash_identifier(value: Any) -> str:
    """
    driver_id / customer_id をログにそのまま残さないためのHMACハッシュ化。
    監査追跡は可能だが、ログ単体から個人を特定しにくくする。
    """
    raw = str(value).encode("utf-8")
    secret = AUDIT_SECRET.encode("utf-8")
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()


def _audit_log(
    event: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    reason: Optional[str] = None,
    fields: Optional[list[str]] = None,
) -> None:
    """
    監査ログには氏名・住所・電話番号・medical_history・credit_card等を絶対に出さない。
    """
    record = {
        "event": event,
        "driver_hash": _hash_identifier(driver_id),
        "customer_hash": _hash_identifier(customer_id),
        "result": result,
        "reason": reason,
        "returned_fields": fields or [],
    }

    logger.info(json.dumps(record, ensure_ascii=False))


# -------------------------
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# -------------------------

def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = str(name)
    if len(name) <= 1:
        return "*"

    return name[0] + "*" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) <= 4:
        return "****"

    return "*" * (len(digits) - 4) + digits[-4:]


def _mask_email(email: Optional[str]) -> Optional[str]:
    if not email or "@" not in email:
        return None

    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 1)

    return f"{masked_local}@{domain}"


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    例示用の簡易マスキング。
    実運用では住所パーサー等で「市区町村まで」などに正規化することが望ましい。
    """
    if not address:
        return None

    address = str(address)

    # 長すぎる詳細住所は末尾を伏せる
    if len(address) <= 6:
        return "*" * len(address)

    return address[:6] + "********"


def _contains_forbidden_key(obj: Any, path: str = "") -> Optional[str]:
    """
    辞書・リストを再帰的に走査し、返却禁止キーが含まれていないか検知する。
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()

            for forbidden in FORBIDDEN_KEYWORDS:
                if forbidden in key_lower:
                    return f"{path}.{key}" if path else str(key)

            child_path = f"{path}.{key}" if path else str(key)
            found = _contains_forbidden_key(value, child_path)
            if found:
                return found

    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            found = _contains_forbidden_key(item, f"{path}[{index}]")
            if found:
                return found

    return None


def _looks_like_credit_card(value: str) -> bool:
    """
    返却値にクレジットカード番号らしきものが混入していないか簡易検査する。
    Luhnチェック付き。
    """
    candidates = re.findall(r"(?:\d[ -]?){13,19}", value)

    for candidate in candidates:
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


def _contains_forbidden_value(obj: Any) -> bool:
    """
    値の中にカード番号らしきものがないか検知する。
    """
    if isinstance(obj, dict):
        return any(_contains_forbidden_value(v) for v in obj.values())

    if isinstance(obj, list):
        return any(_contains_forbidden_value(v) for v in obj)

    if isinstance(obj, str):
        return _looks_like_credit_card(obj)

    return False


# -------------------------
# L2: AI監査
# サニタイズ関数による最小権限化
# -------------------------

def _sanitize_customer_for_driver(row: sqlite3.Row) -> Dict[str, Any]:
    """
    driverに必要な最小限の情報だけを返す。
    medical_history / credit_card はそもそもSELECTしないし、ここでも返さない。
    """
    data = dict(row)

    return {
        "customer_id": data["id"],
        "name": _mask_name(data.get("full_name")),
        "address": _mask_address(data.get("address")),
        "phone": _mask_phone(data.get("phone")),
        "email": _mask_email(data.get("email")),
        "emergency_contact": {
            "name": _mask_name(data.get("emergency_contact_name")),
            "phone": _mask_phone(data.get("emergency_contact_phone")),
        },
        "safety_status": data.get("safety_status"),
        "last_checkin_at": data.get("last_checkin_at"),
    }


# -------------------------
# L3: 人間介入
# 返却直前でのガード節によるチェック
# -------------------------

def _guard_response(payload: Dict[str, Any]) -> None:
    """
    返却直前の最終安全検査。
    ここで検出されたら返却せず、監査ログに残して異常終了させる。
    """
    forbidden_key = _contains_forbidden_key(payload)
    if forbidden_key:
        raise SecurityViolation(f"Forbidden key detected in response: {forbidden_key}")

    if _contains_forbidden_value(payload):
        raise SecurityViolation("Forbidden value detected in response")


# -------------------------
# API本体
# -------------------------

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    要件:
    - DBから指定されたcustomer_idの顧客レコードを取得する
    - medical_history / credit_card等の機密情報は返却しない
    - driver_idに紐づく顧客だけ取得可能にする
    - 返却前にサニタイズ・ガードチェックを行う
    - 安全な監査ログを残す
    """

    _audit_log(
        event="get_customer_for_driver.requested",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    query = """
        SELECT
            c.id,
            c.full_name,
            c.address,
            c.phone,
            c.email,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.safety_status,
            c.last_checkin_at
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = ?
            AND dca.driver_id = ?
            AND c.deleted_at IS NULL
        LIMIT 1
    """

    try:
        with get_db_connection() as conn:
            row = conn.execute(query, (customer_id, driver_id)).fetchone()

        if row is None:
            _audit_log(
                event="get_customer_for_driver.denied_or_not_found",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
                reason="not_found_or_not_assigned",
            )
            raise AccessDeniedOrNotFound("Customer not found or access denied")

        # L2: 最小権限化された返却データへ変換
        payload = _sanitize_customer_for_driver(row)

        # L3: 返却直前の最終チェック
        _guard_response(payload)

        # L4: 安全な監査ログ
        _audit_log(
            event="get_customer_for_driver.succeeded",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
            fields=list(payload.keys()),
        )

        return payload

    except SecurityViolation as e:
        _audit_log(
            event="get_customer_for_driver.security_violation",
            driver_id=driver_id,
            customer_id=customer_id,
            result="blocked",
            reason=str(e),
        )
        raise

    except Exception as e:
        if not isinstance(e, AccessDeniedOrNotFound):
            _audit_log(
                event="get_customer_for_driver.failed",
                driver_id=driver_id,
                customer_id=customer_id,
                result="error",
                reason=type(e).__name__,
            )
        raise