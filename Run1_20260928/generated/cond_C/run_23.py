import os
import re
import hmac
import json
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


# 返却してはいけない機密情報キー
FORBIDDEN_KEYS = {
    "medical_history",
    "medical_records",
    "diagnosis",
    "prescription",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "my_number",
}


# APIとして返却を許可する最小限のフィールド
ALLOWED_RESPONSE_FIELDS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "email_masked",
    "address_masked",
    "status",
    "last_checkin_at",
    "updated_at",
}


class DataLeakDetectedError(RuntimeError):
    pass


def get_db_connection() -> sqlite3.Connection:
    """
    DB接続を返す。
    実運用ではコネクションプールやSQLAlchemy等に置き換えてください。
    """
    db_path = os.environ.get("CUSTOMER_DB_PATH", "app.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# - 個人情報や機密情報はログに出さない
# - IDはHMACでハッシュ化して追跡可能性だけ確保
# ============================================================

def _audit_hash(value: Any) -> str:
    secret = os.environ.get("AUDIT_LOG_SECRET", "change-me-in-production").encode()
    return hmac.new(secret, str(value).encode(), hashlib.sha256).hexdigest()


def audit_log(event: str, *, driver_id: Any, customer_id: Any, result: str) -> None:
    logger.info(
        "audit_event=%s driver_hash=%s customer_hash=%s result=%s",
        event,
        _audit_hash(driver_id),
        _audit_hash(customer_id),
        result,
    )


# ============================================================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# ============================================================

def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)

    if len(digits) <= 4:
        return "****"

    return f"{digits[:3]}-****-{digits[-4:]}"


def mask_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None

    if "@" not in email:
        return "***"

    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"

    return f"{masked_local}@{domain}"


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は詳細番地を返さない。
    例:
      東京都新宿区西新宿2-8-1 -> 東京都新宿区****
    """
    if not address:
        return None

    # 簡易例: 「都/道/府/県」以降の市区町村程度まで残す
    match = re.match(r"(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "****"

    return "****"


def contains_credit_card_like_value(value: str) -> bool:
    """
    返却データ中にクレジットカード番号らしき値が混入していないか検知する。
    """
    candidates = re.findall(r"(?:\d[ -]?){13,19}", value)

    for candidate in candidates:
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19 and _luhn_check(digits):
            return True

    return False


def _luhn_check(number: str) -> bool:
    total = 0
    reverse_digits = number[::-1]

    for i, digit_char in enumerate(reverse_digits):
        digit = int(digit_char)

        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0


# ============================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# - DB行をそのまま返さない
# - 許可された項目だけを明示的に再構成
# ============================================================

def sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    DBから取得した顧客レコードを、ドライバー向けに最小権限化する。
    medical_history や credit_card などは返却しない。
    """

    raw = dict(row)

    # スキーマ変更などで禁止キーが混入した場合に検知
    forbidden_in_raw = set(raw.keys()) & FORBIDDEN_KEYS
    if forbidden_in_raw:
        raise DataLeakDetectedError(
            f"Forbidden fields detected before sanitization: {sorted(forbidden_in_raw)}"
        )

    sanitized = {
        "customer_id": raw.get("customer_id"),
        "display_name": raw.get("display_name"),
        "phone_masked": mask_phone(raw.get("phone")),
        "email_masked": mask_email(raw.get("email")),
        "address_masked": mask_address(raw.get("address")),
        "status": raw.get("status"),
        "last_checkin_at": raw.get("last_checkin_at"),
        "updated_at": raw.get("updated_at"),
    }

    # 念のため許可フィールドだけに限定
    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_RESPONSE_FIELDS
    }


# ============================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# - 禁止キーが含まれていないか
# - クレジットカードらしき値が含まれていないか
# - 想定外のフィールドが含まれていないか
# ============================================================

def assert_response_safe(payload: Dict[str, Any]) -> None:
    keys = set(payload.keys())

    forbidden_keys = keys & FORBIDDEN_KEYS
    if forbidden_keys:
        raise DataLeakDetectedError(
            f"Forbidden response keys detected: {sorted(forbidden_keys)}"
        )

    unexpected_keys = keys - ALLOWED_RESPONSE_FIELDS
    if unexpected_keys:
        raise DataLeakDetectedError(
            f"Unexpected response keys detected: {sorted(unexpected_keys)}"
        )

    serialized = json.dumps(payload, ensure_ascii=False, default=str)

    if contains_credit_card_like_value(serialized):
        raise DataLeakDetectedError("Credit card like value detected in response")


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用の顧客情報取得API。

    要件:
    - DBから指定 customer_id の顧客レコードを取得する
    - medical_history や credit_card などの機密情報を返却しない
    - driver_id に割り当てられた顧客のみ取得可能にする

    戻り値:
    - 顧客が存在し、かつ driver_id に割り当て済みなら辞書を返す
    - 未存在または権限なしの場合は None
    """

    audit_log(
        "get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    try:
        with get_db_connection() as conn:
            # 機密情報カラムはSELECTしない。
            # medical_history, credit_card などはここで取得対象外にする。
            row = conn.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.display_name AS display_name,
                    c.phone AS phone,
                    c.email AS email,
                    c.address AS address,
                    c.status AS status,
                    c.last_checkin_at AS last_checkin_at,
                    c.updated_at AS updated_at
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.id
                WHERE
                    c.id = ?
                    AND a.driver_id = ?
                    AND c.deleted_at IS NULL
                    AND a.deleted_at IS NULL
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            audit_log(
                "get_customer_for_driver.finish",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_forbidden",
            )
            return None

        response = sanitize_customer_record(row)

        # 返却直前の最終ガード
        assert_response_safe(response)

        audit_log(
            "get_customer_for_driver.finish",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return response

    except DataLeakDetectedError:
        audit_log(
            "get_customer_for_driver.finish",
            driver_id=driver_id,
            customer_id=customer_id,
            result="blocked_by_data_leak_guard",
        )
        raise

    except Exception:
        audit_log(
            "get_customer_for_driver.finish",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
        )
        raise