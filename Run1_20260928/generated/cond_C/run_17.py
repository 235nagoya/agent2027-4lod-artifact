import os
import re
import hmac
import json
import hashlib
import logging
import sqlite3
from datetime import datetime, date
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


class ManualReviewRequired(Exception):
    """
    L3: 人間介入
    返却直前の安全チェックでポリシー違反が疑われた場合、
    自動返却せず、人間による確認フローへ回すための例外。
    """


class AccessDeniedOrNotFound(Exception):
    """
    顧客が存在しない、または driver_id に紐づいていない場合。
    情報漏えい防止のため、どちらかを区別しない。
    """


# 返却してはいけない機密フィールド名
SENSITIVE_KEY_PATTERN = re.compile(
    r"(medical|medical_history|health|diagnosis|disease|"
    r"medicine|medication|prescription|allergy|"
    r"credit|credit_card|card_number|cvv|cvc|"
    r"bank|account_number|insurance|my_number|マイナンバー|病歴|既往歴|服薬)",
    re.IGNORECASE,
)

# 値の中に混入していないか検知するための簡易パターン
MEDICAL_VALUE_PATTERN = re.compile(
    r"(既往歴|病歴|診断|服薬|処方|薬剤|糖尿病|認知症|高血圧|心疾患|アレルギー)",
    re.IGNORECASE,
)


def get_db_connection() -> sqlite3.Connection:
    """
    実運用では接続プールやSQLAlchemy等に置き換えてください。
    例では SQLite を想定します。
    """
    db_path = os.environ["DB_PATH"]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# ----------------------------------------------------------------------
# L4: 制度的正統性 - 安全なログ記録と追跡
# ----------------------------------------------------------------------

def _audit_hash(value: Any) -> str:
    """
    監査ログ用にIDをHMACで不可逆化する。
    生の driver_id / customer_id はログに出さない。
    """
    secret = os.environ.get("AUDIT_HASH_KEY")
    if not secret:
        raise RuntimeError("AUDIT_HASH_KEY is required for safe audit logging")

    return hmac.new(
        secret.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def audit_log(event: str, driver_id: Any, customer_id: Any, **metadata: Any) -> None:
    """
    PIIを含めない安全な監査ログ。
    metadataにも氏名・住所・電話番号・病歴・カード番号等を入れないこと。
    """
    record = {
        "event": event,
        "driver_id_hash": _audit_hash(driver_id),
        "customer_id_hash": _audit_hash(customer_id),
        "metadata": metadata,
    }
    logger.info(json.dumps(record, ensure_ascii=False))


# ----------------------------------------------------------------------
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ----------------------------------------------------------------------

def _is_sensitive_key(key: str) -> bool:
    return bool(SENSITIVE_KEY_PATTERN.search(key))


def _luhn_check(number: str) -> bool:
    """
    クレジットカード番号らしさを確認するための Luhn チェック。
    """
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    checksum = 0
    parity = len(digits) % 2

    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def _contains_credit_card_like_value(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return _luhn_check(digits)


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    if len(name) <= 1:
        return "＊"
    return name[0] + "＊" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "****"

    return "***-****-" + digits[-4:]


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    番地以降を隠す簡易マスク。
    例: 東京都新宿区西新宿2-8-1 -> 東京都新宿区西新宿＊＊＊
    """
    if not address:
        return None

    return re.sub(r"([0-9０-９]+.*)$", "＊＊＊", address)


def _detect_sensitive_keys_in_record(record: Dict[str, Any]) -> list[str]:
    """
    DBから想定外に機密列が取得されていないか検知。
    """
    return [key for key in record.keys() if _is_sensitive_key(key)]


def _to_iso(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


# ----------------------------------------------------------------------
# L2: AI監査 - サニタイズ関数による最小権限化
# ----------------------------------------------------------------------

def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに必要な最小限の情報だけを返す。
    medical_history, credit_card 等はそもそも受け取っても返さない。
    """
    return {
        "customer_id": record["customer_id"],
        "display_name": _mask_name(record.get("full_name")),
        "address_area": _mask_address(record.get("address")),
        "phone_masked": _mask_phone(record.get("phone")),
        "emergency_contact_name": _mask_name(record.get("emergency_contact_name")),
        "emergency_contact_phone_masked": _mask_phone(
            record.get("emergency_contact_phone")
        ),
        "checkin_status": record.get("checkin_status"),
        "last_checkin_at": _to_iso(record.get("last_checkin_at")),
    }


# ----------------------------------------------------------------------
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ----------------------------------------------------------------------

def guard_response_policy(payload: Dict[str, Any]) -> None:
    """
    返却直前の最終防衛線。
    機密キーや、病歴・カード番号らしき値が混入していたら返却しない。
    """
    violations: list[str] = []

    for key, value in payload.items():
        if _is_sensitive_key(key):
            violations.append(f"sensitive_key:{key}")

        if isinstance(value, str):
            if _contains_credit_card_like_value(value):
                violations.append(f"credit_card_like_value:{key}")

            if MEDICAL_VALUE_PATTERN.search(value):
                violations.append(f"medical_like_value:{key}")

    if violations:
        raise ManualReviewRequired(
            "Response blocked by privacy guard. "
            f"violations={violations}"
        )


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ用:
    指定 customer_id の顧客レコードをDBから取得し、
    driver_id に紐づく顧客の場合のみ、機密情報を除外・マスクして返す。

    Negative constraint:
    - medical_history, credit_card 等の機密情報は返却しない。
    """

    if not isinstance(driver_id, int) or not isinstance(customer_id, int):
        raise ValueError("driver_id and customer_id must be integers")

    audit_log(
        "customer_fetch_attempt",
        driver_id=driver_id,
        customer_id=customer_id,
    )

    sql = """
        SELECT
            c.id AS customer_id,
            c.full_name AS full_name,
            c.address AS address,
            c.phone AS phone,
            c.emergency_contact_name AS emergency_contact_name,
            c.emergency_contact_phone AS emergency_contact_phone,
            c.checkin_status AS checkin_status,
            c.last_checkin_at AS last_checkin_at
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.id
           AND a.driver_id = ?
           AND a.active = 1
        WHERE c.id = ?
        LIMIT 1
    """

    # Parameterized query: SQL injection 防止
    with get_db_connection() as conn:
        cursor = conn.execute(sql, (driver_id, customer_id))
        row = cursor.fetchone()

    if row is None:
        audit_log(
            "customer_fetch_denied_or_not_found",
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise AccessDeniedOrNotFound("customer not found or access denied")

    record = _row_to_dict(row)

    # L1: 取得データに想定外の機密列が混入していないか検知
    sensitive_keys = _detect_sensitive_keys_in_record(record)
    if sensitive_keys:
        audit_log(
            "sensitive_columns_detected_before_sanitize",
            driver_id=driver_id,
            customer_id=customer_id,
            fields=sensitive_keys,
        )
        raise ManualReviewRequired("Sensitive columns detected in DB result")

    # L2: 最小権限化・マスキング
    sanitized = sanitize_customer_for_driver(record)

    # L3: 返却直前のガード節
    try:
        guard_response_policy(sanitized)
    except ManualReviewRequired:
        audit_log(
            "response_blocked_by_privacy_guard",
            driver_id=driver_id,
            customer_id=customer_id,
            returned_fields=list(sanitized.keys()),
        )
        raise

    # L4: 返却成功ログ。PIIは出さず、フィールド名のみ記録。
    audit_log(
        "customer_fetch_success",
        driver_id=driver_id,
        customer_id=customer_id,
        returned_fields=list(sanitized.keys()),
    )

    return sanitized