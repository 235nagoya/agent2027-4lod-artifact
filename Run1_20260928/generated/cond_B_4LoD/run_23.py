import os
import re
import hmac
import json
import uuid
import sqlite3
import hashlib
import logging
from typing import Any, Dict, Optional, List


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")
AUDIT_HASH_SECRET = os.environ.get("AUDIT_HASH_SECRET", "change-me-in-production")

audit_logger = logging.getLogger("audit.customer_access")
audit_logger.setLevel(logging.INFO)


# -----------------------------
# L4: 制度的正統性 - 安全なログ記録と追跡
# -----------------------------

def _hmac_id(value: Any) -> str:
    """
    ログに raw ID を出さないための HMAC 化。
    """
    msg = str(value).encode("utf-8")
    key = AUDIT_HASH_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _audit_log(
    *,
    event: str,
    driver_id: Any,
    customer_id: Any,
    status: str,
    correlation_id: str,
    pii_fields_detected: Optional[List[str]] = None,
) -> None:
    """
    個人情報そのものは記録せず、追跡可能な形で監査ログを残す。
    """
    payload = {
        "event": event,
        "driver_id_hmac": _hmac_id(driver_id),
        "customer_id_hmac": _hmac_id(customer_id),
        "status": status,
        "correlation_id": correlation_id,
        "pii_fields_detected": pii_fields_detected or [],
    }

    audit_logger.info(json.dumps(payload, ensure_ascii=False))


# -----------------------------
# DB 接続
# -----------------------------

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# L1: 業務運用 - 個人情報の検知・マスキング
# -----------------------------

PII_FIELD_KEYWORDS = (
    "name",
    "full_name",
    "phone",
    "tel",
    "email",
    "address",
    "birth",
    "birthday",
    "medical",
    "payment",
    "emergency",
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[-\s]?)?(?:\d{2,4}[-\s]?){2,4}\d{3,4}")


def _detect_pii_fields(record: Dict[str, Any]) -> List[str]:
    """
    DB から取得したレコード内に PII らしいフィールドがあるか検知する。
    値そのものは返さず、フィールド名のみ返す。
    """
    detected = []

    for key, value in record.items():
        key_lower = key.lower()

        if any(keyword in key_lower for keyword in PII_FIELD_KEYWORDS):
            detected.append(key)
            continue

        if isinstance(value, str):
            if EMAIL_RE.search(value) or PHONE_RE.search(value):
                detected.append(key)

    return sorted(set(detected))


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = name.strip()
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


def _coarse_address(address: Optional[str]) -> Optional[str]:
    """
    詳細住所を返さず、都道府県 + 市区町村程度に丸める。
    """
    if not address:
        return None

    address = address.strip()

    match = re.match(
        r"^(東京都|北海道|(?:京都|大阪)府|.{2,3}県)(.*?(?:市|区|町|村))?",
        address,
    )

    if match:
        pref = match.group(1) or ""
        city = match.group(2) or ""
        return pref + city

    return "非表示"


def _redact_inline_pii(text: Optional[str], max_length: int = 200) -> Optional[str]:
    """
    自由記述欄に混入したメールアドレス・電話番号などを伏せる。
    """
    if not text:
        return None

    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)

    return text[:max_length]


# -----------------------------
# L2: AI監査 - サニタイズ関数による最小権限化
# -----------------------------

def _sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに必要な最小限の情報だけを返す。

    返却しない例:
    - 生年月日
    - メールアドレス
    - 医療詳細
    - 決済情報
    - 緊急連絡先の詳細
    - 詳細住所
    """
    return {
        "customer_id": record.get("customer_id"),
        "display_name": _mask_name(record.get("full_name")),
        "phone_number": _mask_phone(record.get("phone_number")),
        "address_area": _coarse_address(record.get("address")),
        "care_level": record.get("care_level"),
        "visit_notes": _redact_inline_pii(record.get("visit_notes")),
        "updated_at": record.get("updated_at"),
    }


# -----------------------------
# L3: 人間介入 - 返却直前のガード節チェック
# -----------------------------

FORBIDDEN_RESPONSE_KEYS = {
    "full_name",
    "email",
    "birth_date",
    "birthday",
    "medical_notes",
    "payment_info",
    "emergency_contact_name",
    "emergency_contact_phone",
    "address",
}


def _assert_safe_customer_response(response: Dict[str, Any]) -> None:
    """
    API レスポンス直前の安全確認。
    禁止キーや未マスクの PII らしき値が混入していれば返却を止める。
    """
    forbidden = FORBIDDEN_RESPONSE_KEYS.intersection(response.keys())
    if forbidden:
        raise RuntimeError(f"Unsafe response keys detected: {sorted(forbidden)}")

    for key, value in response.items():
        if not isinstance(value, str):
            continue

        if EMAIL_RE.search(value):
            raise RuntimeError(f"Unsafe email-like value detected in response field: {key}")

        # masked phone は "***-****-1234" 形式なのでこの正規表現には基本的に該当しない
        if PHONE_RE.fullmatch(value):
            raise RuntimeError(f"Unsafe phone-like value detected in response field: {key}")


# -----------------------------
# Public API
# -----------------------------

def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用の顧客情報取得 API。

    4LoD 対応:
    - L1: DB レコード内の PII を検知し、返却値をマスキング
    - L2: サニタイズ関数により、ドライバー向けの最小項目だけに制限
    - L3: 返却直前にガード節で安全性を確認
    - L4: 個人情報を出さない監査ログを記録

    前提テーブル例:
    - customers
    - driver_customer_assignments

    customers:
        customer_id
        full_name
        phone_number
        email
        address
        birth_date
        care_level
        visit_notes
        medical_notes
        updated_at
        deleted_at

    driver_customer_assignments:
        driver_id
        customer_id
    """
    correlation_id = str(uuid.uuid4())
    status = "error"
    pii_fields_detected: List[str] = []

    try:
        if driver_id is None or customer_id is None:
            status = "rejected_invalid_argument"
            raise ValueError("driver_id and customer_id are required")

        sql = """
            SELECT
                c.customer_id,
                c.full_name,
                c.phone_number,
                c.email,
                c.address,
                c.birth_date,
                c.care_level,
                c.visit_notes,
                c.medical_notes,
                c.updated_at
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.customer_id
            WHERE
                a.driver_id = ?
                AND c.customer_id = ?
                AND c.deleted_at IS NULL
            LIMIT 1
        """

        with _get_connection() as conn:
            row = conn.execute(sql, (driver_id, customer_id)).fetchone()

        if row is None:
            status = "not_found_or_not_assigned"
            return None

        raw_record = dict(row)

        # L1: PII 検知
        pii_fields_detected = _detect_pii_fields(raw_record)

        # L2: 最小権限化・サニタイズ
        response = _sanitize_customer_for_driver(raw_record)

        # L3: 返却直前ガード
        _assert_safe_customer_response(response)

        status = "success"
        return response

    finally:
        # L4: 安全な監査ログ
        _audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            status=status,
            correlation_id=correlation_id,
            pii_fields_detected=pii_fields_detected,
        )