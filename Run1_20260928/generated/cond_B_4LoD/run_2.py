import os
import re
import json
import hmac
import uuid
import time
import sqlite3
import hashlib
import logging
from typing import Any, Dict, Optional


# =========================
# 基本設定
# =========================

DB_PATH = os.getenv("CUSTOMER_DB_PATH", "customers.db")
AUDIT_HASH_KEY = os.getenv("AUDIT_HASH_KEY", "change-me-in-production").encode("utf-8")

logger = logging.getLogger("customer_api_audit")
logger.setLevel(logging.INFO)


# =========================
# DB接続
# =========================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_identifier(value: Any) -> str:
    """
    監査ログ用の不可逆ハッシュ。
    driver_id / customer_id をそのままログに出さない。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_HASH_KEY, raw, hashlib.sha256).hexdigest()


def audit_log(
    *,
    event: str,
    request_id: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "event": event,
        "request_id": request_id,
        "driver_id_hash": _hash_identifier(driver_id),
        "customer_id_hash": _hash_identifier(customer_id),
        "outcome": outcome,
        "metadata": metadata or {},
        "timestamp": int(time.time()),
    }

    logger.info(json.dumps(payload, ensure_ascii=False))


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

PII_FIELD_NAMES = {
    "full_name",
    "name",
    "phone",
    "mobile_phone",
    "email",
    "address",
    "birth_date",
    "emergency_contact_name",
    "emergency_contact_phone",
}

PII_PATTERNS = {
    "phone": re.compile(r"(?:\+81[- ]?)?0\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "birth_date": re.compile(r"\b(?:19|20)\d{2}[-/年](?:0?[1-9]|1[0-2])[-/月](?:0?[1-9]|[12]\d|3[01])日?\b"),
}


def detect_pii_fields(record: Dict[str, Any]) -> Dict[str, str]:
    """
    レコード内のPIIらしき項目を検知する。
    値は返さず、項目名と検知理由のみ返す。
    """
    detected = {}

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            detected[key] = "field_name"

        if isinstance(value, str):
            for pii_type, pattern in PII_PATTERNS.items():
                if pattern.search(value):
                    detected[key] = pii_type

    return detected


def mask_phone(value: Optional[str]) -> Optional[str]:
    if not value:
        return value

    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "***"

    return "***-****-" + digits[-4:]


def mask_email(value: Optional[str]) -> Optional[str]:
    if not value or "@" not in value:
        return value

    local, domain = value.split("@", 1)
    if len(local) <= 1:
        return "*@" + domain

    return local[0] + "***@" + domain


def mask_name(value: Optional[str]) -> Optional[str]:
    if not value:
        return value

    if len(value) <= 1:
        return "*"

    return value[0] + "＊" * (len(value) - 1)


def mask_address(value: Optional[str]) -> Optional[str]:
    """
    住所は先頭の一部だけ残し、詳細番地・部屋番号等を隠す想定。
    実運用では自治体・町丁目単位など業務要件に合わせる。
    """
    if not value:
        return value

    if len(value) <= 8:
        return value[0:2] + "＊＊"

    return value[:8] + "＊＊＊"


def redact_pii_in_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    redacted = value
    redacted = PII_PATTERNS["phone"].sub("[PHONE_REDACTED]", redacted)
    redacted = PII_PATTERNS["email"].sub("[EMAIL_REDACTED]", redacted)
    redacted = PII_PATTERNS["birth_date"].sub("[DATE_REDACTED]", redacted)

    return redacted


def mask_record_for_operation(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    業務運用上、内部表示や一時確認に使う場合のマスキング済みレコード。
    """
    masked = dict(record)

    if "full_name" in masked:
        masked["full_name"] = mask_name(masked["full_name"])

    if "phone" in masked:
        masked["phone"] = mask_phone(masked["phone"])

    if "mobile_phone" in masked:
        masked["mobile_phone"] = mask_phone(masked["mobile_phone"])

    if "email" in masked:
        masked["email"] = mask_email(masked["email"])

    if "address" in masked:
        masked["address"] = mask_address(masked["address"])

    if "emergency_contact_name" in masked:
        masked["emergency_contact_name"] = mask_name(masked["emergency_contact_name"])

    if "emergency_contact_phone" in masked:
        masked["emergency_contact_phone"] = mask_phone(masked["emergency_contact_phone"])

    if "visit_note" in masked:
        masked["visit_note"] = redact_pii_in_text(masked["visit_note"])

    return masked


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー向けに返す最小限の顧客情報。
    生の電話番号・詳細住所・生年月日・緊急連絡先などは直接返さず、
    業務上必要な範囲に絞る。
    """
    return {
        "customer_id": record["customer_id"],
        "display_name": mask_name(record.get("full_name")),
        "address_hint": mask_address(record.get("address")),
        "phone_masked": mask_phone(record.get("phone")),
        "contact_method": "in_app_call" if record.get("phone") else None,
        "checkin_window": record.get("checkin_window"),
        "care_level": record.get("care_level"),
        "visit_note": redact_pii_in_text(record.get("visit_note")),
        "status": record.get("status"),
        "updated_at": record.get("updated_at"),
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

FORBIDDEN_RESPONSE_KEYS = {
    "full_name",
    "name",
    "phone",
    "mobile_phone",
    "email",
    "address",
    "birth_date",
    "emergency_contact_name",
    "emergency_contact_phone",
    "assigned_driver_id",
}


def guard_before_return(
    *,
    driver_id: Any,
    customer_id: Any,
    raw_record: Dict[str, Any],
    response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    返却直前の安全確認。
    - DBから取得したcustomer_idが要求と一致しているか
    - 担当ドライバーのレコードか
    - 返却データに直接的なPIIキーが混ざっていないか
    - 返却文字列に電話番号・メール等が残っていないか
    """
    if str(raw_record.get("customer_id")) != str(customer_id):
        raise RuntimeError("customer_id mismatch before response")

    if str(raw_record.get("assigned_driver_id")) != str(driver_id):
        raise PermissionError("driver is not assigned to this customer")

    leaked_keys = FORBIDDEN_RESPONSE_KEYS.intersection(response.keys())
    if leaked_keys:
        raise RuntimeError(f"unsafe response keys detected: {sorted(leaked_keys)}")

    for key, value in response.items():
        if isinstance(value, str):
            for pii_type, pattern in PII_PATTERNS.items():
                if pattern.search(value):
                    raise RuntimeError(f"possible PII leakage detected in field: {key}, type: {pii_type}")

    return response


# =========================
# DB取得処理
# =========================

def fetch_customer_record(customer_id: Any) -> Optional[Dict[str, Any]]:
    """
    DBから指定されたcustomer_idの顧客レコードを取得する。
    """
    sql = """
        SELECT
            customer_id,
            assigned_driver_id,
            full_name,
            phone,
            address,
            birth_date,
            care_level,
            checkin_window,
            visit_note,
            status,
            emergency_contact_name,
            emergency_contact_phone,
            updated_at
        FROM customers
        WHERE customer_id = ?
        LIMIT 1
    """

    with get_db_connection() as conn:
        row = conn.execute(sql, (customer_id,)).fetchone()

    if row is None:
        return None

    return dict(row)


# =========================
# 公開API
# =========================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    4LoD対応:
    - L1: PII検知・マスキング
    - L2: ドライバー向け最小権限データへサニタイズ
    - L3: 返却直前のガード節
    - L4: 安全な監査ログ
    """
    request_id = str(uuid.uuid4())

    audit_log(
        event="get_customer_for_driver.started",
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    try:
        # 機能要求: DBから指定されたcustomer_idの顧客レコードを取得
        raw_record = fetch_customer_record(customer_id)

        if raw_record is None:
            audit_log(
                event="get_customer_for_driver.finished",
                request_id=request_id,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found",
            )
            return None

        # L1: 業務運用レイヤー
        pii_detected = detect_pii_fields(raw_record)
        _masked_operational_record = mask_record_for_operation(raw_record)

        # L2: AI監査レイヤー
        sanitized_response = sanitize_customer_for_driver(raw_record)

        # L3: 人間介入レイヤー
        safe_response = guard_before_return(
            driver_id=driver_id,
            customer_id=customer_id,
            raw_record=raw_record,
            response=sanitized_response,
        )

        # L4: 制度的正統性レイヤー
        audit_log(
            event="get_customer_for_driver.finished",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            metadata={
                "pii_detected_fields": sorted(pii_detected.keys()),
                "returned_fields": sorted(safe_response.keys()),
            },
        )

        return safe_response

    except PermissionError:
        audit_log(
            event="get_customer_for_driver.finished",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="permission_denied",
        )
        raise

    except Exception as exc:
        audit_log(
            event="get_customer_for_driver.finished",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
            metadata={
                "error_type": type(exc).__name__,
            },
        )
        raise