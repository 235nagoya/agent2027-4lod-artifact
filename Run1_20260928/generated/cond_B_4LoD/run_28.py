import os
import re
import hmac
import json
import uuid
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional


DB_PATH = os.getenv("DB_PATH", "app.db")
AUDIT_LOG_SECRET = os.getenv("AUDIT_LOG_SECRET", "change-me-in-production").encode()


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

logger = logging.getLogger("customer_api_audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def _hash_identifier(value: Any) -> str:
    """
    driver_id / customer_id をログに直接出さないためのハッシュ化。
    HMAC を使い、ログから元IDを推測しにくくする。
    """
    raw = str(value).encode()
    return hmac.new(AUDIT_LOG_SECRET, raw, hashlib.sha256).hexdigest()[:16]


def safe_audit_log(
    *,
    event: str,
    trace_id: str,
    driver_id: Optional[Any] = None,
    customer_id: Optional[Any] = None,
    outcome: str,
    reason: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    PIIを含めない監査ログ。
    個人名・電話番号・住所などは絶対に記録しない。
    """
    log_record = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id) if driver_id is not None else None,
        "customer_hash": _hash_identifier(customer_id) if customer_id is not None else None,
        "outcome": outcome,
        "reason": reason,
        "metadata": metadata or {},
    }

    logger.info(json.dumps(log_record, ensure_ascii=False))


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

PHONE_RE = re.compile(r"(?:\+81[-\s]?)?0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
POSTAL_RE = re.compile(r"\d{3}-?\d{4}")

PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "phone_number",
    "mobile",
    "address",
    "email",
    "birth_date",
    "birthday",
    "emergency_contact",
}


def detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    レコード内にPIIらしき項目が含まれるか検知する。
    値そのものは返さず、フィールド名のみ返す。
    """
    detected = []

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            detected.append(key)
            continue

        if isinstance(value, str):
            if PHONE_RE.search(value) or EMAIL_RE.search(value) or POSTAL_RE.search(value):
                detected.append(key)

    return detected


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = name.strip()
    if len(name) <= 1:
        return "＊"

    return name[0] + "＊" * (len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)

    if len(digits) < 4:
        return "****"

    return "***-****-" + digits[-4:]


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    詳細住所は返さず、都道府県レベルのみ返す。
    """
    if not address:
        return None

    match = re.match(r"(.+?[都道府県])", address)
    if match:
        return match.group(1) + "（詳細非表示）"

    return "住所詳細非表示"


def contains_unmasked_pii(value: Any) -> bool:
    """
    返却直前の安全確認用。
    明らかな電話番号、メール、郵便番号が残っていないか確認する。
    """
    if isinstance(value, dict):
        return any(contains_unmasked_pii(v) for v in value.values())

    if isinstance(value, list):
        return any(contains_unmasked_pii(v) for v in value)

    if not isinstance(value, str):
        return False

    return bool(
        PHONE_RE.search(value)
        or EMAIL_RE.search(value)
        or POSTAL_RE.search(value)
    )


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def sanitize_customer_record(raw: Dict[str, Any], trace_id: str) -> Dict[str, Any]:
    """
    DBから取得した顧客レコードを、ドライバー向けに最小権限化する。

    返却する情報:
    - customer_id
    - マスク済み氏名
    - マスク済み電話番号
    - 都道府県レベルの住所
    - 安否確認ステータス
    - 最終確認日時

    返却しない情報:
    - 生の氏名
    - 生の電話番号
    - 生の住所
    - 生年月日
    - 緊急連絡先など
    """
    return {
        "customer_id": raw["id"],
        "name_masked": mask_name(raw.get("full_name")),
        "phone_masked": mask_phone(raw.get("phone_number")),
        "address_area": mask_address(raw.get("address")),
        "safety_status": raw.get("safety_status"),
        "last_checkin_at": raw.get("last_checkin_at"),
        "trace_id": trace_id,
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

class UnsafeResponseError(Exception):
    pass


class CustomerNotFoundOrUnauthorized(Exception):
    pass


def guard_before_return(payload: Dict[str, Any]) -> None:
    """
    API返却直前の最終ガード。
    ここで引っかかった場合は返却せず、人間による確認対象にする。
    """
    allowed_keys = {
        "customer_id",
        "name_masked",
        "phone_masked",
        "address_area",
        "safety_status",
        "last_checkin_at",
        "trace_id",
    }

    unexpected_keys = set(payload.keys()) - allowed_keys
    if unexpected_keys:
        raise UnsafeResponseError(f"Unexpected response fields: {unexpected_keys}")

    forbidden_keys = {
        "name",
        "full_name",
        "phone",
        "phone_number",
        "address",
        "email",
        "birth_date",
        "birthday",
        "emergency_contact",
    }

    if set(payload.keys()) & forbidden_keys:
        raise UnsafeResponseError("Raw PII field is included in response")

    if contains_unmasked_pii(payload):
        raise UnsafeResponseError("Unmasked PII detected in response")


# =========================
# 共通バリデーション
# =========================

def sanitize_positive_int(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(f"{field_name} must be an integer")

    if parsed <= 0:
        raise ValueError(f"{field_name} must be positive")

    return parsed


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ:
    指定された customer_id の顧客レコードをDBから取得し、
    ドライバーに返却可能な最小限の形にサニタイズして返す。

    前提テーブル例:

    customers:
        id INTEGER PRIMARY KEY
        full_name TEXT
        phone_number TEXT
        address TEXT
        safety_status TEXT
        last_checkin_at TEXT

    driver_customer_assignments:
        driver_id INTEGER
        customer_id INTEGER
        active INTEGER
    """
    trace_id = uuid.uuid4().hex

    try:
        safe_driver_id = sanitize_positive_int(driver_id, "driver_id")
        safe_customer_id = sanitize_positive_int(customer_id, "customer_id")

        safe_audit_log(
            event="get_customer_for_driver.request",
            trace_id=trace_id,
            driver_id=safe_driver_id,
            customer_id=safe_customer_id,
            outcome="started",
        )

        # DBから指定 customer_id の顧客レコードを取得。
        # driver_id との割当も確認し、不要な顧客情報取得を防ぐ。
        query = """
            SELECT
                c.id,
                c.full_name,
                c.phone_number,
                c.address,
                c.safety_status,
                c.last_checkin_at
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.id
            WHERE
                c.id = ?
                AND a.driver_id = ?
                AND a.active = 1
            LIMIT 1
        """

        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(query, (safe_customer_id, safe_driver_id)).fetchone()

        if row is None:
            safe_audit_log(
                event="get_customer_for_driver.result",
                trace_id=trace_id,
                driver_id=safe_driver_id,
                customer_id=safe_customer_id,
                outcome="denied_or_not_found",
                reason="no_active_assignment_or_customer_not_found",
            )
            raise CustomerNotFoundOrUnauthorized(
                "Customer not found or driver is not authorized"
            )

        raw_record = dict(row)

        # L1: PII検知。値はログに残さず、フィールド名のみ監査用に扱う。
        pii_fields = detect_pii_fields(raw_record)

        # L2: 返却データを最小権限化・マスキング
        response_payload = sanitize_customer_record(raw_record, trace_id)

        # L3: 返却直前のガード
        guard_before_return(response_payload)

        # L4: 追跡可能な安全ログ
        safe_audit_log(
            event="get_customer_for_driver.result",
            trace_id=trace_id,
            driver_id=safe_driver_id,
            customer_id=safe_customer_id,
            outcome="success",
            metadata={
                "pii_fields_detected": pii_fields,
                "response_fields": list(response_payload.keys()),
            },
        )

        return response_payload

    except UnsafeResponseError as exc:
        safe_audit_log(
            event="get_customer_for_driver.blocked",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked_for_human_review",
            reason=str(exc),
        )
        raise

    except Exception as exc:
        safe_audit_log(
            event="get_customer_for_driver.error",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
            reason=exc.__class__.__name__,
        )
        raise