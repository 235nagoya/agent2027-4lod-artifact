import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Set


DB_PATH = os.environ.get("APP_DB_PATH", "app.db")
AUDIT_LOG_SECRET = os.environ.get("AUDIT_LOG_SECRET", "change-me-in-production")

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)


class CustomerNotFound(Exception):
    pass


class HumanReviewRequired(Exception):
    pass


# =========================
# L4: 制度的正統性
# 安全なログ記録・追跡
# =========================

def _trace_id() -> str:
    return str(uuid.uuid4())


def _hash_identifier(value: Any) -> str:
    """
    ログ用にIDをHMACで不可逆化する。
    driver_id / customer_id を平文ログに残さない。
    """
    return hmac.new(
        AUDIT_LOG_SECRET.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:20]


def _audit_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    details: Dict[str, Any] | None = None,
) -> None:
    """
    安全な監査ログ。
    個人名・電話番号・住所などのPIIは記録しない。
    """
    record = {
        "event": event,
        "trace_id": trace_id,
        "driver_ref": _hash_identifier(driver_id),
        "customer_ref": _hash_identifier(customer_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details or {},
    }
    logger.info(json.dumps(record, ensure_ascii=False))


# =========================
# DB接続
# =========================

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# L1: 業務運用
# 個人情報の検知・マスキング
# =========================

PHONE_RE = re.compile(r"(?:\+81[-\s]?)?0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
POSTAL_RE = re.compile(r"\d{3}-?\d{4}")
ADDRESS_RE = re.compile(r"(東京都|北海道|(?:京都|大阪)府|.{2,3}県).+?(市|区|町|村)")

PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "mobile_phone",
    "email",
    "address",
    "postal_code",
    "date_of_birth",
    "emergency_contact",
    "medical_note",
    "medical_notes",
}


def _detect_pii(data: Any) -> Set[str]:
    """
    PIIを検知する。
    値そのものは返さず、検知種別のみ返す。
    """
    findings: Set[str] = set()

    if isinstance(data, dict):
        for key, value in data.items():
            key_lower = str(key).lower()
            if key_lower in PII_FIELD_NAMES and value:
                findings.add(f"field:{key_lower}")
            findings |= _detect_pii(value)

    elif isinstance(data, list):
        for item in data:
            findings |= _detect_pii(item)

    elif isinstance(data, str):
        if PHONE_RE.search(data):
            findings.add("pattern:phone")
        if EMAIL_RE.search(data):
            findings.add("pattern:email")
        if POSTAL_RE.search(data):
            findings.add("pattern:postal_code")
        if ADDRESS_RE.search(data):
            findings.add("pattern:address")

    return findings


def _mask_name(name: str | None) -> str | None:
    if not name:
        return None
    if len(name) <= 1:
        return "*"
    return name[0] + "*" * (len(name) - 1)


def _mask_phone(phone: str | None) -> str | None:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 7:
        return "***"

    return f"{digits[:3]}-****-{digits[-4:]}"


def _mask_address(address: str | None) -> str | None:
    """
    住所は都道府県レベルまでに丸める。
    """
    if not address:
        return None

    pref_match = re.match(r"(東京都|北海道|(?:京都|大阪)府|.{2,3}県)", address)
    if pref_match:
        return pref_match.group(1) + "..."

    return "***"


def _sanitize_free_text(text: str | None) -> str | None:
    """
    自由記述欄からPIIを除去する。
    """
    if not text:
        return None

    sanitized = PHONE_RE.sub("[電話番号削除]", text)
    sanitized = EMAIL_RE.sub("[メール削除]", sanitized)
    sanitized = POSTAL_RE.sub("[郵便番号削除]", sanitized)
    sanitized = ADDRESS_RE.sub("[住所削除]", sanitized)

    return sanitized[:200]


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def _sanitize_customer_for_driver(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー向けに必要最小限の項目だけ返す。
    生年月日、医療メモ、緊急連絡先などは返さない。
    """
    return {
        "customer_id": raw["customer_id"],
        "name_masked": _mask_name(raw.get("full_name")),
        "phone_masked": _mask_phone(raw.get("phone")),
        "address_masked": _mask_address(raw.get("address")),
        "checkin_status": raw.get("checkin_status"),
        "last_checkin_at": raw.get("last_checkin_at"),
        "route_note": _sanitize_free_text(raw.get("route_note")),
    }


# =========================
# L3: 人間介入
# 返却直前ガード節
# =========================

SAFE_RESPONSE_KEYS = {
    "customer_id",
    "name_masked",
    "phone_masked",
    "address_masked",
    "checkin_status",
    "last_checkin_at",
    "route_note",
    "trace_id",
}


def _guard_before_return(
    payload: Dict[str, Any],
    *,
    expected_customer_id: Any,
    trace_id: str,
) -> None:
    """
    返却直前に以下を確認する。
    - 想定外のキーが含まれていない
    - customer_id が要求対象と一致している
    - 未マスクのPIIらしき文字列が残っていない

    問題がある場合は HumanReviewRequired を投げ、
    オペレーター確認に回せるよう trace_id を付ける。
    """
    unexpected_keys = set(payload.keys()) - SAFE_RESPONSE_KEYS
    if unexpected_keys:
        raise HumanReviewRequired(
            f"Unexpected response fields detected. trace_id={trace_id}"
        )

    if str(payload.get("customer_id")) != str(expected_customer_id):
        raise HumanReviewRequired(
            f"Customer ID mismatch detected. trace_id={trace_id}"
        )

    serialized = json.dumps(payload, ensure_ascii=False)

    # マスク後の phone_masked は 090-****-1234 のため PHONE_RE に一致しない想定
    if PHONE_RE.search(serialized) or EMAIL_RE.search(serialized) or POSTAL_RE.search(serialized):
        raise HumanReviewRequired(
            f"Unmasked PII detected in response. trace_id={trace_id}"
        )


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    想定テーブル:
      customers(
        customer_id,
        full_name,
        phone,
        address,
        checkin_status,
        last_checkin_at,
        route_note,
        deleted_at
      )

      driver_customer_assignments(
        driver_id,
        customer_id,
        active
      )
    """
    trace_id = _trace_id()

    _audit_log(
        "customer_fetch_requested",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    query = """
        SELECT
            c.customer_id,
            c.full_name,
            c.phone,
            c.address,
            c.checkin_status,
            c.last_checkin_at,
            c.route_note
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.customer_id
           AND a.driver_id = ?
           AND a.active = 1
        WHERE c.customer_id = ?
          AND c.deleted_at IS NULL
        LIMIT 1
    """

    with _get_connection() as conn:
        row = conn.execute(query, (driver_id, customer_id)).fetchone()

    if row is None:
        _audit_log(
            "customer_fetch_not_found_or_unassigned",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise CustomerNotFound("Customer not found")

    raw_record = dict(row)

    # L1: DBから取得した顧客レコード内のPIIを検知
    pii_findings = _detect_pii(raw_record)

    _audit_log(
        "customer_record_loaded",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        details={
            "pii_detected": sorted(pii_findings),
        },
    )

    # L2: ドライバー向けに最小権限化・マスキング
    response = _sanitize_customer_for_driver(raw_record)
    response["trace_id"] = trace_id

    try:
        # L3: 返却直前のガード節
        _guard_before_return(
            response,
            expected_customer_id=customer_id,
            trace_id=trace_id,
        )
    except HumanReviewRequired:
        _audit_log(
            "customer_fetch_human_review_required",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise

    # L4: 安全な追跡ログ
    _audit_log(
        "customer_fetch_succeeded",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        details={
            "returned_fields": sorted(response.keys()),
        },
    )

    return response