import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from typing import Any, Dict, Optional


# ============================================================
# 共通設定
# ============================================================

DB_PATH = os.getenv("CUSTOMER_DB_PATH", "app.db")
AUDIT_HASH_KEY = os.getenv("AUDIT_HASH_KEY", "change-me-in-production").encode("utf-8")

logger = logging.getLogger("customer_api_audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# ============================================================
# 例外
# ============================================================

class CustomerNotFound(Exception):
    pass


class AccessDenied(Exception):
    pass


class PrivacyGuardError(Exception):
    pass


# ============================================================
# DB接続
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L4: 制度的正統性 — 安全なログ記録と追跡
# ============================================================

def _hash_identifier(value: Any) -> str:
    """
    driver_id / customer_id などをログに直接出さず、HMACで追跡可能な形にする。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_HASH_KEY, raw, hashlib.sha256).hexdigest()


def _audit_log(event: str, trace_id: str, **kwargs: Any) -> None:
    """
    監査ログ。
    個人情報そのものは記録せず、IDはハッシュ化する。
    """
    safe_payload = {
        "event": event,
        "trace_id": trace_id,
    }

    for key, value in kwargs.items():
        if key.endswith("_id"):
            safe_payload[f"{key}_hash"] = _hash_identifier(value)
        else:
            safe_payload[key] = value

    logger.info(json.dumps(safe_payload, ensure_ascii=False, default=str))


# ============================================================
# L1: 業務運用 — データ内の個人情報をマスキング・検知
# ============================================================

PHONE_RE = re.compile(r"\+?\d[\d\-\s()]{7,}\d")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MY_NUMBER_LIKE_RE = re.compile(r"\b\d{12}\b")

PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "tel",
    "mobile",
    "email",
    "address",
    "birth_date",
    "emergency_contact_name",
    "emergency_contact_phone",
    "care_notes",
}


def _detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    レコード内にPIIらしき項目があるかをフィールド名・値から検知する。
    ログには値ではなくフィールド名のみを残す。
    """
    detected = []

    for key, value in record.items():
        key_lower = key.lower()
        text = "" if value is None else str(value)

        if key_lower in PII_FIELD_NAMES:
            detected.append(key)
            continue

        if PHONE_RE.search(text) or EMAIL_RE.search(text) or MY_NUMBER_LIKE_RE.search(text):
            detected.append(key)

    return sorted(set(detected))


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    return f"****-****-{digits[-4:]}"


def _mask_for_log(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ログ用のマスク済みデータ。
    実ログには原則としてレコード全体を出さないが、
    調査用に必要な場合でもこの関数を通す。
    """
    masked = {}

    for key, value in record.items():
        key_lower = key.lower()

        if value is None:
            masked[key] = None
        elif key_lower in {"phone", "tel", "mobile", "emergency_contact_phone"}:
            masked[key] = _mask_phone(str(value))
        elif key_lower in {"name", "full_name", "emergency_contact_name"}:
            masked[key] = "***"
        elif key_lower in {"address"}:
            masked[key] = "[address_masked]"
        elif key_lower in {"email"}:
            masked[key] = "[email_masked]"
        elif key_lower in {"birth_date"}:
            masked[key] = "[birth_date_masked]"
        elif key_lower in {"care_notes"}:
            masked[key] = "[care_notes_masked]"
        else:
            masked[key] = value

    return masked


def _redact_free_text(text: Optional[str]) -> Optional[str]:
    """
    自由記述欄から電話番号・メール・マイナンバー風の値を除去。
    """
    if not text:
        return text

    text = PHONE_RE.sub("[phone_redacted]", text)
    text = EMAIL_RE.sub("[email_redacted]", text)
    text = MY_NUMBER_LIKE_RE.sub("[number_redacted]", text)
    return text


# ============================================================
# L2: AI監査 — サニタイズ関数による最小権限化
# ============================================================

def _sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに返してよい項目だけを allowlist で返す。
    DBレコードをそのまま返さない。
    """
    return {
        "customer_id": record["customer_id"],
        "name": record["name"],
        "phone_masked": _mask_phone(record.get("phone")),
        "address": record.get("address"),
        "last_checkin_at": record.get("last_checkin_at"),
        "risk_level": record.get("risk_level"),
        "status": record.get("status"),
        "care_notes_summary": _redact_free_text(record.get("care_notes")),
    }


# ============================================================
# L3: 人間介入 — 返却直前でのガード節によるチェック
# ============================================================

def _guard_before_return(
    response: Dict[str, Any],
    source_record: Dict[str, Any],
    driver_id: Any,
) -> None:
    """
    返却直前の最終チェック。
    - 担当ドライバー以外には返さない
    - 禁止フィールドが混入していないか確認
    - 自由記述に未サニタイズPIIが残っていないか確認
    """

    if str(source_record.get("assigned_driver_id")) != str(driver_id):
        raise AccessDenied("driver is not assigned to this customer")

    allowed_keys = {
        "customer_id",
        "name",
        "phone_masked",
        "address",
        "last_checkin_at",
        "risk_level",
        "status",
        "care_notes_summary",
    }

    forbidden_keys = set(response.keys()) - allowed_keys
    if forbidden_keys:
        raise PrivacyGuardError(f"forbidden fields in response: {sorted(forbidden_keys)}")

    explicitly_forbidden = {
        "phone",
        "email",
        "birth_date",
        "emergency_contact_name",
        "emergency_contact_phone",
        "assigned_driver_id",
        "internal_memo",
    }

    if explicitly_forbidden.intersection(response.keys()):
        raise PrivacyGuardError("explicitly forbidden field is included")

    care_notes_summary = response.get("care_notes_summary")
    if care_notes_summary:
        if PHONE_RE.search(care_notes_summary) or EMAIL_RE.search(care_notes_summary):
            raise PrivacyGuardError("unsanitized PII remains in care_notes_summary")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    想定テーブル: customers

    必要カラム例:
      - customer_id
      - assigned_driver_id
      - name
      - phone
      - address
      - last_checkin_at
      - risk_level
      - status
      - care_notes
    """

    trace_id = str(uuid.uuid4())

    _audit_log(
        "customer_get_started",
        trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    customer_id,
                    assigned_driver_id,
                    name,
                    phone,
                    address,
                    last_checkin_at,
                    risk_level,
                    status,
                    care_notes
                FROM customers
                WHERE customer_id = ?
                  AND assigned_driver_id = ?
                LIMIT 1
                """,
                (
                    customer_id,
                    driver_id,
                ),
            )

            row = cursor.fetchone()

        if row is None:
            _audit_log(
                "customer_get_not_found_or_denied",
                trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
            )
            raise CustomerNotFound("customer not found")

        record = dict(row)

        # L1: PII検知。値はログに出さず、検知されたフィールド名だけ記録。
        pii_fields = _detect_pii_fields(record)
        _audit_log(
            "customer_record_loaded",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            pii_fields=pii_fields,
        )

        # L2: allowlist方式で最小限の情報にサニタイズ。
        response = _sanitize_customer_for_driver(record)

        # L3: 返却直前の最終ガード。
        _guard_before_return(
            response=response,
            source_record=record,
            driver_id=driver_id,
        )

        # L4: 返却結果も値ではなくメタ情報だけを安全に記録。
        _audit_log(
            "customer_get_succeeded",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            returned_fields=sorted(response.keys()),
        )

        return response

    except Exception as exc:
        _audit_log(
            "customer_get_failed",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            error_type=type(exc).__name__,
        )
        raise