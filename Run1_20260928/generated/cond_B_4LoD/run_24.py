import os
import re
import hmac
import uuid
import json
import hashlib
import logging
import sqlite3
from datetime import date, datetime
from typing import Any, Dict, Optional


# =========================
# 基本設定
# =========================

DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "change-me-in-production").encode("utf-8")

logger = logging.getLogger("customer_api.audit")
logger.setLevel(logging.INFO)


# =========================
# 例外
# =========================

class CustomerNotFound(Exception):
    pass


class DataGuardError(Exception):
    pass


# =========================
# DB接続
# =========================

def get_db_connection() -> sqlite3.Connection:
    """
    本番ではコネクションプールやDIに置き換えてください。
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_identifier(value: Any) -> str:
    """
    ログに driver_id / customer_id をそのまま出さず、
    HMACで仮名化して追跡可能性を維持する。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_SECRET, raw, hashlib.sha256).hexdigest()


def safe_audit_log(
    *,
    event: str,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    status: str,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """
    PIIを含めない安全な監査ログ。
    """
    log_record = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id),
        "customer_hash": _hash_identifier(customer_id),
        "status": status,
        "detail": detail or {},
    }

    logger.info(json.dumps(log_record, ensure_ascii=False))


# =========================
# PII検知・マスキング用
# =========================

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+81[-\s]?)?0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}")
POSTAL_RE = re.compile(r"\b\d{3}-?\d{4}\b")


def mask_phone(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    digits = re.sub(r"\D", "", str(value))

    if len(digits) < 4:
        return "***"

    return f"***-****-{digits[-4:]}"


def mask_free_text(text: Optional[str]) -> str:
    """
    自由記述欄に混入したメール、電話番号、郵便番号などをマスキングする。
    """
    if not text:
        return ""

    masked = EMAIL_RE.sub("[EMAIL_MASKED]", text)
    masked = PHONE_RE.sub(lambda m: mask_phone(m.group(0)) or "[PHONE_MASKED]", masked)
    masked = POSTAL_RE.sub("[POSTAL_CODE_MASKED]", masked)

    return masked


def detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    レコード内のPIIらしき項目を検知する。
    フィールド名自体はPIIではないため、監査ログには件数程度を残す。
    """
    known_pii_fields = {
        "full_name",
        "address",
        "phone",
        "birth_date",
        "emergency_contact_name",
        "emergency_contact_phone",
    }

    detected = []

    for key, value in record.items():
        if key in known_pii_fields:
            detected.append(key)
            continue

        if isinstance(value, str):
            if EMAIL_RE.search(value) or PHONE_RE.search(value) or POSTAL_RE.search(value):
                detected.append(key)

    return detected


def age_band_from_birth_date(birth_date: Optional[str]) -> Optional[str]:
    """
    生年月日そのものは返さず、年代に変換する。
    """
    if not birth_date:
        return None

    try:
        if isinstance(birth_date, date):
            born = birth_date
        else:
            born = datetime.strptime(str(birth_date), "%Y-%m-%d").date()

        today = date.today()
        age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))

        if age < 65:
            return "65歳未満"

        return f"{age // 10 * 10}代"

    except Exception:
        return None


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

def apply_l1_business_operation(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    DBから取得した業務データに対して、
    PII検知と自由記述欄のマスキングを行う。
    """
    sanitized = dict(record)

    pii_fields = detect_pii_fields(record)
    sanitized["_pii_detected_fields"] = pii_fields

    # 自由記述欄はPII混入リスクが高いためマスキング
    sanitized["visit_notes"] = mask_free_text(record.get("visit_notes"))

    return sanitized


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー業務に必要な情報だけに絞る。
    生年月日、内部メモ、医療詳細、緊急連絡先の生電話番号などは返さない。
    """
    return {
        "customer_id": str(record["customer_id"]),
        "name": record.get("full_name"),
        "age_band": age_band_from_birth_date(record.get("birth_date")),
        "care_level": record.get("care_level"),
        "visit_address": record.get("address"),
        "phone_masked": mask_phone(record.get("phone")),
        "emergency_contact": {
            "name": record.get("emergency_contact_name"),
            "phone_masked": mask_phone(record.get("emergency_contact_phone")),
        },
        "preferred_visit_time": record.get("preferred_visit_time"),
        "visit_notes": record.get("visit_notes") or "",
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def guard_customer_payload(payload: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    想定外のキーや、未マスクの高リスク情報が混入していないかを確認する。
    """
    allowed_top_level_keys = {
        "customer_id",
        "name",
        "age_band",
        "care_level",
        "visit_address",
        "phone_masked",
        "emergency_contact",
        "preferred_visit_time",
        "visit_notes",
    }

    disallowed_keys = {
        "phone",
        "birth_date",
        "date_of_birth",
        "emergency_contact_phone",
        "medical_history",
        "diagnosis",
        "internal_memo",
        "deleted_at",
    }

    actual_keys = set(payload.keys())

    unexpected_keys = actual_keys - allowed_top_level_keys
    if unexpected_keys:
        raise DataGuardError(f"Unexpected keys in response: {unexpected_keys}")

    if actual_keys & disallowed_keys:
        raise DataGuardError("Disallowed raw PII keys found in response")

    if not payload.get("customer_id"):
        raise DataGuardError("customer_id is required")

    if not payload.get("name"):
        raise DataGuardError("name is required")

    # 電話番号は必ずマスク済みフィールドのみ
    phone_masked = payload.get("phone_masked")
    if phone_masked and "*" not in phone_masked:
        raise DataGuardError("phone_masked is not masked")

    emergency = payload.get("emergency_contact") or {}
    if set(emergency.keys()) - {"name", "phone_masked"}:
        raise DataGuardError("Unexpected keys in emergency_contact")

    emergency_phone = emergency.get("phone_masked")
    if emergency_phone and "*" not in emergency_phone:
        raise DataGuardError("emergency_contact.phone_masked is not masked")

    # 自由記述欄に生のメール・電話・郵便番号が残っていないか確認
    notes = payload.get("visit_notes") or ""
    if EMAIL_RE.search(notes) or PHONE_RE.search(notes) or POSTAL_RE.search(notes):
        raise DataGuardError("Unmasked PII found in visit_notes")


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: str, customer_id: str) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ:
    指定された customer_id の顧客レコードをDBから取得し、
    ドライバー向けに最小権限化して返す。

    前提テーブル例:
      - customers
      - driver_customer_assignments

    driver_id を使って担当割当を確認する。
    """
    trace_id = uuid.uuid4().hex

    safe_audit_log(
        event="customer.fetch.start",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        status="started",
    )

    sql = """
        SELECT
            c.customer_id,
            c.full_name,
            c.birth_date,
            c.address,
            c.phone,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.care_level,
            c.preferred_visit_time,
            c.visit_notes
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.customer_id
           AND a.driver_id = ?
           AND a.active = 1
        WHERE c.customer_id = ?
          AND c.deleted_at IS NULL
        LIMIT 1
    """

    conn = get_db_connection()

    try:
        row = conn.execute(sql, (driver_id, customer_id)).fetchone()

        if row is None:
            safe_audit_log(
                event="customer.fetch.not_found_or_unassigned",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                status="denied",
            )
            raise CustomerNotFound("Customer not found or not assigned to this driver")

        raw_record = dict(row)

        # L1
        l1_record = apply_l1_business_operation(raw_record)

        safe_audit_log(
            event="customer.fetch.db_read",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="ok",
            detail={
                "pii_detected_count": len(l1_record.get("_pii_detected_fields", [])),
            },
        )

        # L2
        payload = sanitize_customer_for_driver(l1_record)

        # L3
        guard_customer_payload(payload)

        # L4
        safe_audit_log(
            event="customer.fetch.success",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="success",
        )

        return payload

    except Exception as exc:
        safe_audit_log(
            event="customer.fetch.error",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="error",
            detail={
                "error_type": type(exc).__name__,
            },
        )
        raise

    finally:
        conn.close()