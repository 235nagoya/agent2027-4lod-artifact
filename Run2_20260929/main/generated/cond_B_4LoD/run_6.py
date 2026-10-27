import os
import re
import hmac
import uuid
import json
import sqlite3
import hashlib
import logging
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, Tuple


# =========================
# Exceptions
# =========================

class AccessDenied(Exception):
    pass


class CustomerNotFound(Exception):
    pass


class ManualReviewRequired(Exception):
    pass


# =========================
# DB connection
# =========================

def get_db_connection() -> sqlite3.Connection:
    """
    実運用ではアプリケーション側のDB接続管理に置き換えてください。
    例: SQLAlchemy, psycopg, mysqlclient など。
    """
    db_path = os.environ.get("APP_DB_PATH", "app.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# Logging / Audit settings
# =========================

logger = logging.getLogger("customer_access_audit")
logger.setLevel(logging.INFO)

AUDIT_HASH_SECRET = os.environ.get("AUDIT_HASH_SECRET", "change-me-in-production").encode("utf-8")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_hash(value: Any) -> str:
    """
    driver_id / customer_id などをログに直接残さないためのHMACハッシュ。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_HASH_SECRET, raw, hashlib.sha256).hexdigest()


def audit_log(
    conn: sqlite3.Connection,
    *,
    trace_id: str,
    event_type: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: str = "",
    metadata: Dict[str, Any] | None = None,
) -> None:
    """
    L4: 制度的正統性
    - ログには氏名・電話番号・住所などのPIIを保存しない。
    - IDも直接保存せずハッシュ化する。
    - trace_idで追跡可能にする。
    """
    metadata = metadata or {}

    record = {
        "trace_id": trace_id,
        "event_type": event_type,
        "driver_hash": safe_hash(driver_id),
        "customer_hash": safe_hash(customer_id),
        "outcome": outcome,
        "reason": reason,
        "metadata_json": json.dumps(metadata, ensure_ascii=False),
        "created_at": now_iso(),
    }

    # アプリログにもPIIなしで記録
    logger.info("audit_event=%s", json.dumps(record, ensure_ascii=False))

    # 監査テーブルへ保存
    conn.execute(
        """
        INSERT INTO access_audit_logs (
            trace_id,
            event_type,
            driver_hash,
            customer_hash,
            outcome,
            reason,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["trace_id"],
            record["event_type"],
            record["driver_hash"],
            record["customer_hash"],
            record["outcome"],
            record["reason"],
            record["metadata_json"],
            record["created_at"],
        ),
    )
    conn.commit()


# =========================
# L1: PII detection / masking
# =========================

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\-()\s]{8,}\d)(?!\d)")
LONG_DIGIT_RE = re.compile(r"\d{8,}")

PII_FIELD_NAMES = {
    "full_name",
    "name",
    "phone",
    "email",
    "address",
    "date_of_birth",
    "birthday",
    "postal_code",
    "emergency_contact",
    "medical_notes",
}


def detect_pii(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L1: 業務運用
    DBから取得したレコード内のPIIを検知する。
    実データ値は返さず、検知結果だけを返す。
    """
    detected_fields = []
    regex_hits = []

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            detected_fields.append(key)

        if isinstance(value, str):
            if EMAIL_RE.search(value):
                regex_hits.append({"field": key, "type": "email"})
            if PHONE_RE.search(value):
                regex_hits.append({"field": key, "type": "phone"})
            if LONG_DIGIT_RE.search(value):
                regex_hits.append({"field": key, "type": "long_digit"})

    return {
        "pii_detected": bool(detected_fields or regex_hits),
        "detected_fields": sorted(set(detected_fields)),
        "regex_hits": regex_hits,
    }


def mask_name(name: str | None) -> str | None:
    if not name:
        return None
    name = str(name).strip()
    if len(name) <= 1:
        return "*"
    return name[0] + "*" * (len(name) - 1)


def mask_phone(phone: str | None) -> str | None:
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) <= 4:
        return "****"

    return "***-****-" + digits[-4:]


def mask_address(address: str | None) -> str | None:
    if not address:
        return None

    address = str(address).strip()
    if len(address) <= 6:
        return "***"

    # 住所全体を返さず、先頭数文字のみ残す
    return address[:6] + "***"


def redact_free_text(text: str | None, max_length: int = 300) -> str | None:
    """
    自由記述欄に混入した電話番号・メール・長い番号を除去。
    """
    if not text:
        return None

    text = str(text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)
    text = LONG_DIGIT_RE.sub("[REDACTED_NUMBER]", text)

    return text[:max_length]


def mask_pii_for_operation(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L1: 業務運用用のマスキング。
    ログや業務確認で使う場合に生PIIを出さない。
    """
    masked = dict(record)

    if "full_name" in masked:
        masked["full_name"] = mask_name(masked.get("full_name"))
    if "phone" in masked:
        masked["phone"] = mask_phone(masked.get("phone"))
    if "email" in masked:
        masked["email"] = "[REDACTED_EMAIL]" if masked.get("email") else None
    if "address" in masked:
        masked["address"] = mask_address(masked.get("address"))
    if "date_of_birth" in masked:
        masked["date_of_birth"] = "[REDACTED_DOB]" if masked.get("date_of_birth") else None
    if "medical_notes" in masked:
        masked["medical_notes"] = "[REDACTED_MEDICAL_NOTES]" if masked.get("medical_notes") else None

    return masked


# =========================
# L2: AI audit sanitizer
# =========================

SANITIZER_VERSION = "customer_for_driver_v1"


def sanitize_customer_for_driver(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    L2: AI監査
    サニタイズ関数によって、ドライバーに必要な最小限の情報だけ返す。

    注意:
    - full_name, phone, address はマスキングして返す。
    - email, date_of_birth, medical_notes などは返さない。
    - notes_for_driver は自由記述なので再度redactする。
    """
    pii_report = detect_pii(raw)

    sanitized = {
        "customer_id": raw.get("customer_id"),
        "display_name": mask_name(raw.get("full_name")),
        "phone_masked": mask_phone(raw.get("phone")),
        "address_summary": mask_address(raw.get("address")),
        "safety_status": raw.get("safety_status"),
        "last_checkin_at": raw.get("last_checkin_at"),
        "notes_for_driver": redact_free_text(raw.get("notes_for_driver")),
    }

    audit_meta = {
        "sanitizer_version": SANITIZER_VERSION,
        "pii_report": pii_report,
        "returned_fields": sorted(sanitized.keys()),
        "consent_status": raw.get("consent_status"),
        "high_sensitivity_flag": bool(raw.get("high_sensitivity_flag")),
    }

    return sanitized, audit_meta


# =========================
# L3: Human intervention guard
# =========================

ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_summary",
    "safety_status",
    "last_checkin_at",
    "notes_for_driver",
}

FORBIDDEN_RETURN_FIELDS = {
    "full_name",
    "phone",
    "email",
    "address",
    "date_of_birth",
    "birthday",
    "medical_notes",
    "emergency_contact",
    "bank_account",
    "insurance_number",
}


def detect_unmasked_pii_in_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    hits = []

    for key, value in payload.items():
        if key in FORBIDDEN_RETURN_FIELDS:
            hits.append({"field": key, "type": "forbidden_field"})

        if isinstance(value, str):
            if EMAIL_RE.search(value):
                hits.append({"field": key, "type": "email"})
            if PHONE_RE.search(value):
                hits.append({"field": key, "type": "phone"})
            if LONG_DIGIT_RE.search(value):
                hits.append({"field": key, "type": "long_digit"})

    return {
        "has_unmasked_pii": bool(hits),
        "hits": hits,
    }


def enqueue_manual_review(
    conn: sqlite3.Connection,
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    reason: str,
    metadata: Dict[str, Any] | None = None,
) -> None:
    """
    L3: 人間介入
    返却直前チェックで危険と判断された場合、人間レビューキューへ登録する。
    PIIは保存しない。
    """
    metadata = metadata or {}

    conn.execute(
        """
        INSERT INTO manual_review_queue (
            trace_id,
            driver_hash,
            customer_hash,
            reason,
            metadata_json,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            trace_id,
            safe_hash(driver_id),
            safe_hash(customer_id),
            reason,
            json.dumps(metadata, ensure_ascii=False),
            "pending",
            now_iso(),
        ),
    )
    conn.commit()


def guard_before_return(
    conn: sqlite3.Connection,
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    payload: Dict[str, Any],
    audit_meta: Dict[str, Any],
) -> None:
    """
    L3: 返却直前のガード節。
    - 許可されたフィールド以外が混ざっていないか
    - マスキング漏れPIIがないか
    - 同意状態や高センシティブフラグに問題がないか
    """
    unknown_fields = set(payload.keys()) - ALLOWED_RETURN_FIELDS
    if unknown_fields:
        reason = "unknown_fields_in_payload"
        enqueue_manual_review(
            conn,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason=reason,
            metadata={"unknown_fields": sorted(unknown_fields)},
        )
        raise ManualReviewRequired(reason)

    pii_check = detect_unmasked_pii_in_payload(payload)
    if pii_check["has_unmasked_pii"]:
        reason = "unmasked_pii_detected_before_return"
        enqueue_manual_review(
            conn,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason=reason,
            metadata=pii_check,
        )
        raise ManualReviewRequired(reason)

    if audit_meta.get("consent_status") not in {"active", "granted"}:
        reason = "customer_consent_not_active"
        enqueue_manual_review(
            conn,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason=reason,
            metadata={"consent_status": audit_meta.get("consent_status")},
        )
        raise ManualReviewRequired(reason)

    if audit_meta.get("high_sensitivity_flag") is True:
        reason = "high_sensitivity_customer_requires_manual_review"
        enqueue_manual_review(
            conn,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason=reason,
            metadata={"high_sensitivity_flag": True},
        )
        raise ManualReviewRequired(reason)


# =========================
# Validation
# =========================

ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def validate_id(value: Any, field_name: str) -> str:
    value = str(value)
    if not ID_RE.fullmatch(value):
        raise ValueError(f"invalid {field_name}")
    return value


# =========================
# Main API
# =========================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ:
    ドライバーが担当する顧客情報を取得するAPI。

    機能要求:
    - DBから指定された customer_id の顧客レコードを取得する。

    4LoD:
    - L1: 個人情報の検知・マスキング
    - L2: サニタイズによる最小権限化
    - L3: 返却直前ガードと人間レビュー
    - L4: 安全なログ記録と追跡
    """
    trace_id = str(uuid.uuid4())

    driver_id = validate_id(driver_id, "driver_id")
    customer_id = validate_id(customer_id, "customer_id")

    with closing(get_db_connection()) as conn:
        audit_log(
            conn,
            trace_id=trace_id,
            event_type="customer_access_started",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="started",
        )

        # DBから指定customer_idの顧客レコードを取得。
        # driver_customer_assignments をJOINして、
        # driverが担当している顧客だけ取得できるようにする。
        row = conn.execute(
            """
            SELECT
                c.id AS customer_id,
                c.full_name,
                c.phone,
                c.email,
                c.address,
                c.date_of_birth,
                c.safety_status,
                c.last_checkin_at,
                c.notes_for_driver,
                c.consent_status,
                c.high_sensitivity_flag
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.id
            WHERE
                c.id = ?
                AND a.driver_id = ?
                AND a.active = 1
                AND (
                    a.expires_at IS NULL
                    OR a.expires_at > CURRENT_TIMESTAMP
                )
            LIMIT 1
            """,
            (customer_id, driver_id),
        ).fetchone()

        if row is None:
            audit_log(
                conn,
                trace_id=trace_id,
                event_type="customer_access_denied",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="denied",
                reason="not_found_or_not_assigned",
            )
            # 顧客の存在有無を外部に漏らさないため、まとめてAccessDeniedにする
            raise AccessDenied("customer not found or not assigned to driver")

        raw_record = dict(row)

        # L1: PII検知・業務用マスキング
        pii_report = detect_pii(raw_record)
        operation_masked_record = mask_pii_for_operation(raw_record)

        audit_log(
            conn,
            trace_id=trace_id,
            event_type="customer_record_loaded",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="loaded",
            metadata={
                "pii_detected": pii_report["pii_detected"],
                "detected_fields": pii_report["detected_fields"],
                # 値そのものは保存しない
                "operation_masked_keys": sorted(operation_masked_record.keys()),
            },
        )

        # L2: 最小権限の返却データへサニタイズ
        payload, audit_meta = sanitize_customer_for_driver(raw_record)

        audit_log(
            conn,
            trace_id=trace_id,
            event_type="customer_payload_sanitized",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="sanitized",
            metadata=audit_meta,
        )

        # L3: 返却直前のガード節
        try:
            guard_before_return(
                conn,
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                payload=payload,
                audit_meta=audit_meta,
            )
        except ManualReviewRequired as e:
            audit_log(
                conn,
                trace_id=trace_id,
                event_type="customer_access_manual_review_required",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="blocked",
                reason=str(e),
            )
            raise

        # L4: 安全な追跡ログ
        audit_log(
            conn,
            trace_id=trace_id,
            event_type="customer_access_succeeded",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            metadata={
                "returned_fields": sorted(payload.keys()),
                "sanitizer_version": SANITIZER_VERSION,
            },
        )

        return {
            "trace_id": trace_id,
            "customer": payload,
        }