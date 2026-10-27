import os
import re
import hmac
import json
import uuid
import sqlite3
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List


DB_PATH = os.environ.get("DB_PATH", "app.db")

# 本番では必ず十分に長い秘密値を環境変数で設定してください
AUDIT_HASH_KEY = os.environ.get("AUDIT_HASH_KEY", "change-me-in-production").encode("utf-8")

logger = logging.getLogger("customer_api")
logging.basicConfig(level=logging.INFO)


class CustomerNotFound(Exception):
    pass


class AccessDenied(Exception):
    pass


class PolicyViolation(Exception):
    pass


# ============================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# - driver_id / customer_id は生値でログに出さず HMAC ハッシュ化
# - trace_id により監査追跡可能
# - PII をログに出さない
# ============================================================

def _hash_identifier(value: Any) -> str:
    return hmac.new(
        AUDIT_HASH_KEY,
        str(value).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def audit_log(
    event: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    trace_id: str,
    details: Dict[str, Any] | None = None,
) -> None:
    log_record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "trace_id": trace_id,
        "event": event,
        "actor_type": "driver",
        "driver_ref": _hash_identifier(driver_id),
        "customer_ref": _hash_identifier(customer_id),
        "result": result,
    }

    if details:
        log_record["details"] = _mask_pii_in_object(details)

    logger.info(json.dumps(log_record, ensure_ascii=False))


# ============================================================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# - DB から取得したレコードに PII が含まれるか検知
# - 運用ログ等にはマスキング済みデータのみ利用
# ============================================================

PHONE_RE = re.compile(r"(\+?\d[\d\- ]{7,}\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "email",
    "address",
    "emergency_contact",
    "emergency_contact_phone",
    "medical_notes",
}


def _detect_pii_fields(record: Dict[str, Any]) -> List[str]:
    detected = []

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            detected.append(key)
            continue

        if isinstance(value, str):
            if PHONE_RE.search(value) or EMAIL_RE.search(value):
                detected.append(key)

    return sorted(set(detected))


def _mask_string(value: str) -> str:
    value = EMAIL_RE.sub("***@***", value)
    value = PHONE_RE.sub("***-****-****", value)

    if len(value) <= 2:
        return "*"

    return value[0] + "*" * max(len(value) - 2, 1) + value[-1]


def _mask_pii_in_object(obj: Any) -> Any:
    if isinstance(obj, dict):
        masked = {}
        for key, value in obj.items():
            if key.lower() in PII_FIELD_NAMES:
                masked[key] = _mask_pii_in_object(value)
            else:
                masked[key] = _mask_pii_in_object(value)
        return masked

    if isinstance(obj, list):
        return [_mask_pii_in_object(v) for v in obj]

    if isinstance(obj, str):
        if PHONE_RE.search(obj) or EMAIL_RE.search(obj):
            return _mask_string(obj)
        return obj

    return obj


def _mask_record_for_operations(record: Dict[str, Any]) -> Dict[str, Any]:
    masked = {}

    for key, value in record.items():
        if key.lower() in PII_FIELD_NAMES:
            if isinstance(value, str):
                masked[key] = _mask_string(value)
            else:
                masked[key] = "***"
        else:
            masked[key] = value

    return masked


# ============================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# - DB レコード全体をそのまま返さない
# - ドライバー業務に必要な最小限の項目だけ返す
# ============================================================

ALLOWED_RESPONSE_KEYS = {
    "customer_id",
    "name",
    "phone",
    "address",
    "care_status",
}

DENIED_RESPONSE_KEYS = {
    "medical_notes",
    "emergency_contact",
    "emergency_contact_phone",
    "date_of_birth",
    "email",
    "created_at",
    "updated_at",
    "deleted_at",
}


def _sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "customer_id": record["id"],
        "name": record["full_name"],
        "phone": record["phone"],
        "address": record["address"],
        "care_status": record["care_status"],
    }


# ============================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# - 返却データのスキーマを allowlist で確認
# - 禁止項目が混入していないことを確認
# - requested customer_id と返却 customer_id の一致確認
# ============================================================

def _guard_before_return(
    payload: Dict[str, Any],
    requested_customer_id: int,
) -> None:
    payload_keys = set(payload.keys())

    unexpected_keys = payload_keys - ALLOWED_RESPONSE_KEYS
    if unexpected_keys:
        raise PolicyViolation(f"Unexpected response keys: {sorted(unexpected_keys)}")

    denied_keys = payload_keys & DENIED_RESPONSE_KEYS
    if denied_keys:
        raise PolicyViolation(f"Denied response keys detected: {sorted(denied_keys)}")

    if payload.get("customer_id") != requested_customer_id:
        raise PolicyViolation("Customer ID mismatch before return")

    required_keys = {"customer_id", "name", "address", "care_status"}
    missing_keys = required_keys - payload_keys
    if missing_keys:
        raise PolicyViolation(f"Missing required keys: {sorted(missing_keys)}")


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _validate_positive_int(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(f"{field_name} must be an integer")

    if parsed <= 0:
        raise ValueError(f"{field_name} must be positive")

    return parsed


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id, customer_id) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    driver_id に割り当てられている customer_id の顧客情報のみ取得し、
    ドライバー業務に必要な最小限の情報だけ返す。
    """

    trace_id = str(uuid.uuid4())

    driver_id = _validate_positive_int(driver_id, "driver_id")
    customer_id = _validate_positive_int(customer_id, "customer_id")

    audit_log(
        event="customer.get.start",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
        trace_id=trace_id,
    )

    try:
        with _get_connection() as conn:
            row = conn.execute(
                """
                SELECT
                    c.id,
                    c.full_name,
                    c.phone,
                    c.address,
                    c.care_status,
                    c.medical_notes,
                    c.emergency_contact_phone,
                    c.email,
                    c.created_at,
                    c.updated_at
                FROM customers c
                INNER JOIN driver_customer_assignments dca
                    ON dca.customer_id = c.id
                WHERE
                    c.id = ?
                    AND dca.driver_id = ?
                    AND dca.active = 1
                    AND c.deleted_at IS NULL
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            audit_log(
                event="customer.get.not_found_or_denied",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied_or_not_found",
                trace_id=trace_id,
            )
            raise CustomerNotFound("Customer not found or access denied")

        raw_record = dict(row)

        # L1: PII検知
        pii_fields = _detect_pii_fields(raw_record)

        # L1: 運用確認用にはマスク済みデータだけを扱う
        masked_record = _mask_record_for_operations(raw_record)

        audit_log(
            event="customer.get.loaded",
            driver_id=driver_id,
            customer_id=customer_id,
            result="loaded",
            trace_id=trace_id,
            details={
                "pii_fields_detected": pii_fields,
                "masked_record_keys": list(masked_record.keys()),
            },
        )

        # L2: 最小権限化
        response_payload = _sanitize_customer_for_driver(raw_record)

        # L3: 返却直前のガード節
        _guard_before_return(
            payload=response_payload,
            requested_customer_id=customer_id,
        )

        # L4: 監査ログ
        audit_log(
            event="customer.get.success",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
            trace_id=trace_id,
            details={
                "returned_fields": sorted(response_payload.keys()),
            },
        )

        return response_payload

    except Exception as exc:
        audit_log(
            event="customer.get.failure",
            driver_id=driver_id,
            customer_id=customer_id,
            result="failure",
            trace_id=trace_id,
            details={
                "error_type": type(exc).__name__,
            },
        )
        raise