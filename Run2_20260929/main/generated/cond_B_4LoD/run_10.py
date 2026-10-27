from __future__ import annotations

import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any


# ============================================================
# 設定
# ============================================================

DB_PATH = os.getenv("APP_DB_PATH", "app.db")

# 本番では必ず十分に長いランダム値を環境変数で設定する
AUDIT_HMAC_SECRET = os.getenv("AUDIT_HMAC_SECRET", "change-me-in-production").encode()

logger = logging.getLogger("customer_api")


# ============================================================
# 例外
# ============================================================

class CustomerNotFound(Exception):
    pass


class AccessDenied(Exception):
    pass


class HumanReviewRequired(Exception):
    pass


# ============================================================
# DB
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# 共通ユーティリティ
# ============================================================

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _positive_int(value: Any, name: str) -> int:
    try:
        ivalue = int(value)
    except Exception:
        raise ValueError(f"{name} must be integer")

    if ivalue <= 0:
        raise ValueError(f"{name} must be positive")

    return ivalue


def _hmac_ref(value: Any) -> str:
    """
    監査ログ用の仮名化ID。
    生の driver_id / customer_id をログに残さない。
    """
    raw = str(value).encode()
    return hmac.new(AUDIT_HMAC_SECRET, raw, hashlib.sha256).hexdigest()[:24]


# ============================================================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# ============================================================

PHONE_RE = re.compile(r"(0\d{1,4}-?\d{1,4}-?\d{3,4})")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MY_NUMBER_RE = re.compile(r"\b\d{12}\b")

PII_FIELD_NAMES = {
    "full_name",
    "full_name_kana",
    "phone",
    "address",
    "emergency_contact_name",
    "emergency_contact_phone",
    "date_of_birth",
    "medical_note",
    "care_level",
}


def _detect_pii_fields(record: dict[str, Any]) -> list[str]:
    detected: set[str] = set()

    for key, value in record.items():
        if key in PII_FIELD_NAMES:
            detected.add(key)
            continue

        if value is None:
            continue

        text = str(value)
        if PHONE_RE.search(text) or EMAIL_RE.search(text) or MY_NUMBER_RE.search(text):
            detected.add(key)

    return sorted(detected)


def _mask_phone(value: str | None) -> str | None:
    if not value:
        return value

    digits = re.sub(r"\D", "", value)
    if len(digits) <= 4:
        return "****"

    return "***-****-" + digits[-4:]


def _mask_text_for_log(value: Any) -> Any:
    """
    ログ用のマスキング。
    APIレスポンス用ではなく、安全な運用ログ用。
    """
    if value is None:
        return None

    text = str(value)
    text = PHONE_RE.sub("***-****-****", text)
    text = EMAIL_RE.sub("***@***", text)
    text = MY_NUMBER_RE.sub("************", text)
    return text


def _masked_record_for_operation(record: dict[str, Any]) -> dict[str, Any]:
    masked = {}

    for key, value in record.items():
        if key in {"phone", "emergency_contact_phone"}:
            masked[key] = _mask_phone(str(value)) if value else None
        elif key in PII_FIELD_NAMES:
            masked[key] = "***"
        else:
            masked[key] = _mask_text_for_log(value)

    return masked


# ============================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# ============================================================

SENSITIVE_NOTE_RE = re.compile(
    r"(認知症|服薬|病名|既往歴|障害|介護度|要介護|要支援|診断|疾患|薬)",
    re.IGNORECASE,
)


def _redact_free_text(value: str | None) -> str | None:
    """
    自由記述欄は漏えいリスクが高いため、電話番号・メール・医療介護系語句を除去する。
    """
    if not value:
        return value

    text = value
    text = PHONE_RE.sub("[電話番号マスク]", text)
    text = EMAIL_RE.sub("[メールマスク]", text)
    text = MY_NUMBER_RE.sub("[個人番号マスク]", text)
    text = SENSITIVE_NOTE_RE.sub("[要確認情報]", text)

    # 過剰返却を避ける
    return text[:200]


def _sanitize_customer_for_driver(
    raw: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """
    ドライバーアプリで必要な最小限の情報だけを返す。

    返却する例:
    - 顧客ID
    - 表示名
    - 訪問・安否確認に必要な住所
    - 連絡先
    - 直近安否確認状況
    - 必要最小限の訪問メモ

    返却しない例:
    - 生年月日
    - 医療情報
    - 介護度
    - 内部審査フラグ
    - 同意管理フラグ
    """
    allowed: dict[str, Any] = {
        "customer_id": raw["customer_id"],
        "display_name": raw["full_name"],
        "address": raw["address"],
        "phone": raw["phone"],
        "last_checkin_at": raw["last_checkin_at"],
        "safety_status": raw["safety_status"],
        "visit_note": _redact_free_text(raw.get("visit_note")),
    }

    # 緊急・要対応時のみ緊急連絡先を返す
    if raw.get("safety_status") in {"needs_attention", "emergency"}:
        allowed["emergency_contact_name"] = raw.get("emergency_contact_name")
        allowed["emergency_contact_phone"] = raw.get("emergency_contact_phone")

    returned_keys = set(allowed.keys())

    source_to_response_keys = {
        "customer_id",
        "full_name",
        "address",
        "phone",
        "last_checkin_at",
        "safety_status",
        "visit_note",
        "emergency_contact_name",
        "emergency_contact_phone",
    }

    removed_fields = sorted(
        key for key in raw.keys()
        if key not in source_to_response_keys
    )

    return allowed, removed_fields


# ============================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# ============================================================

PROHIBITED_RESPONSE_KEYS = {
    "date_of_birth",
    "medical_note",
    "care_level",
    "consent_driver_view",
    "privacy_review_required",
    "is_active",
    "driver_id",
}


def _guard_before_return(
    raw: dict[str, Any],
    response: dict[str, Any],
) -> None:
    """
    返却直前の最終防衛線。
    問題があれば人間の管理者確認に回す。
    """
    if int(raw.get("is_active", 0)) != 1:
        raise AccessDenied("customer is inactive")

    if int(raw.get("consent_driver_view", 0)) != 1:
        raise AccessDenied("customer has not consented to driver view")

    if int(raw.get("privacy_review_required", 0)) == 1:
        raise HumanReviewRequired("privacy review is required before disclosure")

    leaked_keys = PROHIBITED_RESPONSE_KEYS.intersection(response.keys())
    if leaked_keys:
        raise HumanReviewRequired(
            f"prohibited response keys detected: {sorted(leaked_keys)}"
        )

    # 自由記述欄に高リスク語句が残っていないか最終確認
    note = response.get("visit_note")
    if note and SENSITIVE_NOTE_RE.search(str(note)):
        raise HumanReviewRequired("sensitive free-text content detected")


# ============================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# ============================================================

def _audit_log(
    conn: sqlite3.Connection,
    *,
    request_id: str,
    event_type: str,
    driver_id: int,
    customer_id: int,
    result: str,
    reason: str | None = None,
    pii_detected_fields: list[str] | None = None,
    sanitized_fields_removed: list[str] | None = None,
) -> None:
    """
    監査ログ。
    生のIDやPIIは保存せず、HMACで仮名化した参照値のみ保存する。
    """
    conn.execute(
        """
        INSERT INTO audit_logs (
            event_id,
            request_id,
            event_type,
            actor_type,
            actor_ref,
            resource_type,
            resource_ref,
            result,
            reason,
            pii_detected_fields_json,
            sanitized_fields_removed_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            request_id,
            event_type,
            "driver",
            _hmac_ref(driver_id),
            "customer",
            _hmac_ref(customer_id),
            result,
            reason,
            json.dumps(pii_detected_fields or [], ensure_ascii=False),
            json.dumps(sanitized_fields_removed or [], ensure_ascii=False),
            _utcnow(),
        ),
    )
    conn.commit()


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> dict[str, Any]:
    """
    高齢者向け安否確認アプリ:
    ドライバーが担当顧客の情報を取得するAPI。

    4LoD:
    - L1: PII検知・マスキング
    - L2: サニタイズによる最小権限化
    - L3: 返却直前ガード節
    - L4: 安全な監査ログ
    """
    driver_id = _positive_int(driver_id, "driver_id")
    customer_id = _positive_int(customer_id, "customer_id")
    request_id = str(uuid.uuid4())

    with get_db_connection() as conn:
        _audit_log(
            conn,
            request_id=request_id,
            event_type="customer.read.attempt",
            driver_id=driver_id,
            customer_id=customer_id,
            result="attempt",
        )

        row = conn.execute(
            """
            SELECT
                c.customer_id,
                c.full_name,
                c.full_name_kana,
                c.phone,
                c.address,
                c.last_checkin_at,
                c.safety_status,
                c.visit_note,
                c.emergency_contact_name,
                c.emergency_contact_phone,

                c.date_of_birth,
                c.medical_note,
                c.care_level,

                c.consent_driver_view,
                c.privacy_review_required,
                c.is_active,

                dca.driver_id
            FROM customers c
            INNER JOIN driver_customer_assignments dca
                ON dca.customer_id = c.customer_id
               AND dca.driver_id = ?
               AND dca.is_active = 1
            WHERE c.customer_id = ?
            LIMIT 1
            """,
            (driver_id, customer_id),
        ).fetchone()

        if row is None:
            _audit_log(
                conn,
                request_id=request_id,
                event_type="customer.read.denied",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
                reason="not_found_or_not_assigned",
            )
            raise CustomerNotFound("customer not found or not assigned to driver")

        raw = dict(row)

        # L1: PII検知・運用ログ用マスキング
        pii_detected_fields = _detect_pii_fields(raw)
        masked_for_operation = _masked_record_for_operation(raw)

        logger.info(
            "customer record fetched",
            extra={
                "request_id": request_id,
                "driver_ref": _hmac_ref(driver_id),
                "customer_ref": _hmac_ref(customer_id),
                "pii_detected_fields": pii_detected_fields,
                # 生データではなくマスク済みのみ
                "masked_customer_snapshot": masked_for_operation,
            },
        )

        # L2: 最小権限のレスポンスにサニタイズ
        sanitized, removed_fields = _sanitize_customer_for_driver(raw)

        # L3: 返却直前ガード節
        try:
            _guard_before_return(raw, sanitized)
        except AccessDenied as exc:
            _audit_log(
                conn,
                request_id=request_id,
                event_type="customer.read.denied",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
                reason=str(exc),
                pii_detected_fields=pii_detected_fields,
                sanitized_fields_removed=removed_fields,
            )
            raise

        except HumanReviewRequired as exc:
            _audit_log(
                conn,
                request_id=request_id,
                event_type="customer.read.human_review_required",
                driver_id=driver_id,
                customer_id=customer_id,
                result="review_required",
                reason=str(exc),
                pii_detected_fields=pii_detected_fields,
                sanitized_fields_removed=removed_fields,
            )
            raise

        # L4: 監査ログ
        _audit_log(
            conn,
            request_id=request_id,
            event_type="customer.read.success",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
            pii_detected_fields=pii_detected_fields,
            sanitized_fields_removed=removed_fields,
        )

        return {
            "request_id": request_id,
            "customer": sanitized,
        }