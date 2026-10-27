import os
import re
import uuid
import hmac
import json
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional


# =========================
# 基本設定
# =========================

DB_PATH = os.getenv("DB_PATH", "app.db")

# ログ上でIDを追跡可能にしつつ、平文IDを出さないための鍵
LOG_HASH_KEY = os.getenv("LOG_HASH_KEY", "change-me-in-production").encode("utf-8")

logger = logging.getLogger("customer_api")
logging.basicConfig(level=logging.INFO)


# =========================
# 例外定義
# =========================

class CustomerNotFoundError(Exception):
    pass


class ManualReviewRequired(Exception):
    pass


class SecurityGuardViolation(Exception):
    pass


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_identifier(value: Any) -> str:
    """
    ログ用にIDをHMACハッシュ化する。
    平文の driver_id / customer_id をログに出さず、追跡可能性だけを残す。
    """
    msg = str(value).encode("utf-8")
    return hmac.new(LOG_HASH_KEY, msg, hashlib.sha256).hexdigest()


def _safe_log(
    event: str,
    trace_id: str,
    driver_id: Optional[Any] = None,
    customer_id: Optional[Any] = None,
    **extra: Any
) -> None:
    """
    PIIを含めない安全なログ。
    driver_id / customer_id はハッシュ化して記録する。
    """
    log_record = {
        "event": event,
        "trace_id": trace_id,
    }

    if driver_id is not None:
        log_record["driver_hash"] = _hash_identifier(driver_id)

    if customer_id is not None:
        log_record["customer_hash"] = _hash_identifier(customer_id)

    log_record.update(extra)

    logger.info(json.dumps(log_record, ensure_ascii=False))


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

PII_FIELD_HINTS = {
    "name": "name",
    "full_name": "name",
    "kana": "name",
    "phone": "phone",
    "tel": "phone",
    "email": "email",
    "address": "address",
    "birth": "birth_date",
    "dob": "birth_date",
    "medical": "medical_info",
    "note": "free_text",
}

PHONE_RE = re.compile(r"\b0\d{1,4}-?\d{1,4}-?\d{3,4}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MY_NUMBER_RE = re.compile(r"\b\d{12}\b")


def _detect_pii(record: Dict[str, Any]) -> Dict[str, str]:
    """
    DBから取得したレコード内に、どの種類のPIIが含まれるかを検知する。
    ログには値を出さず、PII種別のみを残す。
    """
    detected = {}

    for key, value in record.items():
        key_lower = key.lower()
        value_str = "" if value is None else str(value)

        for hint, pii_type in PII_FIELD_HINTS.items():
            if hint in key_lower:
                detected[key] = pii_type

        if PHONE_RE.search(value_str):
            detected[key] = "phone"

        if EMAIL_RE.search(value_str):
            detected[key] = "email"

        if MY_NUMBER_RE.search(value_str):
            detected[key] = "my_number_candidate"

    return detected


def _mask_value(key: str, value: Any) -> Any:
    """
    ログや監査サンプル用のマスキング。
    APIレスポンスそのものではなく、記録用に使う。
    """
    if value is None:
        return None

    key_lower = key.lower()
    text = str(value)

    if "phone" in key_lower or "tel" in key_lower:
        digits = re.sub(r"\D", "", text)
        return f"***-****-{digits[-4:]}" if len(digits) >= 4 else "***"

    if "email" in key_lower:
        local, _, domain = text.partition("@")
        return f"{local[:1]}***@{domain}" if domain else "***"

    if "name" in key_lower:
        return text[:1] + "***" if text else "***"

    if "address" in key_lower:
        return "[MASKED_ADDRESS]"

    if "birth" in key_lower or "dob" in key_lower:
        return "[MASKED_BIRTH_DATE]"

    if "medical" in key_lower or "note" in key_lower:
        return "[MASKED_TEXT]"

    return value


def _mask_record_for_log(record: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _mask_value(k, v) for k, v in record.items()}


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def _sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー業務に必要な最小限の項目だけを返す。

    返却する例:
    - customer_id
    - display_name
    - phone
    - address
    - safety_status
    - last_checkin_at
    - emergency_contact_phone

    返却しない例:
    - 生年月日
    - 医療詳細
    - 内部メモ
    - 保険情報
    - 本人確認番号
    """
    return {
        "customer_id": record["customer_id"],
        "display_name": record.get("full_name"),
        "phone": record.get("phone"),
        "address": record.get("address"),
        "safety_status": record.get("safety_status"),
        "last_checkin_at": record.get("last_checkin_at"),
        "emergency_contact_phone": record.get("emergency_contact_phone"),
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

ALLOWED_RESPONSE_KEYS = {
    "customer_id",
    "display_name",
    "phone",
    "address",
    "safety_status",
    "last_checkin_at",
    "emergency_contact_phone",
    "trace_id",
}

FORBIDDEN_KEY_HINTS = {
    "birth",
    "dob",
    "medical",
    "diagnosis",
    "insurance",
    "my_number",
    "mynumber",
    "credit",
    "password",
    "token",
    "internal_note",
    "private_note",
}


def _pre_return_human_guard(payload: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    異常があれば自動返却せず、人間レビューに回す想定。
    """
    keys = set(payload.keys())

    unexpected_keys = keys - ALLOWED_RESPONSE_KEYS
    if unexpected_keys:
        raise SecurityGuardViolation(
            f"Unexpected response keys detected: {sorted(unexpected_keys)}"
        )

    for key in keys:
        key_lower = key.lower()
        if any(hint in key_lower for hint in FORBIDDEN_KEY_HINTS):
            raise SecurityGuardViolation(f"Forbidden key detected: {key}")

    serialized = json.dumps(payload, ensure_ascii=False)

    # マイナンバー候補のような強い機微情報が混入していないか確認
    if MY_NUMBER_RE.search(serialized):
        raise SecurityGuardViolation("My-number-like value detected in response")

    if not payload.get("customer_id"):
        raise SecurityGuardViolation("customer_id is missing")

    if not payload.get("trace_id"):
        raise SecurityGuardViolation("trace_id is missing")


def _create_manual_review_ticket(
    trace_id: str,
    reason: str,
    driver_id: Any,
    customer_id: Any
) -> str:
    """
    実運用ではチケット管理システムや監査DBに登録する。
    ここでは安全なログのみを残し、チケットIDを返す。
    """
    ticket_id = f"MR-{uuid.uuid4()}"

    _safe_log(
        event="manual_review.created",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        ticket_id=ticket_id,
        reason=reason,
    )

    return ticket_id


# =========================
# DB接続
# =========================

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    指定された customer_id の顧客レコードをDBから取得し、
    ドライバーに必要な最小限の情報だけを返す。

    4LoD対応:
    - L1: DB取得後にPIIを検知し、ログ用データはマスキング
    - L2: サニタイズ関数で最小権限のレスポンスへ変換
    - L3: 返却直前にガード節でチェックし、異常時は人間レビューへ
    - L4: 全処理をPIIなしの安全ログで追跡
    """
    trace_id = str(uuid.uuid4())

    _safe_log(
        event="customer.get.start",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    if not isinstance(driver_id, int) or not isinstance(customer_id, int):
        _safe_log(
            event="customer.get.validation_failed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason="driver_id and customer_id must be int",
        )
        raise ValueError("driver_id and customer_id must be integers")

    try:
        with _get_connection() as conn:
            row = conn.execute(
                """
                SELECT
                    c.customer_id,
                    c.full_name,
                    c.phone,
                    c.address,
                    c.safety_status,
                    c.last_checkin_at,
                    c.emergency_contact_phone,
                    c.birth_date,
                    c.medical_note,
                    c.internal_note
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.customer_id
                WHERE
                    c.customer_id = ?
                    AND a.driver_id = ?
                    AND c.deleted_at IS NULL
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            _safe_log(
                event="customer.get.not_found",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
            )
            raise CustomerNotFoundError("customer not found")

        raw_record = dict(row)

        # L1: PII検知とマスキング済み監査情報
        detected_pii = _detect_pii(raw_record)
        masked_record = _mask_record_for_log(raw_record)

        _safe_log(
            event="customer.get.record_loaded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            detected_pii_types=sorted(set(detected_pii.values())),
            masked_record=masked_record,
        )

        # L2: 最小権限化
        response_payload = _sanitize_customer_for_driver(raw_record)
        response_payload["trace_id"] = trace_id

        # L3: 返却直前チェック
        try:
            _pre_return_human_guard(response_payload)
        except SecurityGuardViolation as e:
            ticket_id = _create_manual_review_ticket(
                trace_id=trace_id,
                reason=str(e),
                driver_id=driver_id,
                customer_id=customer_id,
            )

            _safe_log(
                event="customer.get.blocked_before_return",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                ticket_id=ticket_id,
            )

            raise ManualReviewRequired(
                f"response blocked and sent to manual review: {ticket_id}"
            ) from e

        # L4: 成功ログ
        _safe_log(
            event="customer.get.success",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            returned_keys=sorted(response_payload.keys()),
        )

        return response_payload

    except CustomerNotFoundError:
        raise

    except ManualReviewRequired:
        raise

    except Exception as e:
        _safe_log(
            event="customer.get.error",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            error_type=type(e).__name__,
        )
        raise