import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from typing import Any, Dict, Optional, Set


DB_PATH = os.getenv("APP_DB_PATH", "app.db")

logger = logging.getLogger("customer_api.audit")
logger.setLevel(logging.INFO)


class NotFoundOrForbiddenError(Exception):
    """顧客が存在しない、またはdriverに閲覧権限がない場合に返す。"""
    pass


class ManualReviewRequiredError(Exception):
    """返却直前チェックで人間確認が必要と判断された場合に返す。"""
    pass


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

def _audit_hash(value: Any) -> str:
    """
    監査ログ用にIDをHMACで不可逆化する。
    ログにはdriver_id/customer_idの生値を出さない。
    """
    key = os.getenv("AUDIT_HASH_KEY", "CHANGE_ME_IN_PRODUCTION").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _audit_log(
    event: str,
    trace_id: str,
    *,
    driver_id: Optional[Any] = None,
    customer_id: Optional[Any] = None,
    status: str = "ok",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "event": event,
        "trace_id": trace_id,
        "status": status,
        "driver_ref": _audit_hash(driver_id) if driver_id is not None else None,
        "customer_ref": _audit_hash(customer_id) if customer_id is not None else None,
        "details": details or {},
    }

    # PIIを含めずJSONログとして記録
    logger.info(json.dumps(payload, ensure_ascii=False, sort_keys=True))


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?:\+?\d{1,3}[- ]?)?(?:\d{2,4}[- ]?){2,4}\d{3,4}"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "my_number": re.compile(r"\b\d{12}\b"),  # 日本のマイナンバー形式の簡易検知
}

PII_FIELD_HINTS = {
    "name": "name",
    "full_name": "name",
    "phone": "phone",
    "mobile": "phone",
    "email": "email",
    "address": "address",
    "date_of_birth": "date_of_birth",
    "dob": "date_of_birth",
    "medical_notes": "medical",
    "payment_token": "payment",
}


def detect_pii(record: Dict[str, Any]) -> Set[str]:
    """
    レコード内のPII種別を検知する。
    ログには検知結果のみを出し、生値は出さない。
    """
    detected: Set[str] = set()

    for key, value in record.items():
        key_lower = str(key).lower()

        if key_lower in PII_FIELD_HINTS:
            detected.add(PII_FIELD_HINTS[key_lower])

        if isinstance(value, str):
            for pii_type, pattern in PII_PATTERNS.items():
                if pattern.search(value):
                    detected.add(pii_type)

    return detected


def _mask_value(key: str, value: Any) -> Any:
    if value is None:
        return None

    key_lower = key.lower()
    text = str(value)

    if key_lower in {"name", "full_name"}:
        return text[:1] + "***" if text else None

    if key_lower in {"phone", "mobile"}:
        digits = re.sub(r"\D", "", text)
        return "***-****-" + digits[-4:] if len(digits) >= 4 else "***"

    if key_lower == "email":
        return "***@***"

    if key_lower == "address":
        return "[MASKED_ADDRESS]"

    if key_lower in {"medical_notes", "payment_token", "date_of_birth", "dob"}:
        return "[MASKED]"

    return text


def mask_record_for_log(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    監査・運用ログ用にレコードをマスクする。
    """
    return {key: _mask_value(key, value) for key, value in record.items()}


def redact_free_text(text: Optional[str]) -> Optional[str]:
    """
    自由記述欄から不要なPIIを除去する。
    driver_note等に電話番号やメールが混入していても返却しない。
    """
    if text is None:
        return None

    redacted = text
    redacted = PII_PATTERNS["email"].sub("[REDACTED_EMAIL]", redacted)
    redacted = PII_PATTERNS["credit_card"].sub("[REDACTED_CARD]", redacted)
    redacted = PII_PATTERNS["my_number"].sub("[REDACTED_MY_NUMBER]", redacted)

    # 電話番号は専用フィールド phone で返すため、自由記述内の電話番号は伏せる
    redacted = PII_PATTERNS["phone"].sub("[REDACTED_PHONE]", redacted)

    return redacted


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

ALLOWED_RESPONSE_KEYS = {
    "customer_id",
    "name",
    "phone",
    "address",
    "visit_window",
    "driver_note",
}

FORBIDDEN_RESPONSE_KEYS = {
    "date_of_birth",
    "dob",
    "email",
    "medical_notes",
    "payment_token",
    "billing_address",
    "family_notes",
}


def sanitize_customer_for_driver(db_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    driverに必要な最小限の顧客情報だけを返却用に整形する。
    例:
    - 氏名
    - 電話番号
    - 訪問先住所
    - 訪問時間帯
    - driver向け連絡事項

    医療情報、決済情報、生年月日、メール等は返さない。
    """
    return {
        "customer_id": db_record["customer_id"],
        "name": db_record.get("full_name"),
        "phone": db_record.get("phone"),
        "address": db_record.get("address"),
        "visit_window": db_record.get("visit_window"),
        "driver_note": redact_free_text(db_record.get("driver_note")),
    }


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def guard_before_return(
    payload: Dict[str, Any],
    *,
    driver_id: Any,
    customer_id: Any,
    trace_id: str,
) -> None:
    """
    返却直前の安全確認。
    想定外の項目や高リスクPIIが残っている場合は返却せず、人間確認に回す。
    """
    keys = set(payload.keys())

    unexpected_keys = keys - ALLOWED_RESPONSE_KEYS
    if unexpected_keys:
        _audit_log(
            "manual_review_required",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="blocked",
            details={"reason": "unexpected_response_keys", "keys": sorted(unexpected_keys)},
        )
        raise ManualReviewRequiredError("Unexpected response keys detected.")

    forbidden_keys = keys & FORBIDDEN_RESPONSE_KEYS
    if forbidden_keys:
        _audit_log(
            "manual_review_required",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="blocked",
            details={"reason": "forbidden_response_keys", "keys": sorted(forbidden_keys)},
        )
        raise ManualReviewRequiredError("Forbidden response keys detected.")

    if str(payload.get("customer_id")) != str(customer_id):
        _audit_log(
            "manual_review_required",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="blocked",
            details={"reason": "customer_id_mismatch"},
        )
        raise ManualReviewRequiredError("Customer ID mismatch.")

    # 自由記述欄に高リスクPIIが残っていないか確認
    note_pii = detect_pii({"driver_note": payload.get("driver_note")})
    high_risk = {"credit_card", "my_number", "email"} & note_pii

    if high_risk:
        _audit_log(
            "manual_review_required",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="blocked",
            details={"reason": "high_risk_pii_in_driver_note", "pii_types": sorted(high_risk)},
        )
        raise ManualReviewRequiredError("High-risk PII detected in response.")


# ============================================================
# DB接続
# ============================================================

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _validate_id(name: str, value: Any) -> str:
    """
    SQLインジェクションはプレースホルダで防ぐが、
    異常に長いIDや制御文字を早期に拒否する。
    UUID/数値/短い外部IDを想定。
    """
    if value is None:
        raise ValueError(f"{name} is required.")

    text = str(value).strip()

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", text):
        raise ValueError(f"{name} has invalid format.")

    return text


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリのdriver向け顧客情報取得API。

    - 指定されたcustomer_idの顧客レコードをDBから取得する
    - driver_idに割り当てられている顧客のみ取得可能
    - PIIを検知・ログ用マスキング
    - サニタイズにより最小限の項目だけ返す
    - 返却直前にガード節でチェック
    - 監査ログはHMAC化IDのみ記録
    """
    trace_id = uuid.uuid4().hex

    driver_id = _validate_id("driver_id", driver_id)
    customer_id = _validate_id("customer_id", customer_id)

    _audit_log(
        "get_customer_for_driver_requested",
        trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    query = """
        SELECT
            c.id AS customer_id,
            c.full_name,
            c.phone,
            c.address,
            c.visit_window,
            c.driver_note,

            -- 以下はDB上には存在するが、返却しない項目の例
            c.date_of_birth,
            c.email,
            c.medical_notes,
            c.payment_token

        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.id
           AND a.driver_id = ?
           AND a.active = 1
        WHERE c.id = ?
          AND c.deleted_at IS NULL
        LIMIT 1
    """

    with _get_connection() as conn:
        row = conn.execute(query, (driver_id, customer_id)).fetchone()

    if row is None:
        _audit_log(
            "get_customer_for_driver_not_found_or_forbidden",
            trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="denied",
        )
        raise NotFoundOrForbiddenError("Customer not found or access forbidden.")

    db_record = dict(row)

    # L1: PII検知とマスキング済みスナップショットの監査記録
    pii_types = detect_pii(db_record)
    masked_snapshot = mask_record_for_log(db_record)

    _audit_log(
        "customer_record_loaded",
        trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        details={
            "pii_types": sorted(pii_types),
            "masked_snapshot": masked_snapshot,
        },
    )

    # L2: driver向け最小権限データにサニタイズ
    response_payload = sanitize_customer_for_driver(db_record)

    # None値は不要なら除外
    response_payload = {
        key: value
        for key, value in response_payload.items()
        if value is not None
    }

    # L3: 返却直前のガード節
    guard_before_return(
        response_payload,
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
    )

    # L4: 成功監査ログ
    _audit_log(
        "get_customer_for_driver_succeeded",
        trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        details={
            "returned_keys": sorted(response_payload.keys()),
        },
    )

    return response_payload