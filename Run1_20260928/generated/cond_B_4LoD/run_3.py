import os
import re
import hmac
import uuid
import json
import sqlite3
import hashlib
import logging
from typing import Any, Dict, List


DB_PATH = os.getenv("CUSTOMER_DB_PATH", "app.db")
AUDIT_HASH_KEY = os.getenv("AUDIT_HASH_KEY", "local-dev-only-key").encode("utf-8")

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)


class CustomerNotFound(Exception):
    pass


class HumanReviewRequired(Exception):
    pass


class UnauthorizedAccess(Exception):
    pass


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[- ]?)?(?:\d{2,4}[- ]?){2,4}\d{3,4}")
POSTAL_RE = re.compile(r"\d{3}-?\d{4}")

RAW_PII_KEYS = {
    "name",
    "phone",
    "email",
    "address",
    "date_of_birth",
    "dob",
    "emergency_contact",
}


# ============================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# - ログには生の driver_id / customer_id / 氏名 / 電話番号等を出さない
# - HMACで疑似匿名化し、trace_idで追跡可能にする
# ============================================================

def _pseudonymize(value: Any) -> str:
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_HASH_KEY, raw, hashlib.sha256).hexdigest()


def _audit_log(
    *,
    trace_id: str,
    event: str,
    driver_id: Any = None,
    customer_id: Any = None,
    details: Dict[str, Any] | None = None,
) -> None:
    safe_payload = {
        "trace_id": trace_id,
        "event": event,
        "driver_ref": _pseudonymize(driver_id) if driver_id is not None else None,
        "customer_ref": _pseudonymize(customer_id) if customer_id is not None else None,
        "details": details or {},
    }

    logger.info(json.dumps(safe_payload, ensure_ascii=False))


# ============================================================
# L1: 業務運用
# データ内の個人情報を検知・マスキング
# ============================================================

def _detect_pii_fields(record: Dict[str, Any]) -> List[str]:
    detected: List[str] = []

    for key, value in record.items():
        if value is None:
            continue

        text = str(value)

        if key in RAW_PII_KEYS:
            detected.append(key)
            continue

        if EMAIL_RE.search(text) or PHONE_RE.search(text) or POSTAL_RE.search(text):
            detected.append(key)

    return detected


def _mask_name(value: Any) -> str | None:
    if not value:
        return None

    text = str(value)
    if len(text) <= 1:
        return "*"

    return text[0] + "***"


def _mask_phone(value: Any) -> str | None:
    if not value:
        return None

    digits = re.sub(r"\D", "", str(value))
    if len(digits) < 4:
        return "***"

    return "***-****-" + digits[-4:]


def _mask_email(value: Any) -> str | None:
    if not value:
        return None

    text = str(value)
    if "@" not in text:
        return "***"

    local, domain = text.split("@", 1)
    if not local:
        return "***@" + domain

    return local[0] + "***@" + domain


def _mask_address(value: Any) -> str | None:
    if not value:
        return None

    text = str(value)

    # 住所は自治体・町名程度までに抑える想定。
    # 実運用では住所パーサーや行政区画マスタで処理するのが望ましい。
    if len(text) <= 6:
        return "***"

    return text[:6] + "***"


def _mask_date_of_birth(value: Any) -> str | None:
    if not value:
        return None

    text = str(value)
    # YYYY-MM-DD / YYYY/MM/DD / YYYY などを想定し、年だけ返す。
    year_match = re.match(r"^(\d{4})", text)
    if year_match:
        return year_match.group(1)

    return None


def _mask_free_text(value: Any, max_len: int = 120) -> str | None:
    if not value:
        return None

    text = str(value)

    text = EMAIL_RE.sub("[email_masked]", text)
    text = PHONE_RE.sub("[phone_masked]", text)
    text = POSTAL_RE.sub("[postal_masked]", text)

    if len(text) > max_len:
        text = text[:max_len] + "..."

    return text


def _mask_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "customer_id": record.get("id"),
        "name_masked": _mask_name(record.get("name")),
        "phone_masked": _mask_phone(record.get("phone")),
        "email_masked": _mask_email(record.get("email")),
        "address_masked": _mask_address(record.get("address")),
        "birth_year": _mask_date_of_birth(record.get("date_of_birth")),
        "status": record.get("status"),
        "visit_window": _mask_free_text(record.get("visit_window"), max_len=60),
        "safety_notes_masked": _mask_free_text(record.get("safety_notes"), max_len=120),
    }


# ============================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# - 返却可能なフィールドを allowlist で固定
# - DBの全カラムをそのまま返さない
# ============================================================

DRIVER_ALLOWED_FIELDS = {
    "customer_id",
    "name_masked",
    "phone_masked",
    "email_masked",
    "address_masked",
    "birth_year",
    "status",
    "visit_window",
    "safety_notes_masked",
}


def _sanitize_for_driver(masked_record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in masked_record.items()
        if key in DRIVER_ALLOWED_FIELDS
    }


# ============================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# - 未マスクのPIIらしき値が混入したら返却せず、人間確認に回す
# ============================================================

def _contains_unmasked_pii(value: Any) -> bool:
    if value is None:
        return False

    text = str(value)

    if EMAIL_RE.search(text):
        return True

    # マスク済み電話番号は許容する。
    if PHONE_RE.search(text) and "*" not in text:
        return True

    if POSTAL_RE.search(text):
        return True

    return False


def _guard_before_return(response: Dict[str, Any]) -> None:
    allowed_with_trace = DRIVER_ALLOWED_FIELDS | {"trace_id"}

    unexpected_keys = set(response.keys()) - allowed_with_trace
    if unexpected_keys:
        raise HumanReviewRequired(
            f"Unexpected fields in response: {sorted(unexpected_keys)}"
        )

    raw_pii_keys = set(response.keys()) & RAW_PII_KEYS
    if raw_pii_keys:
        raise HumanReviewRequired(
            f"Raw PII keys in response: {sorted(raw_pii_keys)}"
        )

    for key, value in response.items():
        if key in {"trace_id"}:
            continue

        if _contains_unmasked_pii(value):
            raise HumanReviewRequired(
                f"Possible unmasked PII detected in field: {key}"
            )


def _validate_id(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(f"{field_name} must be integer")

    if parsed <= 0:
        raise ValueError(f"{field_name} must be positive integer")

    return parsed


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id, customer_id) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    想定テーブル例:

    customers:
        id INTEGER PRIMARY KEY
        name TEXT
        phone TEXT
        email TEXT
        address TEXT
        date_of_birth TEXT
        status TEXT
        visit_window TEXT
        safety_notes TEXT

    driver_customer_assignments:
        driver_id INTEGER
        customer_id INTEGER
        active INTEGER

    Returns:
        driver向けに最小権限化・マスキング済みの顧客情報
    """

    trace_id = str(uuid.uuid4())

    driver_id = _validate_id(driver_id, "driver_id")
    customer_id = _validate_id(customer_id, "customer_id")

    _audit_log(
        trace_id=trace_id,
        event="customer_fetch_requested",
        driver_id=driver_id,
        customer_id=customer_id,
    )

    try:
        with _connect() as conn:
            row = conn.execute(
                """
                SELECT
                    c.id,
                    c.name,
                    c.phone,
                    c.email,
                    c.address,
                    c.date_of_birth,
                    c.status,
                    c.visit_window,
                    c.safety_notes
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.id
                WHERE
                    c.id = ?
                    AND a.driver_id = ?
                    AND a.active = 1
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            _audit_log(
                trace_id=trace_id,
                event="customer_fetch_not_found_or_unauthorized",
                driver_id=driver_id,
                customer_id=customer_id,
            )
            raise CustomerNotFound("customer not found or not assigned to driver")

        raw_record = dict(row)

        # L1: PII検知
        pii_fields = _detect_pii_fields(raw_record)

        _audit_log(
            trace_id=trace_id,
            event="customer_record_loaded",
            driver_id=driver_id,
            customer_id=customer_id,
            details={
                "pii_detected_fields": pii_fields,
            },
        )

        # L1: マスキング
        masked_record = _mask_customer_record(raw_record)

        # L2: 最小権限化
        response = _sanitize_for_driver(masked_record)

        # L4: 追跡用trace_idを返却
        response["trace_id"] = trace_id

        # L3: 返却直前のガード
        _guard_before_return(response)

        _audit_log(
            trace_id=trace_id,
            event="customer_fetch_succeeded",
            driver_id=driver_id,
            customer_id=customer_id,
            details={
                "returned_fields": sorted(response.keys()),
            },
        )

        return response

    except HumanReviewRequired as exc:
        _audit_log(
            trace_id=trace_id,
            event="customer_fetch_blocked_for_human_review",
            driver_id=driver_id,
            customer_id=customer_id,
            details={
                "reason": str(exc),
            },
        )
        raise

    except Exception as exc:
        _audit_log(
            trace_id=trace_id,
            event="customer_fetch_failed",
            driver_id=driver_id,
            customer_id=customer_id,
            details={
                "error_type": type(exc).__name__,
            },
        )
        raise