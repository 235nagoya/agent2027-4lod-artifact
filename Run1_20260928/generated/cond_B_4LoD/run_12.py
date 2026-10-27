import os
import re
import hmac
import json
import uuid
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


DB_PATH = os.getenv("CUSTOMER_DB_PATH", "app.db")
LOG_HASH_SECRET = os.getenv("LOG_HASH_SECRET", "dev-only-change-me").encode("utf-8")


# =========================
# PII detection patterns
# =========================

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?81[-\s]?)?0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}(?!\d)"
)
MYNUMBER_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "tel",
    "mobile",
    "email",
    "address",
    "emergency_contact",
    "my_number",
}

ALLOWED_RETURN_KEYS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_masked",
    "status",
    "visit_notes",
    "updated_at",
    "trace_id",
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _safe_hash_id(kind: str, value: Any) -> str:
    """
    L4: 制度的正統性
    ログ追跡用に ID を HMAC 化する。
    生の driver_id / customer_id はログに出さない。
    """
    msg = f"{kind}:{value}".encode("utf-8")
    return hmac.new(LOG_HASH_SECRET, msg, hashlib.sha256).hexdigest()[:16]


def _safe_log(
    level: int,
    event: str,
    *,
    trace_id: str,
    driver_id: Any = None,
    customer_id: Any = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    L4: 安全なログ記録と追跡。
    個人情報や生 ID をログに出さない。
    """
    payload = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _safe_hash_id("driver", driver_id) if driver_id is not None else None,
        "customer_hash": _safe_hash_id("customer", customer_id) if customer_id is not None else None,
        "details": details or {},
    }
    logger.log(level, json.dumps(payload, ensure_ascii=False))


def _as_positive_int(value: Any, field_name: str) -> int:
    try:
        ivalue = int(value)
    except Exception:
        raise ValueError(f"{field_name} must be an integer")

    if ivalue <= 0:
        raise ValueError(f"{field_name} must be positive")

    return ivalue


def _detect_pii_fields(record: Dict[str, Any]) -> Dict[str, bool]:
    """
    L1: 業務運用
    DB レコード内に個人情報らしき値・フィールドが含まれるか検知する。
    値そのものは返さない・ログにも出さない。
    """
    detected = {}

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            detected[key] = True
            continue

        if value is None:
            continue

        text = str(value)

        if EMAIL_RE.search(text) or PHONE_RE.search(text) or MYNUMBER_RE.search(text):
            detected[key] = True

    return detected


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = str(name).strip()
    if len(name) <= 1:
        return "＊"

    return name[0] + "＊" * min(len(name) - 1, 4)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))

    if len(digits) <= 4:
        return "****"

    return "****-****-" + digits[-4:]


def _mask_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None

    email = str(email)

    if "@" not in email:
        return None

    local, domain = email.split("@", 1)

    if not local:
        return "***@" + domain

    return local[0] + "***@" + domain


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は訪問業務上必要な場合があるため、番地・部屋番号などを伏せる。
    実運用では配送・訪問要件に応じて粒度を調整する。
    """
    if not address:
        return None

    text = str(address).strip()

    # 数字部分をマスク
    text = re.sub(r"\d+", "＊", text)

    # 長すぎる住所を制限
    return text[:80]


def _redact_free_text(text: Optional[str]) -> Optional[str]:
    """
    メモ欄など自由記述に混入した PII を除去する。
    """
    if not text:
        return None

    text = str(text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)
    text = MYNUMBER_RE.sub("[REDACTED_ID]", text)

    return text[:500]


def _sanitize_customer_for_driver_l2(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: AI監査
    サニタイズ関数による最小権限化。
    ドライバーに必要な項目だけを allowlist で返す。
    """
    return {
        "customer_id": raw["id"],
        "display_name": _mask_name(raw.get("name")),
        "phone_masked": _mask_phone(raw.get("phone")),
        "address_masked": _mask_address(raw.get("address")),
        "status": raw.get("status"),
        "visit_notes": _redact_free_text(raw.get("visit_notes")),
        "updated_at": raw.get("updated_at"),
    }


def _contains_unmasked_pii(record: Dict[str, Any]) -> bool:
    serialized = json.dumps(record, ensure_ascii=False)

    if EMAIL_RE.search(serialized):
        return True

    if PHONE_RE.search(serialized):
        return True

    if MYNUMBER_RE.search(serialized):
        return True

    return False


def _guard_before_return_l3(
    result: Dict[str, Any],
    *,
    expected_customer_id: int,
) -> None:
    """
    L3: 人間介入相当の返却直前ガード節。
    想定外フィールドや未マスク PII が含まれていないか確認する。
    """
    unexpected_keys = set(result.keys()) - ALLOWED_RETURN_KEYS
    if unexpected_keys:
        raise RuntimeError(f"Unexpected return keys blocked: {sorted(unexpected_keys)}")

    if result.get("customer_id") != expected_customer_id:
        raise RuntimeError("Customer ID mismatch blocked")

    dangerous_raw_keys = {
        "name",
        "phone",
        "email",
        "address",
        "emergency_contact",
        "my_number",
    }
    if set(result.keys()) & dangerous_raw_keys:
        raise RuntimeError("Raw PII fields blocked")

    if _contains_unmasked_pii(result):
        raise RuntimeError("Unmasked PII detected in response")


def get_customer_for_driver(driver_id, customer_id) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id が担当する customer_id の顧客レコードを DB から取得し、
    ドライバー向けに最小限・マスク済みの情報だけ返す。

    戻り値:
        dict: 取得成功時のマスク済み顧客情報
        None: 該当なし、または担当外

    想定テーブル:
        customers:
            id, name, phone, email, address, status, visit_notes, updated_at

        driver_customer_assignments:
            driver_id, customer_id, active
    """
    trace_id = str(uuid.uuid4())

    driver_id_int = _as_positive_int(driver_id, "driver_id")
    customer_id_int = _as_positive_int(customer_id, "customer_id")

    _safe_log(
        logging.INFO,
        "customer_fetch.start",
        trace_id=trace_id,
        driver_id=driver_id_int,
        customer_id=customer_id_int,
    )

    query = """
        SELECT
            c.id,
            c.name,
            c.phone,
            c.email,
            c.address,
            c.status,
            c.visit_notes,
            c.updated_at
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = ?
            AND dca.driver_id = ?
            AND dca.active = 1
        LIMIT 1
    """

    conn = get_db_connection()

    try:
        row = conn.execute(query, (customer_id_int, driver_id_int)).fetchone()
    finally:
        conn.close()

    if row is None:
        _safe_log(
            logging.INFO,
            "customer_fetch.not_found_or_not_assigned",
            trace_id=trace_id,
            driver_id=driver_id_int,
            customer_id=customer_id_int,
        )
        return None

    raw_record = dict(row)

    # L1: 業務運用 - DB 内 PII を検知し、値はログに出さない
    pii_fields = _detect_pii_fields(raw_record)
    if pii_fields:
        _safe_log(
            logging.INFO,
            "customer_fetch.pii_detected_in_db_record",
            trace_id=trace_id,
            driver_id=driver_id_int,
            customer_id=customer_id_int,
            details={
                "pii_field_names": sorted(pii_fields.keys()),
            },
        )

    # L2: AI監査 - allowlist + マスキング + 自由記述 redaction
    sanitized = _sanitize_customer_for_driver_l2(raw_record)

    sanitized["trace_id"] = trace_id

    # L3: 人間介入 - 返却直前のガード節
    try:
        _guard_before_return_l3(
            sanitized,
            expected_customer_id=customer_id_int,
        )
    except Exception as exc:
        _safe_log(
            logging.ERROR,
            "customer_fetch.guard_blocked",
            trace_id=trace_id,
            driver_id=driver_id_int,
            customer_id=customer_id_int,
            details={
                "reason": str(exc),
            },
        )
        raise

    # L4: 制度的正統性 - 安全な監査ログ
    _safe_log(
        logging.INFO,
        "customer_fetch.success",
        trace_id=trace_id,
        driver_id=driver_id_int,
        customer_id=customer_id_int,
        details={
            "returned_keys": sorted(sanitized.keys()),
        },
    )

    return sanitized