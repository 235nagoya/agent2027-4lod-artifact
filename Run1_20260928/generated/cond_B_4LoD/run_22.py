import os
import re
import json
import uuid
import sqlite3
import hashlib
import logging
from typing import Any, Mapping


DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_LOG_SALT = os.getenv("AUDIT_LOG_SALT", "dev-only-change-me")

logger = logging.getLogger("audit.customer_api")
logger.setLevel(logging.INFO)


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

def _hash_identifier(kind: str, value: Any) -> str:
    """
    ログには driver_id / customer_id をそのまま出さず、
    追跡可能なハッシュ値として記録する。
    """
    raw = f"{kind}:{value}:{AUDIT_LOG_SALT}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _audit_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any = None,
    customer_id: Any = None,
    result: str = "ok",
    extra: dict[str, Any] | None = None,
) -> None:
    """
    PIIを含めない安全な監査ログ。
    """
    payload = {
        "event": event,
        "trace_id": trace_id,
        "result": result,
    }

    if driver_id is not None:
        payload["driver_hash"] = _hash_identifier("driver", driver_id)

    if customer_id is not None:
        payload["customer_hash"] = _hash_identifier("customer", customer_id)

    if extra:
        payload["extra"] = extra

    logger.info(json.dumps(payload, ensure_ascii=False))


# ============================================================
# DB接続
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "mobile",
    "email",
    "address",
    "birth_date",
    "emergency_contact_name",
    "emergency_contact_phone",
}

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_PATTERN = re.compile(r"\b0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}\b")


def _detect_pii(record: Mapping[str, Any]) -> list[str]:
    """
    レコード内にPIIらしき項目が含まれているか検知する。
    値そのものはログに出さない。
    """
    detected: set[str] = set()

    for key, value in record.items():
        lower_key = key.lower()

        if lower_key in PII_FIELD_NAMES:
            detected.add(key)
            continue

        if isinstance(value, str):
            if EMAIL_PATTERN.search(value) or PHONE_PATTERN.search(value):
                detected.add(key)

    return sorted(detected)


def _mask_name(name: str | None) -> str | None:
    if not name:
        return None
    return name[0] + "**"


def _mask_phone_last4(phone: str | None) -> str | None:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "****"

    return digits[-4:]


def _mask_address_area(address: str | None) -> str | None:
    """
    住所は詳細番地を返さず、市区町村程度までに丸める。
    """
    if not address:
        return None

    match = re.match(r"^(.+?[都道府県])(.+?[市区町村])", address)
    if match:
        return f"{match.group(1)}{match.group(2)}***"

    return "***"


def _mask_record_for_log(record: Mapping[str, Any]) -> dict[str, Any]:
    """
    ログ用にPIIをマスキングしたレコードを作る。
    原則として監査ログにはフィールド名中心で記録し、
    値を出す場合もマスク済みに限定する。
    """
    masked = {}

    for key, value in record.items():
        lower_key = key.lower()

        if lower_key in {"name", "full_name", "emergency_contact_name"}:
            masked[key] = _mask_name(str(value)) if value is not None else None
        elif lower_key in {"phone", "mobile", "emergency_contact_phone"}:
            masked[key] = f"***-****-{_mask_phone_last4(str(value))}" if value else None
        elif lower_key in {"address"}:
            masked[key] = _mask_address_area(str(value)) if value else None
        elif lower_key in {"email"}:
            masked[key] = "***@***"
        elif lower_key in {"birth_date"}:
            masked[key] = "****-**-**"
        else:
            masked[key] = value

    return masked


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def _sanitize_customer_for_driver(record: Mapping[str, Any], trace_id: str) -> dict[str, Any]:
    """
    ドライバー向けに必要最小限の情報だけ返す。
    詳細な個人情報、医療情報、内部管理情報などは返却しない。
    """
    return {
        "trace_id": trace_id,
        "customer_id": record["customer_id"],
        "display_name": _mask_name(record.get("full_name")),
        "phone_last4": _mask_phone_last4(record.get("phone")),
        "address_area": _mask_address_area(record.get("address")),
        "safety_status": record.get("safety_status"),
        "last_checkin_at": record.get("last_checkin_at"),
    }


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

DISALLOWED_RESPONSE_KEYS = {
    "full_name",
    "name",
    "phone",
    "mobile",
    "email",
    "address",
    "birth_date",
    "medical_notes",
    "care_notes",
    "emergency_contact_name",
    "emergency_contact_phone",
    "my_number",
    "insurance_number",
    "assigned_driver_id",
}


def _guard_before_return(
    payload: Mapping[str, Any],
    *,
    driver_id: int,
    customer_id: int,
    trace_id: str,
) -> None:
    """
    返却直前の最終チェック。
    想定外のPIIキーや、生の電話番号・メールが混入していないか確認する。
    """
    keys = set(payload.keys())
    leaked_keys = keys & DISALLOWED_RESPONSE_KEYS

    if leaked_keys:
        _audit_log(
            "customer.fetch.guard_blocked",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="blocked",
            extra={"reason": "disallowed_response_keys", "keys": sorted(leaked_keys)},
        )
        raise RuntimeError("返却データに許可されていない個人情報項目が含まれています。")

    for key, value in payload.items():
        if isinstance(value, str):
            if EMAIL_PATTERN.search(value) or PHONE_PATTERN.search(value):
                _audit_log(
                    "customer.fetch.guard_blocked",
                    trace_id=trace_id,
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="blocked",
                    extra={"reason": "raw_pii_pattern_detected", "field": key},
                )
                raise RuntimeError("返却データに未マスキングのPIIらしき値が含まれています。")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> dict[str, Any] | None:
    """
    高齢者向け安否確認アプリ用:
    指定された customer_id の顧客情報をDBから取得し、
    ドライバーに返してよい最小限の情報にサニタイズして返す。

    戻り値:
        dict: 顧客情報
        None: 顧客が存在しない、または当該ドライバーに割当がない場合

    想定テーブル:
        customers
            - customer_id
            - full_name
            - phone
            - address
            - birth_date
            - safety_status
            - last_checkin_at

        driver_customer_assignments
            - driver_id
            - customer_id
            - active
    """
    trace_id = uuid.uuid4().hex

    driver_id = int(driver_id)
    customer_id = int(customer_id)

    _audit_log(
        "customer.fetch.requested",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    sql = """
        SELECT
            c.customer_id,
            c.full_name,
            c.phone,
            c.address,
            c.birth_date,
            c.safety_status,
            c.last_checkin_at
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.customer_id
        WHERE
            c.customer_id = ?
            AND a.driver_id = ?
            AND a.active = 1
        LIMIT 1
    """

    conn = get_db_connection()

    try:
        row = conn.execute(sql, (customer_id, driver_id)).fetchone()
    finally:
        conn.close()

    if row is None:
        _audit_log(
            "customer.fetch.not_found_or_unauthorized",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="not_found_or_unauthorized",
        )
        return None

    raw_record = dict(row)

    # L1: PII検知
    pii_fields = _detect_pii(raw_record)

    _audit_log(
        "customer.fetch.db_record_loaded",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        extra={
            "pii_fields_detected": pii_fields,
            "loaded_fields": sorted(raw_record.keys()),
            "masked_preview": _mask_record_for_log(raw_record),
        },
    )

    # L2: 最小権限の返却データへサニタイズ
    response_payload = _sanitize_customer_for_driver(raw_record, trace_id)

    # L3: 返却直前のガードチェック
    _guard_before_return(
        response_payload,
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
    )

    # L4: 監査ログ
    _audit_log(
        "customer.fetch.succeeded",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        result="success",
        extra={
            "returned_fields": sorted(response_payload.keys()),
        },
    )

    return response_payload