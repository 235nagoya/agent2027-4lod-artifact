import sqlite3
import logging
import json
import hmac
import hashlib
import re
import uuid
from datetime import date, datetime
from typing import Any, Dict, Optional


DB_PATH = "app.db"

# 本番では環境変数やKMSなどから取得してください
AUDIT_HASH_SECRET = b"replace-with-secure-secret"

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)


# ----------------------------
# DB connection
# ----------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ----------------------------
# L4: 制度的正統性
# 安全なログ記録と追跡
# ----------------------------

def _hash_identifier(value: Any) -> str:
    """
    ログに raw driver_id / customer_id を出さないための追跡用ハッシュ。
    """
    msg = str(value).encode("utf-8")
    return hmac.new(AUDIT_HASH_SECRET, msg, hashlib.sha256).hexdigest()


def _safe_audit_log(
    *,
    event: str,
    request_id: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    PIIを含めず、安全に監査ログを記録する。
    """
    log_entry = {
        "event": event,
        "request_id": request_id,
        "driver_hash": _hash_identifier(driver_id),
        "customer_hash": _hash_identifier(customer_id),
        "outcome": outcome,
        "reason": reason,
        "metadata": metadata or {},
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    audit_logger.info(json.dumps(log_entry, ensure_ascii=False))


# ----------------------------
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# ----------------------------

PII_FIELD_NAMES = {
    "full_name",
    "name",
    "kana",
    "phone",
    "mobile_phone",
    "email",
    "postal_code",
    "address",
    "birth_date",
    "emergency_contact_name",
    "emergency_contact_phone",
    "medical_history",
    "payment_token",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+81[- ]?)?0\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}")


def _detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    レコード内にPIIらしきフィールド・値があるかを検知する。
    """
    detected = []

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            detected.append(key)
            continue

        if isinstance(value, str):
            if EMAIL_RE.search(value) or PHONE_RE.search(value):
                detected.append(key)

    return detected


def _mask_name(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) == 1:
        return "*"
    return value[0] + "*" * (len(value) - 1)


def _mask_address(value: Optional[str]) -> Optional[str]:
    if not value:
        return value

    # 例: 詳細住所は返さず、先頭数文字だけに抑える
    if len(value) <= 6:
        return value[0] + "****"
    return value[:6] + "…"


def _phone_last4(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return None
    return digits[-4:]


def _redact_free_text(value: Optional[str]) -> Optional[str]:
    """
    notes_for_driver 等の自由記述欄から電話番号・メールを除去する。
    """
    if not value:
        return value

    value = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    value = PHONE_RE.sub("[REDACTED_PHONE]", value)
    return value


# ----------------------------
# L2: AI監査
# サニタイズ関数による最小権限化
# ----------------------------

def _age_band_from_birth_date(birth_date: Optional[str]) -> Optional[str]:
    """
    生年月日そのものは返さず、年代のみ返す。
    """
    if not birth_date:
        return None

    try:
        born = date.fromisoformat(str(birth_date))
    except ValueError:
        return None

    today = date.today()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    decade = age // 10 * 10
    return f"{decade}代"


def _sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに必要な最小限の情報だけ返す。
    氏名・住所・電話番号・生年月日などは直接返さない。
    """
    return {
        "customer_id": record.get("customer_id"),
        "display_name": _mask_name(record.get("full_name")),
        "age_band": _age_band_from_birth_date(record.get("birth_date")),
        "safety_status": record.get("safety_status"),
        "visit_area": _mask_address(record.get("address")),
        "phone_last4": _phone_last4(record.get("phone")),
        "care_level": record.get("care_level"),
        "notes_for_driver": _redact_free_text(record.get("notes_for_driver")),
        "last_checkin_at": record.get("last_checkin_at"),
    }


# ----------------------------
# DB access
# ----------------------------

def _fetch_customer_record(customer_id: int) -> Optional[Dict[str, Any]]:
    """
    機能要求:
    DBから指定された customer_id の顧客レコードを取得する。
    """
    sql = """
        SELECT
            customer_id,
            full_name,
            phone,
            email,
            postal_code,
            address,
            birth_date,
            safety_status,
            care_level,
            medical_history,
            payment_token,
            notes_for_driver,
            last_checkin_at
        FROM customers
        WHERE customer_id = ?
        LIMIT 1
    """

    with get_db() as conn:
        row = conn.execute(sql, (customer_id,)).fetchone()

    if row is None:
        return None

    return dict(row)


def _is_driver_assigned_to_customer(driver_id: int, customer_id: int) -> bool:
    """
    ドライバーが当該顧客を担当しているか確認する。
    """
    sql = """
        SELECT 1
        FROM driver_customer_assignments
        WHERE driver_id = ?
          AND customer_id = ?
          AND active = 1
        LIMIT 1
    """

    with get_db() as conn:
        row = conn.execute(sql, (driver_id, customer_id)).fetchone()

    return row is not None


# ----------------------------
# L3: 人間介入
# 返却直前でのガード節によるチェック
# ----------------------------

FORBIDDEN_RESPONSE_KEYS = {
    "full_name",
    "name",
    "kana",
    "phone",
    "mobile_phone",
    "email",
    "postal_code",
    "address",
    "birth_date",
    "medical_history",
    "payment_token",
    "emergency_contact_name",
    "emergency_contact_phone",
}


def _guard_response_payload(
    *,
    payload: Dict[str, Any],
    driver_id: int,
    customer_id: int,
    request_id: str,
) -> None:
    """
    返却直前の最終チェック。
    問題があれば返却せず、監査ログを残して例外にする。
    """

    if payload.get("customer_id") != customer_id:
        _safe_audit_log(
            event="customer_access_guard",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason="customer_id_mismatch",
        )
        raise RuntimeError("Guard blocked response: customer_id mismatch")

    leaked_keys = FORBIDDEN_RESPONSE_KEYS.intersection(payload.keys())
    if leaked_keys:
        _safe_audit_log(
            event="customer_access_guard",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason="forbidden_keys_in_response",
            metadata={"keys": sorted(leaked_keys)},
        )
        raise RuntimeError("Guard blocked response: forbidden keys included")

    notes = payload.get("notes_for_driver")
    if isinstance(notes, str):
        if EMAIL_RE.search(notes) or PHONE_RE.search(notes):
            _safe_audit_log(
                event="customer_access_guard",
                request_id=request_id,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="blocked",
                reason="pii_in_notes_for_driver",
            )
            raise RuntimeError("Guard blocked response: PII detected in notes")

    # 返却直前に割当状態を再確認する。
    if not _is_driver_assigned_to_customer(driver_id, customer_id):
        _safe_audit_log(
            event="customer_access_guard",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason="assignment_revoked_or_missing",
        )
        raise PermissionError("Driver is not assigned to this customer")


# ----------------------------
# Public API
# ----------------------------

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    4LoD:
    - L1: 個人情報フィールドの検知・マスキング
    - L2: サニタイズによる最小権限化
    - L3: 返却直前のガード節チェック
    - L4: 安全な監査ログと追跡
    """

    request_id = str(uuid.uuid4())

    if not isinstance(driver_id, int) or not isinstance(customer_id, int):
        _safe_audit_log(
            event="customer_access",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="failed",
            reason="invalid_id_type",
        )
        raise ValueError("driver_id and customer_id must be integers")

    _safe_audit_log(
        event="customer_access",
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    # 機能要求: DBから customer_id の顧客レコードを取得
    record = _fetch_customer_record(customer_id)

    if record is None:
        _safe_audit_log(
            event="customer_access",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="failed",
            reason="customer_not_found",
        )
        raise LookupError("Customer not found")

    # L1: PII検知
    pii_fields = _detect_pii_fields(record)
    _safe_audit_log(
        event="customer_pii_detection",
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="detected",
        metadata={"pii_fields": pii_fields},
    )

    # 担当ドライバーか確認
    if not _is_driver_assigned_to_customer(driver_id, customer_id):
        _safe_audit_log(
            event="customer_access",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="denied",
            reason="driver_not_assigned",
        )
        raise PermissionError("Driver is not assigned to this customer")

    # L2: 最小権限化されたレスポンスへ変換
    payload = _sanitize_customer_for_driver(record)

    # L3: 返却直前ガード
    _guard_response_payload(
        payload=payload,
        driver_id=driver_id,
        customer_id=customer_id,
        request_id=request_id,
    )

    # L4: 成功ログ
    _safe_audit_log(
        event="customer_access",
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="success",
        metadata={"returned_fields": sorted(payload.keys())},
    )

    return payload