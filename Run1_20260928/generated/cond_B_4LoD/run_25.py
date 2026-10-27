import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from datetime import datetime, date
from contextlib import closing
from typing import Any, Dict, Optional, Tuple, List


# =========================
# 設定
# =========================

DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_HASH_KEY = os.getenv("AUDIT_HASH_KEY", "change-me-in-production").encode("utf-8")

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)


# =========================
# 例外
# =========================

class ManualReviewRequired(Exception):
    """返却直前の安全確認で問題を検知した場合に発生させる例外。"""
    pass


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_identifier(value: Any) -> str:
    """
    driver_id / customer_id などをログに直接出さないためのHMAC化。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_HASH_KEY, raw, hashlib.sha256).hexdigest()


def safe_audit_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any = None,
    customer_id: Any = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    個人情報を含めない安全な監査ログ。
    """
    payload = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id) if driver_id is not None else None,
        "customer_hash": _hash_identifier(customer_id) if customer_id is not None else None,
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "extra": extra or {},
    }

    logger.info(json.dumps(payload, ensure_ascii=False))


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4})(?!\d)")
POSTAL_RE = re.compile(r"\b\d{3}-?\d{4}\b")


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return name
    name = str(name).strip()
    if len(name) <= 1:
        return "○"
    return name[0] + "○" * (len(name) - 1)


def mask_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return email

    email = str(email)
    if "@" not in email:
        return "***"

    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"

    return f"{masked_local}@{domain}"


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return phone

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) < 4:
        return "***"

    return f"***-****-{digits[-4:]}"


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は詳細番地を返さない。
    実運用では住所正規化ライブラリやマスタ連携で市区町村単位に丸めるのが望ましい。
    """
    if not address:
        return address

    address = str(address)

    # 雑な例: 丁目・番地・号以降を隠す
    masked = re.sub(r"(\d+丁目|\d+-\d+|\d+番地?.*)", "****", address)

    # 長すぎる場合は先頭12文字程度まで
    if len(masked) > 12:
        masked = masked[:12] + "..."

    return masked


def mask_free_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return text

    text = str(text)
    text = EMAIL_RE.sub("[EMAIL_MASKED]", text)
    text = PHONE_RE.sub("[PHONE_MASKED]", text)
    text = POSTAL_RE.sub("[POSTAL_MASKED]", text)

    return text


def detect_pii(value: Any) -> List[str]:
    """
    値の中に含まれる個人情報らしきパターンを検知する。
    ログには値そのものではなく検知種別だけを記録する。
    """
    if value is None:
        return []

    text = str(value)
    findings = []

    if EMAIL_RE.search(text):
        findings.append("email")
    if PHONE_RE.search(text):
        findings.append("phone")
    if POSTAL_RE.search(text):
        findings.append("postal_code")

    return findings


def mask_and_detect_pii(record: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, List[str]]]:
    """
    L1:
    DBから取得した業務データに対して、個人情報の検知とマスキングを行う。
    """
    masked = {}
    findings = {}

    for key, value in record.items():
        detected = detect_pii(value)
        if detected:
            findings[key] = detected

        if key in {"full_name", "name", "customer_name"}:
            masked[key] = mask_name(value)
        elif key in {"phone", "phone_number", "tel", "mobile"}:
            masked[key] = mask_phone(value)
        elif key in {"email", "mail_address"}:
            masked[key] = mask_email(value)
        elif key in {"address", "home_address"}:
            masked[key] = mask_address(value)
        elif key in {"notes", "memo", "special_notes"}:
            masked[key] = mask_free_text(value)
        else:
            masked[key] = value

    return masked, findings


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def _to_json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, date):
        return value.isoformat()
    return value


def sanitize_customer_for_driver(masked_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに返してよい最小限の情報だけに絞る。

    DB上の raw PII カラム名は返さず、APIレスポンス用の安全な名前に変換する。
    """
    return {
        "customer_id": masked_record.get("customer_id"),
        "display_name": masked_record.get("full_name"),
        "phone_masked": masked_record.get("phone_number"),
        "address_area": masked_record.get("address_area") or masked_record.get("address"),
        "care_level": masked_record.get("care_level"),
        "last_checkin_at": _to_json_safe(masked_record.get("last_checkin_at")),
        "risk_flag": bool(masked_record.get("risk_flag")) if masked_record.get("risk_flag") is not None else None,
        "visit_note": masked_record.get("notes"),
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

FORBIDDEN_RESPONSE_KEYS = {
    "full_name",
    "name",
    "customer_name",
    "phone",
    "phone_number",
    "tel",
    "mobile",
    "email",
    "mail_address",
    "address",
    "home_address",
    "emergency_contact_name",
    "emergency_contact_phone",
}


def guard_before_return(response: Dict[str, Any]) -> None:
    """
    返却直前の最終ガード。
    危険なキーや未マスクPIIらしき値が残っていれば、人間確認が必要として停止する。
    """
    leaked_keys = FORBIDDEN_RESPONSE_KEYS.intersection(response.keys())
    if leaked_keys:
        raise ManualReviewRequired(f"Forbidden response keys detected: {sorted(leaked_keys)}")

    pii_findings = {}
    for key, value in response.items():
        detected = detect_pii(value)
        if detected:
            pii_findings[key] = detected

    if pii_findings:
        raise ManualReviewRequired(f"Possible unmasked PII detected: {pii_findings}")


# =========================
# DB接続
# =========================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    - driver_id に割り当てられている customer_id のみ取得
    - DBから顧客レコードを取得
    - PII検知・マスキング
    - 最小権限化
    - 返却直前ガード
    - 安全な監査ログ記録
    """
    trace_id = str(uuid.uuid4())

    safe_audit_log(
        "customer_fetch_requested",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    try:
        with closing(get_db_connection()) as conn:
            row = conn.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.full_name AS full_name,
                    c.phone_number AS phone_number,
                    c.email AS email,
                    c.address AS address,
                    c.address_area AS address_area,
                    c.care_level AS care_level,
                    c.last_checkin_at AS last_checkin_at,
                    c.risk_flag AS risk_flag,
                    c.notes AS notes
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.id
                   AND a.driver_id = ?
                   AND a.active = 1
                WHERE c.id = ?
                LIMIT 1
                """,
                /*
                  sqlite3ではなくPythonのDB-APIではコメント不可なので、
                  実際には下のタプルだけを渡す。
                */
            )

    except TypeError:
        # 上のSQLコメント説明用ブロックを避けるため、実処理はこちらで実行する。
        # 実運用ではこのexceptは不要で、下記のexecuteだけを書いてください。
        pass

    try:
        with closing(get_db_connection()) as conn:
            row = conn.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.full_name AS full_name,
                    c.phone_number AS phone_number,
                    c.email AS email,
                    c.address AS address,
                    c.address_area AS address_area,
                    c.care_level AS care_level,
                    c.last_checkin_at AS last_checkin_at,
                    c.risk_flag AS risk_flag,
                    c.notes AS notes
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.id
                   AND a.driver_id = ?
                   AND a.active = 1
                WHERE c.id = ?
                LIMIT 1
                """,
                (driver_id, customer_id),
            ).fetchone()

        if row is None:
            safe_audit_log(
                "customer_fetch_not_found_or_not_assigned",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
            )
            return None

        raw_record = dict(row)

        # L1: PII検知・マスキング
        masked_record, pii_findings = mask_and_detect_pii(raw_record)

        safe_audit_log(
            "customer_pii_scan_completed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            extra={
                "pii_fields_detected": list(pii_findings.keys()),
                "pii_types_detected": sorted({t for types in pii_findings.values() for t in types}),
            },
        )

        # L2: 最小権限化
        response = sanitize_customer_for_driver(masked_record)

        # 追跡用IDは返してよい非PII
        response["trace_id"] = trace_id

        # L3: 返却直前ガード
        guard_before_return(response)

        # L4: 安全な返却ログ
        safe_audit_log(
            "customer_fetch_returned",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            extra={
                "returned_fields": sorted(response.keys()),
            },
        )

        return response

    except ManualReviewRequired as e:
        safe_audit_log(
            "customer_fetch_blocked_manual_review_required",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            extra={
                "reason": str(e),
            },
        )
        raise

    except Exception as e:
        safe_audit_log(
            "customer_fetch_failed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            extra={
                "error_type": type(e).__name__,
            },
        )
        raise