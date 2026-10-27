import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ============================================================
# 例外
# ============================================================

class NotFoundOrUnauthorizedError(Exception):
    pass


class SecurityViolationError(Exception):
    pass


# ============================================================
# 設定
# ============================================================

DATABASE_PATH = os.environ.get("APP_DB_PATH", "app.db")

# L4: 制度的正統性 - ログ用HMAC秘密鍵
# 本番では必ずSecret Manager等から取得してください
AUDIT_HASH_SECRET = os.environ.get("AUDIT_HASH_SECRET", "change-me-in-production")

audit_logger = logging.getLogger("audit.customer_access")
audit_logger.setLevel(logging.INFO)


# ============================================================
# 機密情報定義
# ============================================================

# 返却してはならない項目
FORBIDDEN_FIELDS = {
    "medical_history",
    "medical_records",
    "diagnosis",
    "medication",
    "allergy",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "security_code",
    "bank_account",
    "insurance_number",
    "my_number",
    "password",
    "password_hash",
}

# APIとして返却を許可する項目の allowlist
ALLOWED_RESPONSE_FIELDS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_area",
    "checkin_status",
    "last_seen_at",
}


# ============================================================
# DB接続
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

def _hash_identifier(value: Any) -> str:
    """
    driver_id / customer_id をそのままログに出さず、HMACで追跡可能な形にする。
    """
    msg = str(value).encode("utf-8")
    key = AUDIT_HASH_SECRET.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def audit_log(
    *,
    event: str,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    PIIや機密情報を含めずに監査ログを残す。
    """
    record = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id),
        "customer_hash": _hash_identifier(customer_id),
        "outcome": outcome,
        "metadata": metadata or {},
        "logged_at": datetime.now(timezone.utc).isoformat(),
    }

    # extraではなくJSON文字列として安全に出す例
    audit_logger.info(json.dumps(record, ensure_ascii=False))


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PHONE_RE = re.compile(r"\b0\d{1,4}-?\d{1,4}-?\d{3,4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = str(name).strip()

    if len(name) <= 1:
        return "*"

    return name[0] + "*" * (len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))

    if len(digits) < 4:
        return "***"

    return "***-****-" + digits[-4:]


def build_address_area(prefecture: Optional[str], city: Optional[str]) -> Optional[str]:
    """
    番地・建物名は返さず、都道府県・市区町村程度に丸める。
    """
    parts = [p for p in [prefecture, city] if p]
    if not parts:
        return None

    return " ".join(parts)


def detect_sensitive_content(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    返却前の業務上検知。
    実値はログに出さず、検知結果のみ返す。
    """
    findings = []

    for key, value in record.items():
        normalized_key = key.lower()

        if normalized_key in FORBIDDEN_FIELDS:
            findings.append({
                "type": "forbidden_field",
                "field": key,
            })

        if value is None:
            continue

        value_str = str(value)

        if CREDIT_CARD_RE.search(value_str):
            findings.append({
                "type": "possible_credit_card",
                "field": key,
            })

        if PHONE_RE.search(value_str):
            findings.append({
                "type": "phone_like_value",
                "field": key,
            })

    return {
        "finding_count": len(findings),
        "findings": findings,
    }


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    DBから取得した行を、ドライバーに必要な最小限の情報だけに変換する。

    注意:
    - medical_history, credit_card 等はそもそもSQLで取得しない
    - ここでもallowlist方式で返却項目を固定する
    """

    sanitized = {
        "customer_id": row["customer_id"],
        "display_name": mask_name(row["full_name"]),
        "phone_masked": mask_phone(row["phone"]),
        "address_area": build_address_area(row["prefecture"], row["city"]),
        "checkin_status": row["checkin_status"],
        "last_seen_at": row["last_seen_at"],
    }

    # allowlistで最終整形
    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_RESPONSE_FIELDS
    }


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def notify_security_team(
    *,
    trace_id: str,
    reason: str,
    driver_id: Any,
    customer_id: Any,
    details: Dict[str, Any],
) -> None:
    """
    実運用ではチケット作成、Slack通知、SIEM通知等に置き換える。
    ここでも実IDやPIIは出さない。
    """
    audit_log(
        event="customer_response_blocked_requires_review",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="blocked",
        metadata={
            "reason": reason,
            "details": details,
        },
    )


def assert_safe_response(
    payload: Dict[str, Any],
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
) -> None:
    """
    返却直前の最終ガード。
    禁止フィールドやカード番号らしき値が混入した場合は返却せず、
    人間確認に回す。
    """

    keys = set(payload.keys())

    forbidden_keys = keys & FORBIDDEN_FIELDS
    if forbidden_keys:
        details = {
            "forbidden_keys": sorted(forbidden_keys),
        }

        notify_security_team(
            trace_id=trace_id,
            reason="forbidden_fields_detected",
            driver_id=driver_id,
            customer_id=customer_id,
            details=details,
        )

        raise SecurityViolationError("Unsafe response blocked for manual review.")

    unexpected_keys = keys - ALLOWED_RESPONSE_FIELDS
    if unexpected_keys:
        details = {
            "unexpected_keys": sorted(unexpected_keys),
        }

        notify_security_team(
            trace_id=trace_id,
            reason="unexpected_response_fields_detected",
            driver_id=driver_id,
            customer_id=customer_id,
            details=details,
        )

        raise SecurityViolationError("Unexpected response fields blocked for manual review.")

    payload_text = json.dumps(payload, ensure_ascii=False, default=str)

    if CREDIT_CARD_RE.search(payload_text):
        notify_security_team(
            trace_id=trace_id,
            reason="possible_credit_card_detected",
            driver_id=driver_id,
            customer_id=customer_id,
            details={"detected": True},
        )

        raise SecurityViolationError("Possible credit card data blocked for manual review.")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ用:
    指定driverが担当するcustomer情報をDBから取得し、
    機密情報を含めずに返す。

    重要:
    - medical_history / credit_card などはSQLで取得しない
    - 返却はallowlist方式
    - ログにPIIを出さない
    """

    trace_id = str(uuid.uuid4())

    audit_log(
        event="customer_access_requested",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    try:
        with get_db_connection() as conn:
            # 機密カラムはSELECTしない。
            # driver_customer_assignmentsで、driverがそのcustomerを担当していることも確認する。
            row = conn.execute(
                """
                SELECT
                    c.customer_id,
                    c.full_name,
                    c.phone,
                    c.prefecture,
                    c.city,
                    c.checkin_status,
                    c.last_seen_at
                FROM customers c
                INNER JOIN driver_customer_assignments dca
                    ON dca.customer_id = c.customer_id
                WHERE
                    c.customer_id = ?
                    AND dca.driver_id = ?
                    AND c.deleted_at IS NULL
                LIMIT 1
                """,
                [customer_id, driver_id],
            ).fetchone()

        if row is None:
            audit_log(
                event="customer_access_denied_or_not_found",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_unauthorized",
            )
            raise NotFoundOrUnauthorizedError("Customer not found or not assigned to driver.")

        raw_record = dict(row)

        # L1: 業務運用 - 取得データのPII/機密検知
        l1_findings = detect_sensitive_content(raw_record)

        audit_log(
            event="customer_record_screened",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="screened",
            metadata={
                "finding_count": l1_findings["finding_count"],
                # 実値は含めない
                "finding_types": sorted({f["type"] for f in l1_findings["findings"]}),
            },
        )

        # L2: AI監査 - サニタイズによる最小権限化
        response_payload = sanitize_customer_record(row)

        # L3: 人間介入 - 返却直前ガード
        assert_safe_response(
            response_payload,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
        )

        # L4: 制度的正統性 - 安全な監査ログ
        audit_log(
            event="customer_access_completed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            metadata={
                "returned_fields": sorted(response_payload.keys()),
            },
        )

        return response_payload

    except Exception as exc:
        audit_log(
            event="customer_access_failed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="failed",
            metadata={
                "error_type": type(exc).__name__,
            },
        )
        raise