import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import uuid
from datetime import date, datetime
from typing import Any, Dict, Iterable, Optional


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

AUDIT_LOG_SECRET = os.environ.get("AUDIT_LOG_SECRET", "replace-this-in-production")
audit_logger = logging.getLogger("audit.customer_access")


def _hash_for_audit(value: Any) -> str:
    """
    監査ログ用の不可逆ハッシュ。
    driver_id / customer_id などを平文ログに出さない。
    """
    raw = str(value).encode("utf-8")
    key = AUDIT_LOG_SECRET.encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()[:20]


def audit_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: Optional[str] = None,
    returned_fields: Optional[Iterable[str]] = None,
) -> None:
    """
    PII や医療情報、カード情報をログに出さない安全な監査ログ。
    """
    record = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_for_audit(driver_id),
        "customer_hash": _hash_for_audit(customer_id),
        "outcome": outcome,
    }

    if reason:
        record["reason"] = reason

    if returned_fields:
        record["returned_fields"] = sorted(returned_fields)

    audit_logger.info(json.dumps(record, ensure_ascii=False))


# =========================
# 共通定義
# =========================

class SecurityReviewRequired(Exception):
    """
    L3: 人間介入が必要な状態。
    機密情報の混入など、返却してはいけない可能性がある場合に発生させる。
    """
    pass


# 明示的に返してはいけないフィールド
SENSITIVE_FIELD_NAMES = {
    "medical_history",
    "medical_records",
    "diagnosis",
    "prescription",
    "medication",
    "allergy",
    "doctor_note",
    "credit_card",
    "credit_card_number",
    "card_number",
    "card_cvv",
    "cvv",
    "cvc",
    "card_expiry",
    "bank_account",
    "insurance_number",
    "my_number",
    "social_security_number",
}


# DBから取得してよいカラム。
# SELECT * は使わない。
DB_ALLOWED_COLUMNS = (
    "c.customer_id",
    "c.name",
    "c.phone",
    "c.address",
    "c.safety_status",
    "c.last_checkin_at",
)


# APIとして返却してよいフィールド。
# 内部認可用の assigned_driver_id などはここに入れない。
PUBLIC_RETURN_FIELDS = {
    "customer_id",
    "name",
    "phone",
    "address",
    "safety_status",
    "last_checkin_at",
}


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

def detect_sensitive_fields(data: Any, path: str = "") -> list[str]:
    """
    dict/list を再帰的に走査し、返却禁止フィールド名の混入を検知する。
    """
    found = []

    if isinstance(data, dict):
        for key, value in data.items():
            normalized_key = str(key).lower()
            current_path = f"{path}.{key}" if path else str(key)

            if normalized_key in SENSITIVE_FIELD_NAMES:
                found.append(current_path)

            found.extend(detect_sensitive_fields(value, current_path))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            found.extend(detect_sensitive_fields(item, f"{path}[{i}]"))

    return found


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return name

    if len(name) <= 1:
        return "*"

    return name[0] + "*" * (len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    電話番号は末尾4桁のみ残す。
    """
    if not phone:
        return phone

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "*" * len(digits)

    return "*" * (len(digits) - 4) + digits[-4:]


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は先頭の一部だけを残す。
    実運用では配送・訪問業務に必要な粒度に合わせて設計する。
    """
    if not address:
        return address

    visible_len = min(6, len(address))
    return address[:visible_len] + "..."


def serialize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return value


def l1_mask_and_detect(raw_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L1:
    - 機密フィールドの混入検知
    - 個人情報のマスキング
    """
    detected = detect_sensitive_fields(raw_record)
    if detected:
        raise SecurityReviewRequired(
            f"Sensitive fields detected before masking: {detected}"
        )

    masked = {
        "customer_id": raw_record.get("customer_id"),
        "name": mask_name(raw_record.get("name")),
        "phone": mask_phone(raw_record.get("phone")),
        "address": mask_address(raw_record.get("address")),
        "safety_status": raw_record.get("safety_status"),
        "last_checkin_at": serialize_value(raw_record.get("last_checkin_at")),
    }

    return masked


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー向けに必要最小限の情報だけを返す。
    allowlist ベースで返却データを構築する。
    """
    sanitized = {}

    for field in PUBLIC_RETURN_FIELDS:
        if field in record:
            sanitized[field] = record[field]

    return sanitized


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def _luhn_checksum_is_valid(number: str) -> bool:
    """
    クレジットカード番号らしき値の簡易検知用。
    """
    digits = [int(d) for d in number if d.isdigit()]
    checksum = 0
    parity = len(digits) % 2

    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def contains_credit_card_like_value(data: Any) -> bool:
    """
    値の中にカード番号らしき13〜19桁の数字列が混入していないか検査する。
    """
    if isinstance(data, dict):
        return any(contains_credit_card_like_value(v) for v in data.values())

    if isinstance(data, list):
        return any(contains_credit_card_like_value(v) for v in data)

    if isinstance(data, str):
        candidates = re.findall(r"(?:\d[\s-]?){13,19}", data)
        for candidate in candidates:
            normalized = re.sub(r"\D", "", candidate)
            if 13 <= len(normalized) <= 19 and _luhn_checksum_is_valid(normalized):
                return True

    return False


def guard_before_return(payload: Dict[str, Any]) -> None:
    """
    返却直前の最終防衛線。
    異常があれば返却せず、人間レビュー対象として例外化する。
    """
    unexpected_fields = set(payload.keys()) - PUBLIC_RETURN_FIELDS
    if unexpected_fields:
        raise SecurityReviewRequired(
            f"Unexpected return fields detected: {sorted(unexpected_fields)}"
        )

    sensitive_paths = detect_sensitive_fields(payload)
    if sensitive_paths:
        raise SecurityReviewRequired(
            f"Sensitive fields detected before return: {sensitive_paths}"
        )

    if contains_credit_card_like_value(payload):
        raise SecurityReviewRequired(
            "Credit-card-like value detected before return"
        )


# =========================
# API実装
# =========================

def get_customer_for_driver(
    db: sqlite3.Connection,
    driver_id: int,
    customer_id: int,
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    機能:
    - DBから指定された customer_id の顧客レコードを取得する。
    - driver_id に紐づく顧客のみ取得可能にする。

    セキュリティ:
    - medical_history や credit_card などの機密情報は返却しない。
    - SELECT * を禁止し、許可カラムのみ取得する。
    - 返却直前にガード節で最終チェックする。
    - 監査ログには平文の個人情報を出さない。

    戻り値:
    - 顧客が存在し、かつ driver_id に紐づく場合: マスキング済み顧客情報
    - 存在しない、または権限がない場合: None
    """

    trace_id = str(uuid.uuid4())

    audit_log(
        "customer_access.requested",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    try:
        # DBから取得する時点で allowlist カラムのみに限定する。
        # medical_history / credit_card などはSQLに含めない。
        sql = f"""
            SELECT
                {", ".join(DB_ALLOWED_COLUMNS)}
            FROM customers c
            INNER JOIN driver_customer_assignments dca
                ON dca.customer_id = c.customer_id
            WHERE
                c.customer_id = ?
                AND dca.driver_id = ?
                AND c.deleted_at IS NULL
            LIMIT 1
        """

        cursor = db.execute(sql, (customer_id, driver_id))
        row = cursor.fetchone()

        if row is None:
            # 顧客不存在と権限なしを区別してログ・レスポンスに出さない。
            audit_log(
                "customer_access.finished",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_forbidden",
            )
            return None

        if isinstance(row, sqlite3.Row):
            raw_record = dict(row)
        else:
            columns = [desc[0] for desc in cursor.description]
            raw_record = dict(zip(columns, row))

        # L1: マスキング・機密フィールド検知
        masked_record = l1_mask_and_detect(raw_record)

        # L2: 最小権限化サニタイズ
        payload = sanitize_customer_for_driver(masked_record)

        # L3: 返却直前ガード
        guard_before_return(payload)

        # L4: 安全な監査ログ
        audit_log(
            "customer_access.finished",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            returned_fields=payload.keys(),
        )

        return payload

    except SecurityReviewRequired as exc:
        # ここで人間レビュー・SOC通知・チケット起票などに接続する想定。
        audit_log(
            "customer_access.blocked",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason=str(exc),
        )
        raise

    except Exception:
        # 詳細なDBエラーやSQL、PIIをログに出さない。
        audit_log(
            "customer_access.failed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise