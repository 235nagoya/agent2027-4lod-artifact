import os
import re
import json
import hmac
import hashlib
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional


DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "change-me-in-production").encode("utf-8")

audit_logger = logging.getLogger("audit.customer_access")


# 返却・混入を禁止する機密情報キー
SENSITIVE_FIELD_TOKENS = {
    "medical_history",
    "medical",
    "diagnosis",
    "disease",
    "medicine",
    "medication",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "insurance_number",
    "bank_account",
    "password",
    "secret",
    "token",
}


# 返却を許可する最小限のキー
ALLOWED_RESPONSE_KEYS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_summary",
    "status",
    "latest_checkin_at",
    "emergency_contact_name",
    "emergency_contact_phone_masked",
}


class SafetyReviewRequired(Exception):
    """返却前安全検査に失敗し、人間による確認が必要な場合に使う例外。"""


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_hash(value: Any) -> str:
    """
    L4: 制度的正統性
    監査ログに生の driver_id / customer_id を出さないためのHMACハッシュ。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_SECRET, raw, hashlib.sha256).hexdigest()


def _audit_log(
    event: str,
    *,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: Optional[str] = None,
) -> None:
    """
    L4: 制度的正統性
    安全なログ記録と追跡。
    PIIや医療情報、カード情報、住所、電話番号はログに出さない。
    """
    payload = {
        "ts": _now_iso(),
        "event": event,
        "driver_hash": _safe_hash(driver_id),
        "customer_hash": _safe_hash(customer_id),
        "outcome": outcome,
    }
    if reason:
        payload["reason"] = reason

    audit_logger.info(json.dumps(payload, ensure_ascii=False))


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    L1: 業務運用
    電話番号をマスキングする。
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    return "*" * (len(digits) - 4) + digits[-4:]


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    L1: 業務運用
    詳細住所をそのまま返さず、地域レベルに丸める。
    実運用では住所正規化ライブラリ等で都道府県・市区町村単位にする。
    """
    if not address:
        return None

    # 簡易例: 先頭20文字までに制限し、それ以降を伏せる
    if len(address) <= 20:
        return address

    return address[:20] + "..."


def _contains_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(token in normalized for token in SENSITIVE_FIELD_TOKENS)


def _detect_sensitive_fields(record: Dict[str, Any]) -> None:
    """
    L1: 業務運用
    DBから取得したデータに機密カラムが混入していないか検知する。
    将来、SQLが変更されて medical_history や credit_card が混入した場合に止める。
    """
    leaked_keys = [key for key in record.keys() if _contains_sensitive_key(key)]

    if leaked_keys:
        raise SafetyReviewRequired(
            f"Sensitive fields detected before sanitization: {leaked_keys}"
        )


def _sanitize_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: AI監査
    サニタイズ関数による最小権限化。
    allowlist方式で、返却してよい項目だけを組み立てる。
    """
    sanitized = {
        "customer_id": record.get("customer_id"),
        "display_name": record.get("full_name"),
        "phone_masked": _mask_phone(record.get("phone")),
        "address_summary": _mask_address(record.get("address")),
        "status": record.get("status"),
        "latest_checkin_at": record.get("latest_checkin_at"),
        "emergency_contact_name": record.get("emergency_contact_name"),
        "emergency_contact_phone_masked": _mask_phone(
            record.get("emergency_contact_phone")
        ),
    }

    # allowlistで最終整形
    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_RESPONSE_KEYS
    }


def _guard_before_return(payload: Dict[str, Any]) -> None:
    """
    L3: 人間介入
    返却直前のガード節。
    禁止キーやクレジットカードらしき連続数字があれば返却を止め、
    人間確認が必要な状態にする。
    """
    for key in payload.keys():
        if _contains_sensitive_key(key):
            raise SafetyReviewRequired(
                f"Sensitive key detected in response payload: {key}"
            )

    unexpected_keys = set(payload.keys()) - ALLOWED_RESPONSE_KEYS
    if unexpected_keys:
        raise SafetyReviewRequired(
            f"Unexpected response keys detected: {sorted(unexpected_keys)}"
        )

    # クレジットカード番号らしき13〜19桁の連続数字を検知
    card_like_pattern = re.compile(r"\b\d{13,19}\b")

    for key, value in payload.items():
        if isinstance(value, str) and card_like_pattern.search(value):
            raise SafetyReviewRequired(
                f"Card-like numeric sequence detected in field: {key}"
            )


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    機能要求:
    - DBから指定された customer_id の顧客レコードを取得する。

    ネガティブ制約:
    - medical_history や credit_card などの機密情報を返却データに含めない。

    返却:
    - 担当ドライバーがアクセス可能な場合: サニタイズ済みの顧客情報 dict
    - 存在しない、または担当外の場合: None
      ※ 顧客IDの存在有無を推測されないよう同じ None にする。
    """

    if driver_id is None or customer_id is None:
        raise ValueError("driver_id and customer_id are required")

    _audit_log(
        "customer_lookup_started",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    try:
        with get_db_connection() as conn:
            row = conn.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.full_name AS full_name,
                    c.phone AS phone,
                    c.address AS address,
                    c.status AS status,
                    c.latest_checkin_at AS latest_checkin_at,
                    c.emergency_contact_name AS emergency_contact_name,
                    c.emergency_contact_phone AS emergency_contact_phone
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
                "customer_lookup_finished",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_forbidden",
            )
            return None

        record = dict(row)

        # L1: 業務運用 - 機密カラム混入検知
        _detect_sensitive_fields(record)

        # L2: AI監査 - 最小権限の返却データへサニタイズ
        response_payload = _sanitize_customer_record(record)

        # L3: 人間介入 - 返却直前ガード
        _guard_before_return(response_payload)

        # L4: 制度的正統性 - 安全な監査ログ
        _audit_log(
            "customer_lookup_finished",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
        )

        return response_payload

    except SafetyReviewRequired as exc:
        _audit_log(
            "customer_lookup_blocked",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked_for_human_review",
            reason=str(exc),
        )
        raise

    except Exception:
        _audit_log(
            "customer_lookup_failed",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise