import os
import re
import hmac
import json
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional, Set


DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "change-me-in-production").encode("utf-8")

logger = logging.getLogger(__name__)


# 返却・内部処理で禁止する機密キー
SENSITIVE_KEYS = {
    "medical_history",
    "medical_histories",
    "diagnosis",
    "disease",
    "medicine",
    "medication",
    "allergy",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "my_number",
    "bank_account",
    "insurance_number",
}


# driver に返してよい最小限の項目
SAFE_RETURN_KEYS = {
    "customer_id",
    "display_name_masked",
    "phone_masked",
    "address_masked",
    "emergency_contact_name_masked",
    "emergency_contact_phone_masked",
    "last_checkin_at",
}


def _audit_hash(value: Any) -> str:
    """
    L4: 制度的正統性
    監査ログ用に ID を HMAC 化する。
    生の driver_id / customer_id をログに出さない。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_SECRET, raw, hashlib.sha256).hexdigest()[:20]


def _safe_audit_log(event: str, **fields: Any) -> None:
    """
    L4: 安全なログ記録と追跡。
    PII や機密情報を含めず、追跡に必要なハッシュ・結果のみ記録する。
    """
    logger.info(
        json.dumps(
            {
                "event": event,
                **fields,
            },
            ensure_ascii=False,
        )
    )


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    if len(name) <= 1:
        return "＊"
    return name[0] + "＊" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    # 下4桁のみ残す
    return "****-****-" + digits[-4:]


def _mask_address(address: Optional[str]) -> Optional[str]:
    if not address:
        return None

    # 業務上の識別に必要な範囲だけ残す例
    # 実運用では「市区町村まで」など業務ルールに合わせて調整する
    visible_len = min(6, len(address))
    return address[:visible_len] + "…"


def _looks_like_credit_card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False

    # Luhn check
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def _detect_pii(record: Dict[str, Any]) -> Set[str]:
    """
    L1: 業務運用
    データ内の個人情報・機密情報らしき値を検知する。
    検知結果は監査用メタ情報としてのみ扱い、値そのものはログに出さない。
    """
    detected: Set[str] = set()

    email_pattern = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
    phone_pattern = re.compile(r"\+?\d[\d\-\s]{8,}\d")

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in SENSITIVE_KEYS:
            detected.add(f"sensitive_key:{key_lower}")

        if not isinstance(value, str):
            continue

        if email_pattern.search(value):
            detected.add("email")

        if phone_pattern.search(value):
            detected.add("phone")

        if _looks_like_credit_card(value):
            detected.add("credit_card_like_value")

    return detected


def _mask_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L1: 業務運用
    DBから取得した個人情報を返却用にマスキングする。
    """
    return {
        "customer_id": record.get("customer_id"),
        "display_name_masked": _mask_name(record.get("display_name")),
        "phone_masked": _mask_phone(record.get("phone")),
        "address_masked": _mask_address(record.get("address")),
        "emergency_contact_name_masked": _mask_name(
            record.get("emergency_contact_name")
        ),
        "emergency_contact_phone_masked": _mask_phone(
            record.get("emergency_contact_phone")
        ),
        "last_checkin_at": record.get("last_checkin_at"),
    }


def _sanitize_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: AI監査
    サニタイズ関数で最小権限化する。
    allow-list に含まれる項目だけ返す。
    """
    sanitized: Dict[str, Any] = {}

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in SENSITIVE_KEYS:
            continue

        if key in SAFE_RETURN_KEYS:
            sanitized[key] = value

    return sanitized


def _assert_no_sensitive_leak(payload: Dict[str, Any]) -> None:
    """
    L3: 人間介入
    返却直前のガード節。
    機密キーやクレジットカードらしき値が混入していないか確認する。
    """
    for key, value in payload.items():
        key_lower = key.lower()

        if key_lower in SENSITIVE_KEYS:
            raise RuntimeError(f"Sensitive field detected before response: {key}")

        if isinstance(value, str):
            if _looks_like_credit_card(value):
                raise RuntimeError("Credit-card-like value detected before response")

            if re.search(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                raise RuntimeError("Email-like value detected before response")


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用API。

    - 指定 customer_id の顧客レコードをDBから取得する
    - driver_id に割り当てられた顧客のみ取得可能
    - medical_history / credit_card 等の機密情報は返却しない
    - 返却前にマスキング、サニタイズ、ガードチェックを行う
    """

    driver_hash = _audit_hash(driver_id)
    customer_hash = _audit_hash(customer_id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # 機密列を取得しない。
            # SELECT * は使用しない。
            row = conn.execute(
                """
                SELECT
                    c.customer_id,
                    c.display_name,
                    c.phone,
                    c.address,
                    c.emergency_contact_name,
                    c.emergency_contact_phone,
                    c.last_checkin_at
                FROM customers c
                INNER JOIN driver_customer_assignments dca
                    ON dca.customer_id = c.customer_id
                WHERE
                    c.customer_id = ?
                    AND dca.driver_id = ?
                    AND dca.active = 1
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            _safe_audit_log(
                "get_customer_for_driver.not_found_or_forbidden",
                driver_hash=driver_hash,
                customer_hash=customer_hash,
                result="none",
            )
            return None

        raw_record = dict(row)

        # L1: 個人情報・機密情報の検知
        pii_flags = _detect_pii(raw_record)

        # L1: 個人情報のマスキング
        masked_record = _mask_customer_record(raw_record)

        # L2: サニタイズによる最小権限化
        response_payload = _sanitize_for_driver(masked_record)

        # L3: 返却直前のガード節
        _assert_no_sensitive_leak(response_payload)

        # L4: 安全な監査ログ
        _safe_audit_log(
            "get_customer_for_driver.success",
            driver_hash=driver_hash,
            customer_hash=customer_hash,
            result="success",
            detected_flags=sorted(pii_flags),
            returned_fields=sorted(response_payload.keys()),
        )

        return response_payload

    except Exception as exc:
        _safe_audit_log(
            "get_customer_for_driver.error",
            driver_hash=driver_hash,
            customer_hash=customer_hash,
            result="error",
            error_type=type(exc).__name__,
        )
        raise