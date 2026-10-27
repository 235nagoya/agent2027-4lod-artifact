import os
import re
import hmac
import json
import hashlib
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional


logger = logging.getLogger("customer_api.audit")
logger.setLevel(logging.INFO)


class NotFoundOrAccessDenied(Exception):
    pass


class SecurityViolation(Exception):
    pass


# 返却禁止キー
SENSITIVE_KEY_PATTERNS = [
    "medical",
    "medical_history",
    "diagnosis",
    "disease",
    "medication",
    "allergy",
    "credit_card",
    "card_number",
    "cvv",
    "insurance_number",
    "my_number",
]


# 医療・カード情報らしき値の検知
MEDICAL_WORD_RE = re.compile(
    r"(病歴|既往歴|診断|服薬|投薬|疾患|認知症|糖尿病|高血圧|アレルギー)",
    re.IGNORECASE,
)

CARD_CANDIDATE_RE = re.compile(r"(?:\d[ -]*?){13,19}")


def _audit_hash(value: Any) -> str:
    """
    L4: 制度的正統性
    ログには driver_id / customer_id をそのまま出さず、HMAC化して追跡可能性だけ残す。
    """
    secret = os.environ.get("AUDIT_HMAC_KEY", "dev-only-change-me").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def _audit_log(
    event: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: Optional[str] = None,
) -> None:
    """
    L4: 安全なログ記録と追跡
    生の個人情報・生ID・DBレコード内容はログに出さない。
    """
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "driver_ref": _audit_hash(driver_id),
        "customer_ref": _audit_hash(customer_id),
        "outcome": outcome,
    }

    if reason:
        payload["reason"] = reason

    logger.info(json.dumps(payload, ensure_ascii=False))


def _mask_name(name: Optional[str]) -> Optional[str]:
    """
    L1: 業務運用
    業務に不要な個人情報はマスキングする。
    """
    if not name:
        return None

    name = str(name).strip()
    if len(name) <= 1:
        return "＊"

    return name[0] + "＊" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    L1: 電話番号のマスキング。
    下4桁だけ残す。
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) <= 4:
        return "＊" * len(digits)

    return "＊" * (len(digits) - 4) + digits[-4:]


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False

    checksum = 0
    parity = len(digits) % 2

    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def _contains_credit_card(value: str) -> bool:
    for candidate in CARD_CANDIDATE_RE.findall(value):
        if _luhn_check(candidate):
            return True
    return False


def _sanitize_text(value: Optional[str]) -> Optional[str]:
    """
    L2: AI監査
    自由記述欄からカード番号・医療情報らしき文字列を除去する。
    """
    if not value:
        return None

    text = str(value)

    # カード番号候補を除去
    text = CARD_CANDIDATE_RE.sub("[REDACTED_CARD]", text)

    # 医療情報らしき語を除去
    text = MEDICAL_WORD_RE.sub("[REDACTED_MEDICAL]", text)

    # 返却量を制限
    return text[:500]


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査
    DBレコードから返却してよい項目だけを allowlist で構成する。
    medical_history / credit_card はそもそもここに含めない。
    """
    raw = dict(row)

    return {
        "customer_id": raw["customer_id"],
        "display_name": _mask_name(raw.get("full_name")),
        "age": raw.get("age"),

        # 訪問・安否確認業務に必要なため住所は返す。
        # 不要な場合はここも町名レベル等にマスクする。
        "visit_address": raw.get("address"),

        "phone_masked": _mask_phone(raw.get("phone")),
        "emergency_contact": {
            "name": _mask_name(raw.get("emergency_contact_name")),
            "phone_masked": _mask_phone(raw.get("emergency_contact_phone")),
        },
        "care_level": raw.get("care_level"),
        "visit_notes": _sanitize_text(raw.get("visit_notes")),
    }


def _guard_no_sensitive_payload(data: Any, path: str = "$") -> None:
    """
    L3: 人間介入相当の最終ガード節
    返却直前に、禁止キー・カード番号・医療情報らしき値が混入していないか確認する。
    """
    if isinstance(data, dict):
        for key, value in data.items():
            lowered_key = str(key).lower()

            for sensitive_key in SENSITIVE_KEY_PATTERNS:
                if sensitive_key in lowered_key:
                    raise SecurityViolation(
                        f"sensitive key detected at {path}.{key}"
                    )

            _guard_no_sensitive_payload(value, f"{path}.{key}")

    elif isinstance(data, list):
        for i, item in enumerate(data):
            _guard_no_sensitive_payload(item, f"{path}[{i}]")

    elif isinstance(data, str):
        if _contains_credit_card(data):
            raise SecurityViolation(f"credit card-like value detected at {path}")

        if MEDICAL_WORD_RE.search(data):
            raise SecurityViolation(f"medical-like value detected at {path}")


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    db: sqlite3.Connection,
) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ用API。

    機能:
      - 指定 customer_id の顧客レコードをDBから取得する。

    セキュリティ:
      - driver_id に割り当てられた customer のみ取得可能。
      - medical_history / credit_card 等は返却しない。
      - SELECT * は使わない。
      - 返却直前にガードチェックを行う。
      - ログには生の個人情報を残さない。
    """

    _audit_log(
        event="get_customer_for_driver.request",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    if driver_id is None or customer_id is None:
        _audit_log(
            event="get_customer_for_driver.request",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="rejected",
            reason="missing_id",
        )
        raise ValueError("driver_id and customer_id are required")

    db.row_factory = sqlite3.Row

    try:
        # L1/L2:
        # SELECT * は禁止。
        # medical_history, credit_card などの機密カラムは取得対象に含めない。
        row = db.execute(
            """
            SELECT
                c.id AS customer_id,
                c.full_name,
                c.age,
                c.address,
                c.phone,
                c.emergency_contact_name,
                c.emergency_contact_phone,
                c.care_level,
                c.visit_notes
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
                event="get_customer_for_driver.result",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_access_denied",
            )
            raise NotFoundOrAccessDenied("customer not found or access denied")

        response = _sanitize_customer(row)

        # L3: 返却直前の最終チェック
        _guard_no_sensitive_payload(response)

        _audit_log(
            event="get_customer_for_driver.result",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
        )

        return response

    except SecurityViolation:
        _audit_log(
            event="get_customer_for_driver.result",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason="security_violation",
        )
        raise

    except NotFoundOrAccessDenied:
        raise

    except Exception:
        _audit_log(
            event="get_customer_for_driver.result",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
            reason="internal_error",
        )
        raise