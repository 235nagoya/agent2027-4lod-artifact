from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import uuid
from typing import Any


DB_PATH = os.environ.get("APP_DB_PATH", "app.db")
AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", "change-me-in-production").encode()

audit_logger = logging.getLogger("audit.customer")


class CustomerNotFound(Exception):
    """顧客が存在しない、または当該ドライバーに参照権限がない場合。"""


class SecurityReviewRequired(Exception):
    """返却直前のガードで危険データを検知した場合。"""


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_LIKE_RE = re.compile(r"\d{10,}")  # ハイフン除去済みの電話番号などを想定

PII_FIELD_TOKENS = (
    "name",
    "full_name",
    "phone",
    "mobile",
    "email",
    "address",
    "birth",
    "date_of_birth",
    "emergency",
    "medical",
)

RAW_PII_FIELDS = {
    "full_name",
    "name",
    "phone",
    "phone_number",
    "mobile",
    "email",
    "address",
    "date_of_birth",
    "emergency_contact_name",
    "emergency_contact_phone",
    "medical_note",
}

ALLOWED_RETURN_KEYS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_masked",
    "age_band",
    "care_level",
    "safety_status",
    "last_checkin_at",
    "updated_at",
    "trace_id",
}

FORBIDDEN_RETURN_KEYS = {
    "full_name",
    "name",
    "phone",
    "phone_number",
    "mobile",
    "email",
    "address",
    "date_of_birth",
    "emergency_contact_name",
    "emergency_contact_phone",
    "medical_note",
}


def _hash_for_audit(value: Any) -> str:
    """
    L4: 監査ログ用の不可逆ハッシュ。
    ログには driver_id / customer_id の生値を残さない。
    """
    raw = str(value).encode()
    return hmac.new(AUDIT_HMAC_KEY, raw, hashlib.sha256).hexdigest()


def _audit_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any | None = None,
    customer_id: Any | None = None,
    **attrs: Any,
) -> None:
    """
    L4: 安全なログ記録と追跡。
    PIIの生値は出さず、IDはHMAC化して記録する。
    """
    payload: dict[str, Any] = {
        "event": event,
        "trace_id": trace_id,
        "at": dt.datetime.now(dt.UTC).isoformat(),
    }

    if driver_id is not None:
        payload["driver_hash"] = _hash_for_audit(driver_id)

    if customer_id is not None:
        payload["customer_hash"] = _hash_for_audit(customer_id)

    payload.update(attrs)

    audit_logger.info(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _detect_pii_fields(record: dict[str, Any]) -> list[str]:
    """
    L1: 業務運用レベルで、取得データ内の個人情報らしき項目を検知する。
    値そのものは返さず、フィールド名のみを扱う。
    """
    detected: set[str] = set()

    for key, value in record.items():
        lower_key = key.lower()

        if any(token in lower_key for token in PII_FIELD_TOKENS):
            detected.add(key)
            continue

        if value is None:
            continue

        text = str(value)

        if EMAIL_RE.search(text):
            detected.add(key)
            continue

        digits_only = re.sub(r"\D", "", text)
        if PHONE_LIKE_RE.search(digits_only):
            detected.add(key)

    return sorted(detected)


def _mask_name(value: Any) -> str | None:
    """
    L1: 氏名マスキング。
    """
    if value is None:
        return None

    name = str(value).strip()
    if not name:
        return None

    if len(name) == 1:
        return "＊"

    return name[0] + "＊" * (len(name) - 1)


def _mask_phone(value: Any) -> str | None:
    """
    L1: 電話番号マスキング。
    下4桁のみ残す。
    """
    if value is None:
        return None

    digits = re.sub(r"\D", "", str(value))
    if not digits:
        return None

    if len(digits) <= 4:
        return "****"

    return "****-****-" + digits[-4:]


def _mask_address(value: Any) -> str | None:
    """
    L1: 住所マスキング。
    ここでは詳細住所は返さず、マスク済みであることだけ返す。
    """
    if value is None:
        return None

    address = str(value).strip()
    if not address:
        return None

    return "住所マスク済み"


def _to_age_band(date_of_birth: Any) -> str | None:
    """
    生年月日そのものは返さず、年代に変換する。
    """
    if date_of_birth is None:
        return None

    try:
        dob = dt.date.fromisoformat(str(date_of_birth)[:10])
    except ValueError:
        return None

    today = dt.date.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

    if age < 0:
        return None

    if age >= 100:
        return "100歳以上"

    return f"{age // 10 * 10}代"


def _sanitize_customer_for_driver(record: dict[str, Any], *, trace_id: str) -> dict[str, Any]:
    """
    L2: AI監査・サニタイズ関数による最小権限化。
    DBから取得した生データをそのまま返さず、ドライバー画面に必要な最小項目だけに絞る。
    """
    sanitized = {
        "customer_id": str(record["customer_id"]),
        "display_name": _mask_name(record.get("full_name") or record.get("name")),
        "phone_masked": _mask_phone(record.get("phone_number") or record.get("phone")),
        "address_masked": _mask_address(record.get("address")),
        "age_band": _to_age_band(record.get("date_of_birth")),
        "care_level": record.get("care_level"),
        "safety_status": record.get("safety_status"),
        "last_checkin_at": record.get("last_checkin_at"),
        "updated_at": record.get("updated_at"),
        "trace_id": trace_id,
    }

    return {key: value for key, value in sanitized.items() if value is not None}


def _guard_before_return(payload: dict[str, Any], raw_record: dict[str, Any]) -> None:
    """
    L3: 人間介入相当の返却直前ガード。
    許可されていないキーや、未マスクPIIらしき値を検知した場合は返却を止める。
    実運用ではこの例外をチケット化し、人間レビューに回す。
    """
    unknown_keys = set(payload.keys()) - ALLOWED_RETURN_KEYS
    if unknown_keys:
        raise SecurityReviewRequired(f"Unexpected response keys: {sorted unknown_keys}")

    forbidden_keys = set(payload.keys()) & FORBIDDEN_RETURN_KEYS
    if forbidden_keys:
        raise SecurityReviewRequired(f"Forbidden response keys: {sorted(forbidden_keys)}")

    serialized = json.dumps(payload, ensure_ascii=False)

    if EMAIL_RE.search(serialized):
        raise SecurityReviewRequired("Email-like value detected in response")

    digits_only = re.sub(r"\D", "", serialized)
    if PHONE_LIKE_RE.search(digits_only):
        raise SecurityReviewRequired("Unmasked phone-like value detected in response")

    for field in RAW_PII_FIELDS:
        raw_value = raw_record.get(field)
        if raw_value is None:
            continue

        raw_text = str(raw_value).strip()
        if len(raw_text) >= 4 and raw_text in serialized:
            raise SecurityReviewRequired(f"Raw PII value leaked from field: {field}")


def get_customer_for_driver(driver_id: str, customer_id: str) -> dict[str, Any]:
    """
    高齢者向け安否確認アプリ用API。

    指定された customer_id の顧客レコードをDBから取得し、
    ドライバーに返してよい最小限の情報だけを返す。

    前提テーブル例:
      - customers
          customer_id
          full_name
          phone_number
          email
          address
          date_of_birth
          care_level
          safety_status
          last_checkin_at
          updated_at

      - driver_customer_assignments
          driver_id
          customer_id
          active
    """
    trace_id = uuid.uuid4().hex

    _audit_log(
        "customer.fetch.start",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # DBから指定 customer_id の顧客レコードを取得。
            # driver_id との割当もJOINし、最小権限で取得対象を限定する。
            row = conn.execute(
                """
                SELECT
                    c.customer_id,
                    c.full_name,
                    c.phone_number,
                    c.email,
                    c.address,
                    c.date_of_birth,
                    c.care_level,
                    c.safety_status,
                    c.last_checkin_at,
                    c.updated_at
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.customer_id
                WHERE
                    c.customer_id = ?
                    AND a.driver_id = ?
                    AND a.active = 1
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            _audit_log(
                "customer.fetch.not_found_or_forbidden",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                decision="deny",
            )
            raise CustomerNotFound("customer not found or access denied")

        raw_record = dict(row)

        # L1: データ内PII検知。
        pii_fields = _detect_pii_fields(raw_record)

        _audit_log(
            "customer.fetch.loaded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            pii_field_count=len(pii_fields),
            pii_fields=pii_fields,
        )

        # L2: サニタイズ・最小権限化。
        response = _sanitize_customer_for_driver(raw_record, trace_id=trace_id)

        # L3: 返却直前ガード。
        _guard_before_return(response, raw_record)

        # L4: 安全な成功ログ。
        _audit_log(
            "customer.fetch.success",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            decision="allow",
            response_fields=sorted(response.keys()),
        )

        return response

    except SecurityReviewRequired as exc:
        _audit_log(
            "customer.fetch.security_review_required",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            decision="block",
            error_type=type(exc).__name__,
        )
        raise

    except CustomerNotFound:
        raise

    except Exception as exc:
        _audit_log(
            "customer.fetch.error",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            decision="error",
            error_type=type(exc).__name__,
        )
        raise