from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import sqlite3
import uuid
from typing import Any, Mapping, Optional


logger = logging.getLogger(__name__)

LOG_HASH_SECRET = os.environ.get("LOG_HASH_SECRET", "change-me-in-production").encode("utf-8")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\- ()]{7,}\d)(?!\d)")

PII_KEYWORDS = {
    "name",
    "address",
    "phone",
    "tel",
    "email",
    "birth",
    "dob",
    "medical",
    "emergency",
}

ALLOWED_RESPONSE_FIELDS = frozenset(
    {
        "customer_id",
        "name",
        "address",
        "phone",
        "driver_note",
        "last_checkin_status",
        "last_checkin_at",
        "trace_id",
    }
)

REQUIRED_RESPONSE_FIELDS = frozenset(
    {
        "customer_id",
        "name",
        "address",
        "trace_id",
    }
)


def get_db_connection() -> sqlite3.Connection:
    """
    実運用ではアプリ側のDB接続取得処理に差し替えてください。
    """
    raise NotImplementedError("DB connection provider is not configured.")


# ---------------------------------------------------------------------
# L4: 制度的正統性
# 安全なログ記録と追跡
# ---------------------------------------------------------------------

def _hash_for_log(value: Any) -> str:
    """
    ログ用の疑似ID化。
    driver_id / customer_id をそのままログに出さず、追跡可能なハッシュにする。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(LOG_HASH_SECRET, raw, hashlib.sha256).hexdigest()[:16]


def _safe_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    **fields: Any,
) -> None:
    """
    PIIを含めずに監査ログを残す。
    """
    logger.info(
        event,
        extra={
            "trace_id": trace_id,
            "driver_ref": _hash_for_log(driver_id),
            "customer_ref": _hash_for_log(customer_id),
            **fields,
        },
    )


# ---------------------------------------------------------------------
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# ---------------------------------------------------------------------

def _looks_like_pii(key: str, value: Any) -> bool:
    if value is None:
        return False

    key_lower = key.lower()
    value_text = str(value)

    if any(word in key_lower for word in PII_KEYWORDS):
        return True

    if EMAIL_RE.search(value_text):
        return True

    if PHONE_RE.search(value_text):
        return True

    return False


def _mask_value(key: str, value: Any) -> Any:
    if value is None:
        return None

    key_lower = key.lower()
    text = str(value)

    if "email" in key_lower or EMAIL_RE.search(text):
        return EMAIL_RE.sub("[masked-email]", text)

    if "phone" in key_lower or "tel" in key_lower or PHONE_RE.search(text):
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return f"***-***-{digits[-4:]}"
        return "[masked-phone]"

    if "address" in key_lower:
        return "[masked-address]"

    if "name" in key_lower:
        return text[:1] + "**" if text else "[masked-name]"

    if "birth" in key_lower or "dob" in key_lower:
        return "[masked-birth-date]"

    if "medical" in key_lower:
        return "[masked-medical-info]"

    return "[masked-pii]"


def _detect_and_mask_pii(record: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """
    取得した顧客レコード内のPIIを検知し、監査・運用確認用にマスク済みデータを作る。
    """
    masked: dict[str, Any] = {}
    detected_fields: list[str] = []

    for key, value in record.items():
        if _looks_like_pii(key, value):
            detected_fields.append(key)
            masked[key] = _mask_value(key, value)
        else:
            masked[key] = value

    return masked, detected_fields


# ---------------------------------------------------------------------
# L2: AI監査
# サニタイズ関数による最小権限化
# ---------------------------------------------------------------------

def _redact_free_text(text: Optional[str]) -> Optional[str]:
    """
    自由記述の備考からメールアドレス・電話番号などをマスクする。
    """
    if not text:
        return None

    text = EMAIL_RE.sub("[masked-email]", text)
    text = PHONE_RE.sub("[masked-phone]", text)

    # ドライバー業務に必要な範囲に制限
    return text[:500]


def _sanitize_customer_for_driver(raw: Mapping[str, Any]) -> dict[str, Any]:
    """
    ドライバーに返してよい項目だけをallowlistで構成する。
    """
    response = {
        "customer_id": raw.get("customer_id"),
        "name": raw.get("name"),
        "address": raw.get("address"),
        "phone": raw.get("phone"),
        "driver_note": _redact_free_text(raw.get("driver_note")),
        "last_checkin_status": raw.get("last_checkin_status"),
        "last_checkin_at": raw.get("last_checkin_at"),
    }

    return {k: v for k, v in response.items() if v is not None}


# ---------------------------------------------------------------------
# L3: 人間介入
# 返却直前でのガード節によるチェック
# ---------------------------------------------------------------------

def _response_guard(
    response: Mapping[str, Any],
    *,
    raw_record: Mapping[str, Any],
    driver_id: Any,
) -> tuple[bool, str]:
    """
    返却直前の最終チェック。
    """
    if raw_record.get("authorized_driver_id") != driver_id:
        return False, "driver_assignment_mismatch"

    extra_fields = set(response.keys()) - ALLOWED_RESPONSE_FIELDS
    if extra_fields:
        return False, f"unexpected_response_fields:{sorted(extra_fields)}"

    missing_fields = REQUIRED_RESPONSE_FIELDS - set(response.keys())
    if missing_fields:
        return False, f"missing_required_fields:{sorted(missing_fields)}"

    for field in REQUIRED_RESPONSE_FIELDS:
        if response.get(field) in ("", None):
            return False, f"empty_required_field:{field}"

    return True, "ok"


# ---------------------------------------------------------------------
# API本体
# ---------------------------------------------------------------------

def get_customer_for_driver(
    driver_id: str,
    customer_id: str,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用の顧客情報取得API。

    指定された customer_id の顧客レコードをDBから取得し、
    driver_id に紐づくドライバー業務に必要な最小限の情報だけを返す。

    戻り値:
        dict: 取得・サニタイズ済み顧客情報
        None: 該当顧客が存在しない、または当該driverに紐づいていない場合
    """
    if not driver_id:
        raise ValueError("driver_id is required")

    if not customer_id:
        raise ValueError("customer_id is required")

    trace_id = uuid.uuid4().hex
    owns_connection = conn is None

    _safe_log(
        "customer_lookup_started",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    if conn is None:
        conn = get_db_connection()

    try:
        conn.row_factory = sqlite3.Row

        sql = """
            SELECT
                c.customer_id,
                c.name,
                c.address,
                c.phone,
                c.driver_note,
                s.last_checkin_status,
                s.last_checkin_at,
                a.driver_id AS authorized_driver_id
            FROM customers c
            JOIN driver_customer_assignments a
                ON a.customer_id = c.customer_id
               AND a.driver_id = ?
               AND a.active = 1
            LEFT JOIN customer_safety_status s
                ON s.customer_id = c.customer_id
            WHERE c.customer_id = ?
            LIMIT 1
        """

        row = conn.execute(sql, (driver_id, customer_id)).fetchone()

        if row is None:
            _safe_log(
                "customer_lookup_not_found",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
            )
            return None

        raw_record = dict(row)

        # L1: 取得データ内のPII検知・マスキング
        masked_record, pii_fields = _detect_and_mask_pii(raw_record)

        _safe_log(
            "customer_record_fetched",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            pii_fields=pii_fields,
            masked_preview={
                key: masked_record[key]
                for key in pii_fields[:5]
                if key in masked_record
            },
        )

        # L2: 返却データを最小権限化
        response = _sanitize_customer_for_driver(raw_record)
        response["trace_id"] = trace_id

        # L3: 返却直前の最終ガード
        ok, reason = _response_guard(
            response,
            raw_record=raw_record,
            driver_id=driver_id,
        )

        if not ok:
            _safe_log(
                "customer_response_blocked",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                reason=reason,
            )
            raise PermissionError("customer response blocked by guard")

        # L4: 安全な追跡ログ
        _safe_log(
            "customer_lookup_succeeded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            returned_fields=sorted(response.keys()),
        )

        return response

    finally:
        if owns_connection:
            conn.close()