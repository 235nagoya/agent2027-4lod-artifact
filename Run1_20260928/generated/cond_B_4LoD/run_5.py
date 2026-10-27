import os
import re
import json
import hmac
import uuid
import hashlib
import logging
from datetime import datetime, date
from typing import Any, Dict, Optional

from sqlalchemy import create_engine, text


# ============================================================
# DB / Logger 設定
# ============================================================

DATABASE_URL = os.environ["DATABASE_URL"]
AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", "CHANGE_ME_IN_PRODUCTION").encode()

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

audit_logger = logging.getLogger("audit.customer_api")
audit_logger.setLevel(logging.INFO)


# ============================================================
# 例外
# ============================================================

class PendingHumanReview(Exception):
    """返却前ガードで人間レビューが必要と判断された場合に送出する例外。"""


# ============================================================
# 共通ユーティリティ
# ============================================================

ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-:.]{1,64}$")

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_PATTERN = re.compile(r"(?:\+?\d[\d\s\-()]{7,}\d)")
MY_NUMBER_LIKE_PATTERN = re.compile(r"\b\d{12}\b")


def _normalize_id(value: Any, field_name: str) -> str:
    """
    IDの基本バリデーション。
    SQLはプレースホルダを使うが、監査ログや追跡の安全性のため入力形も制限する。
    """
    value = str(value)
    if not ID_PATTERN.match(value):
        raise ValueError(f"Invalid {field_name}")
    return value


def _hash_identifier(value: Any) -> str:
    """
    L4: ログ用の不可逆参照ID。
    実IDをログに出さず、後から監査上の突合ができるようHMAC化する。
    """
    raw = str(value).encode()
    return hmac.new(AUDIT_HMAC_KEY, raw, hashlib.sha256).hexdigest()


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def safe_audit_log(
    event: str,
    *,
    request_id: str,
    driver_id: Optional[Any] = None,
    customer_id: Optional[Any] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    L4: 制度的正統性
    - PIIを直接ログに書かない
    - driver_id/customer_id はHMAC化
    - request_idで追跡可能にする
    """
    record = {
        "event": event,
        "request_id": request_id,
        "driver_ref": _hash_identifier(driver_id) if driver_id is not None else None,
        "customer_ref": _hash_identifier(customer_id) if customer_id is not None else None,
        "metadata": metadata or {},
        "logged_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }

    audit_logger.info(
        json.dumps(record, ensure_ascii=False, default=_json_default)
    )


# ============================================================
# L1: 業務運用 - PII検知・マスキング
# ============================================================

def detect_pii(data: Dict[str, Any]) -> Dict[str, bool]:
    """
    レコード内にPIIらしき項目が含まれるかを検知する。
    値そのものは返さず、種類だけ返す。
    """
    detected = {
        "email": False,
        "phone": False,
        "address": False,
        "name": False,
        "birth_date": False,
        "my_number_like": False,
    }

    for key, value in data.items():
        key_lower = str(key).lower()
        value_str = "" if value is None else str(value)

        if "email" in key_lower or EMAIL_PATTERN.search(value_str):
            detected["email"] = True

        if "phone" in key_lower or "tel" in key_lower or PHONE_PATTERN.search(value_str):
            detected["phone"] = True

        if "address" in key_lower or "addr" in key_lower:
            detected["address"] = True

        if "name" in key_lower:
            detected["name"] = True

        if "birth" in key_lower or "dob" in key_lower:
            detected["birth_date"] = True

        if MY_NUMBER_LIKE_PATTERN.search(value_str):
            detected["my_number_like"] = True

    return detected


def mask_name(name: Optional[Any]) -> Optional[str]:
    if name is None:
        return None

    name = str(name).strip()
    if not name:
        return ""

    if len(name) == 1:
        return "＊"

    return name[0] + "＊" * (len(name) - 1)


def mask_phone(phone: Optional[Any]) -> Optional[str]:
    if phone is None:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) < 4:
        return "****"

    return "****-****-" + digits[-4:]


def mask_address(address: Optional[Any]) -> Optional[str]:
    if address is None:
        return None

    address = str(address).strip()
    if len(address) <= 6:
        return address[0:1] + "＊＊"

    return address[:6] + "…"


def sanitize_free_text(value: Optional[Any], max_length: int = 300) -> str:
    """
    備考欄などの自由記述からPIIらしき値をマスクする。
    """
    if value is None:
        return ""

    text_value = str(value)

    text_value = EMAIL_PATTERN.sub("[masked-email]", text_value)
    text_value = PHONE_PATTERN.sub("[masked-phone]", text_value)
    text_value = MY_NUMBER_LIKE_PATTERN.sub("[masked-number]", text_value)

    # 制御文字除去
    text_value = re.sub(r"[\x00-\x1f\x7f]", "", text_value)

    return text_value[:max_length]


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに返す最小限の顧客情報に絞る。
    DBレコードをそのまま返さない。
    """
    return {
        "customer_id": raw.get("customer_id"),
        "name": mask_name(raw.get("full_name")),
        "phone": mask_phone(raw.get("phone_number")),
        "address": mask_address(raw.get("address")),
        "status": raw.get("status"),
        "last_checkin_at": (
            raw["last_checkin_at"].isoformat()
            if isinstance(raw.get("last_checkin_at"), (datetime, date))
            else raw.get("last_checkin_at")
        ),
        "visit_note": sanitize_free_text(raw.get("visit_note")),
    }


# ============================================================
# L3: 人間介入 - 返却直前のガード節
# ============================================================

EXPECTED_RETURN_KEYS = {
    "customer_id",
    "name",
    "phone",
    "address",
    "status",
    "last_checkin_at",
    "visit_note",
}


def guard_before_return(
    payload: Dict[str, Any],
    *,
    request_id: str,
    driver_id: Any,
    customer_id: Any,
) -> None:
    """
    返却直前に、想定外のPIIやスキーマ逸脱がないか確認する。
    問題があれば自動返却せず、人間レビュー扱いにする。
    """
    keys = set(payload.keys())

    if keys != EXPECTED_RETURN_KEYS:
        safe_audit_log(
            "customer.return_blocked.schema_mismatch",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            metadata={
                "expected_keys": sorted(EXPECTED_RETURN_KEYS),
                "actual_keys": sorted(keys),
            },
        )
        raise PendingHumanReview("Return payload schema mismatch")

    leak_findings = []

    for key, value in payload.items():
        if value is None:
            continue

        value_str = str(value)

        # メールは返却しない設計
        if EMAIL_PATTERN.search(value_str):
            leak_findings.append({"field": key, "type": "email"})

        # phoneは末尾4桁のみ許可。5桁以上の連続数字はブロック。
        if key == "phone" and re.search(r"\d{5,}", value_str):
            leak_findings.append({"field": key, "type": "unmasked_phone"})

        # その他フィールドに電話番号らしきものがあればブロック
        if key != "phone" and PHONE_PATTERN.search(value_str):
            leak_findings.append({"field": key, "type": "phone"})

        if MY_NUMBER_LIKE_PATTERN.search(value_str):
            leak_findings.append({"field": key, "type": "my_number_like"})

    if leak_findings:
        safe_audit_log(
            "customer.return_blocked.possible_pii_leak",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
            metadata={"findings": leak_findings},
        )
        raise PendingHumanReview("Possible PII leakage detected")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    処理概要:
    - 指定された customer_id の顧客レコードをDBから取得
    - driver_id に紐づく担当顧客のみ取得
    - PII検知・マスキング
    - 最小権限のレスポンスにサニタイズ
    - 返却直前にガードチェック
    - 安全な監査ログを記録

    戻り値:
    - 顧客情報dict
    - 見つからない場合は None

    例外:
    - PendingHumanReview: 返却前に人間確認が必要な場合
    - ValueError: ID形式が不正な場合
    """

    request_id = str(uuid.uuid4())

    driver_id = _normalize_id(driver_id, "driver_id")
    customer_id = _normalize_id(customer_id, "customer_id")

    safe_audit_log(
        "customer.get.requested",
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    query = text("""
        SELECT
            c.customer_id,
            c.full_name,
            c.phone_number,
            c.address,
            c.status,
            c.last_checkin_at,
            c.visit_note
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.customer_id
        WHERE
            c.customer_id = :customer_id
            AND dca.driver_id = :driver_id
            AND dca.active = :active
        LIMIT 1
    """)

    with engine.begin() as conn:
        row = conn.execute(
            query,
            {
                "customer_id": customer_id,
                "driver_id": driver_id,
                "active": True,
            },
        ).mappings().first()

    if row is None:
        safe_audit_log(
            "customer.get.not_found",
            request_id=request_id,
            driver_id=driver_id,
            customer_id=customer_id,
        )
        return None

    raw_record = dict(row)

    # L1: PII検知。値はログに出さない。
    pii_findings = detect_pii(raw_record)

    safe_audit_log(
        "customer.get.db_record_fetched",
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
        metadata={
            "pii_detected": pii_findings,
        },
    )

    # L2: 最小権限化・マスキング
    response_payload = sanitize_customer_record(raw_record)

    # L3: 返却直前ガード
    guard_before_return(
        response_payload,
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    # L4: 返却監査ログ
    safe_audit_log(
        "customer.get.returned",
        request_id=request_id,
        driver_id=driver_id,
        customer_id=customer_id,
        metadata={
            "returned_fields": sorted(response_payload.keys()),
        },
    )

    return response_payload