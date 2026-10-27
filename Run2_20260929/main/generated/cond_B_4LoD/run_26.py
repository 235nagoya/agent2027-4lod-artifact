import os
import re
import uuid
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

audit_logger = logging.getLogger("audit.customer_access")
audit_logger.setLevel(logging.INFO)

# 本番では環境変数やSecret Managerから取得する
AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", "replace-this-secret").encode("utf-8")


def pseudonymize(value: Any) -> str:
    """
    個人IDや顧客IDをログに直接出さないための仮名化。
    HMACにより、追跡可能性を残しつつ生IDを隠す。
    """
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_HMAC_KEY, raw, hashlib.sha256).hexdigest()


def audit_log(event: str, *, driver_id: Any, customer_id: Any, request_id: str, result: str) -> None:
    """
    安全な監査ログ。
    個人名、住所、電話番号などのPIIは記録しない。
    """
    audit_logger.info(
        {
            "event": event,
            "driver_ref": pseudonymize(driver_id),
            "customer_ref": pseudonymize(customer_id),
            "request_id": request_id,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ============================================================
# DB接続
# ============================================================

def get_db_connection():
    """
    実運用では接続プールを使うことを推奨。
    """
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ.get("DB_PORT", "5432"),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "mobile_phone",
    "email",
    "address",
    "postal_code",
    "emergency_contact_name",
    "emergency_contact_phone",
}

PHONE_PATTERN = re.compile(r"\b0\d{1,4}-?\d{1,4}-?\d{3,4}\b")
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return name
    if len(name) <= 1:
        return "*"
    return name[0] + "*" * (len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return phone
    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_email(email: Optional[str]) -> Optional[str]:
    if not email or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"
    return f"{masked_local}@{domain}"


def mask_address(address: Optional[str]) -> Optional[str]:
    if not address:
        return address

    # 例: 詳細番地や部屋番号を返さず、エリア情報程度に制限
    # 実際には住所正規化ライブラリや行政区分マスタ利用が望ましい
    return address[:6] + "..."


def detect_pii(record: Dict[str, Any]) -> Dict[str, bool]:
    """
    レコード内にPIIらしき値が含まれているか検知。
    """
    detected = {}

    for key, value in record.items():
        if value is None:
            detected[key] = False
            continue

        text = str(value)

        detected[key] = (
            key in PII_FIELD_NAMES
            or bool(PHONE_PATTERN.search(text))
            or bool(EMAIL_PATTERN.search(text))
        )

    return detected


def mask_pii_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L1:
    業務運用レイヤーとして、取得データ内のPIIを検知し、
    そのまま外部返却しない形へマスキングする。
    """
    masked = dict(record)

    if "name" in masked:
        masked["name"] = mask_name(masked["name"])

    if "full_name" in masked:
        masked["full_name"] = mask_name(masked["full_name"])

    if "phone" in masked:
        masked["phone"] = mask_phone(masked["phone"])

    if "mobile_phone" in masked:
        masked["mobile_phone"] = mask_phone(masked["mobile_phone"])

    if "email" in masked:
        masked["email"] = mask_email(masked["email"])

    if "address" in masked:
        masked["address"] = mask_address(masked["address"])

    if "emergency_contact_name" in masked:
        masked["emergency_contact_name"] = mask_name(masked["emergency_contact_name"])

    if "emergency_contact_phone" in masked:
        masked["emergency_contact_phone"] = mask_phone(masked["emergency_contact_phone"])

    return masked


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー向けに必要最小限の情報だけ返す。

    例:
    - 内部管理ID、医療情報、生年月日、詳細な緊急連絡先などは返さない
    - 住所や電話番号はマスキング済みの値のみ返す
    """

    # まずPIIをマスキング
    masked = mask_pii_record(record)

    # ドライバーが業務上必要とする最小限の項目のみ許可
    allowed_fields = {
        "customer_id",
        "name",
        "address",
        "phone",
        "status",
        "last_checkin_at",
        "visit_note",
    }

    sanitized = {
        key: value
        for key, value in masked.items()
        if key in allowed_fields
    }

    return sanitized


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

FORBIDDEN_RESPONSE_FIELDS = {
    "email",
    "birth_date",
    "medical_history",
    "medication",
    "insurance_number",
    "emergency_contact_name",
    "emergency_contact_phone",
    "raw_address",
    "internal_memo",
}


def response_guard(response: Dict[str, Any]) -> None:
    """
    返却直前の最終ガード。
    ここで禁止項目や未マスキングのPIIらしき値が残っていないか確認する。
    """

    forbidden = FORBIDDEN_RESPONSE_FIELDS.intersection(response.keys())
    if forbidden:
        raise ValueError(f"Forbidden fields in response: {sorted(forbidden)}")

    for key, value in response.items():
        if value is None:
            continue

        text = str(value)

        # 電話番号らしき生データが残っていないか確認
        if key in {"phone", "mobile_phone"}:
            digits = re.sub(r"\D", "", text)

            # マスキング済みなら "*" が含まれる想定
            if len(digits) >= 8 and "*" not in text:
                raise ValueError("Unmasked phone number detected")

        # メールアドレスはドライバー向けレスポンスでは禁止
        if EMAIL_PATTERN.search(text):
            raise ValueError("Email-like PII detected in response")


# ============================================================
# API本体
# ============================================================

class CustomerNotFoundError(Exception):
    pass


class CustomerAccessDeniedError(Exception):
    pass


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    処理概要:
    1. driver_id と customer_id の担当関係を確認
    2. DBから指定 customer_id の顧客レコードを取得
    3. PIIを検知・マスキング
    4. ドライバー向けに最小権限化
    5. 返却直前にガード節で最終確認
    6. 安全な監査ログを記録
    """

    request_id = str(uuid.uuid4())

    audit_log(
        "customer_access_started",
        driver_id=driver_id,
        customer_id=customer_id,
        request_id=request_id,
        result="started",
    )

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # driver_id が該当 customer_id を担当していることを確認しつつ取得
                # SQLインジェクション対策としてパラメータ化クエリを使用
                cur.execute(
                    """
                    SELECT
                        c.customer_id,
                        c.name,
                        c.address,
                        c.phone,
                        c.status,
                        c.last_checkin_at,
                        c.visit_note,
                        c.email,
                        c.birth_date,
                        c.medical_history,
                        c.emergency_contact_name,
                        c.emergency_contact_phone
                    FROM customers c
                    INNER JOIN driver_customer_assignments a
                        ON a.customer_id = c.customer_id
                    WHERE
                        c.customer_id = %s
                        AND a.driver_id = %s
                        AND c.deleted_at IS NULL
                        AND a.active = TRUE
                    LIMIT 1
                    """,
                    (customer_id, driver_id),
                )

                record = cur.fetchone()

        if record is None:
            audit_log(
                "customer_access_finished",
                driver_id=driver_id,
                customer_id=customer_id,
                request_id=request_id,
                result="not_found_or_denied",
            )
            raise CustomerNotFoundError("Customer not found or access denied")

        raw_record = dict(record)

        # L1: PII検知
        pii_detection_result = detect_pii(raw_record)

        audit_logger.info(
            {
                "event": "customer_pii_detection",
                "driver_ref": pseudonymize(driver_id),
                "customer_ref": pseudonymize(customer_id),
                "request_id": request_id,
                "pii_fields_detected": [
                    key for key, detected in pii_detection_result.items() if detected
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        # L2: サニタイズ・最小権限化
        response = sanitize_customer_for_driver(raw_record)

        # L3: 返却直前のガード節
        response_guard(response)

        # L4: 安全な監査ログ
        audit_log(
            "customer_access_finished",
            driver_id=driver_id,
            customer_id=customer_id,
            request_id=request_id,
            result="success",
        )

        return response

    except Exception:
        audit_log(
            "customer_access_finished",
            driver_id=driver_id,
            customer_id=customer_id,
            request_id=request_id,
            result="error",
        )
        raise