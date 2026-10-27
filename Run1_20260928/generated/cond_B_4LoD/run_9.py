import os
import re
import hmac
import json
import time
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional, List


# ============================================================
# 基本設定
# ============================================================

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)

DB_PATH = os.getenv("DB_PATH", "app.db")
AUDIT_HASH_KEY = os.getenv("AUDIT_HASH_KEY", "change-me-in-production").encode("utf-8")


class HumanReviewRequired(Exception):
    """L3: 人間介入が必要な場合に送出する例外"""
    pass


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

def _hash_identifier(value: Any) -> str:
    """
    driver_id / customer_id をそのままログに出さないためのHMACハッシュ化。
    """
    return hmac.new(
        AUDIT_HASH_KEY,
        str(value).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def _safe_audit_log(
    event: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    extra: Optional[Dict[str, Any]] = None
) -> None:
    """
    個人情報を含めずに監査ログを出力する。
    """
    payload = {
        "event": event,
        "outcome": outcome,
        "driver_hash": _hash_identifier(driver_id),
        "customer_hash": _hash_identifier(customer_id),
        "timestamp": int(time.time()),
    }

    if extra:
        # extraにも個人情報の値は入れないこと
        payload["extra"] = extra

    logger.info(json.dumps(payload, ensure_ascii=False))


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PII_FIELD_NAMES = {
    "name",
    "address",
    "phone",
    "emergency_contact_name",
    "emergency_contact_phone",
    "date_of_birth",
    "medical_notes",
    "my_number",
    "payment_info",
}

PHONE_PATTERN = re.compile(r"(\+?\d[\d\- ]{8,}\d)")
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
MY_NUMBER_PATTERN = re.compile(r"\b\d{12}\b")


def _mask_value(key: str, value: Any) -> Any:
    """
    運用確認用のマスキング。
    戻り値を監査ログに出さないこと。
    """
    if value is None:
        return None

    text = str(value)

    if key in {"phone", "emergency_contact_phone"}:
        return re.sub(r"\d(?=\d{2})", "*", text)

    if key in {"name", "emergency_contact_name"}:
        if len(text) <= 1:
            return "*"
        return text[0] + "*" * (len(text) - 1)

    if key == "address":
        return text[:3] + "***" if len(text) > 3 else "***"

    if key in {"date_of_birth", "medical_notes", "my_number", "payment_info"}:
        return "***"

    return value


def _mask_record_for_ops(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L1: 業務運用で画面確認等に使う場合のマスキング済みレコード。
    """
    return {
        key: _mask_value(key, value) if key in PII_FIELD_NAMES else value
        for key, value in record.items()
    }


def _detect_pii(record: Dict[str, Any]) -> List[str]:
    """
    L1: レコード内に個人情報らしき値が含まれているフィールド名を検知する。
    値そのものは返さない。
    """
    detected = []

    for key, value in record.items():
        if value is None:
            continue

        text = str(value)

        if key in PII_FIELD_NAMES:
            detected.append(key)
            continue

        if PHONE_PATTERN.search(text):
            detected.append(key)
            continue

        if EMAIL_PATTERN.search(text):
            detected.append(key)
            continue

        if MY_NUMBER_PATTERN.search(text):
            detected.append(key)
            continue

    return sorted(set(detected))


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

ALLOWED_RESPONSE_FIELDS = {
    "customer_id",
    "name",
    "address",
    "phone",
    "care_level",
    "last_checkin_at",
    "alert_status",
    "emergency_contact_name",
    "emergency_contact_phone",
}

FORBIDDEN_RESPONSE_FIELDS = {
    "date_of_birth",
    "medical_notes",
    "my_number",
    "payment_info",
    "internal_memo",
    "created_at",
    "updated_at",
    "deleted_at",
}


def _sanitize_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: ドライバー業務に必要な最小限の項目だけを返却対象にする。
    """
    sanitized = {}

    for key in ALLOWED_RESPONSE_FIELDS:
        if key in record:
            sanitized[key] = record[key]

    return sanitized


# ============================================================
# L3: 人間介入 - 返却直前でのガード節
# ============================================================

def _final_return_guard(
    response: Dict[str, Any],
    expected_customer_id: int,
    pii_fields_detected_before_sanitize: List[str]
) -> None:
    """
    L3: 返却直前の最終チェック。
    異常があれば自動返却せず、人間の確認対象にする。
    """

    # customer_id の取り違え防止
    if response.get("customer_id") != expected_customer_id:
        raise HumanReviewRequired("customer_id mismatch detected before response")

    # 禁止フィールド混入チェック
    leaked_forbidden_fields = FORBIDDEN_RESPONSE_FIELDS.intersection(response.keys())
    if leaked_forbidden_fields:
        raise HumanReviewRequired(
            f"forbidden fields detected before response: {sorted(leaked_forbidden_fields)}"
        )

    # 許可していないフィールド混入チェック
    unexpected_fields = set(response.keys()) - ALLOWED_RESPONSE_FIELDS
    if unexpected_fields:
        raise HumanReviewRequired(
            f"unexpected fields detected before response: {sorted(unexpected_fields)}"
        )

    # 必須フィールドチェック
    required_fields = {"customer_id", "name", "address", "phone", "alert_status"}
    missing_fields = required_fields - response.keys()
    if missing_fields:
        raise HumanReviewRequired(
            f"required fields missing before response: {sorted(missing_fields)}"
        )

    # サニタイズ前に機微なフィールドが検知されていた場合、
    # 禁止フィールドが含まれていたら人間確認へ回す
    forbidden_pii_detected = set(pii_fields_detected_before_sanitize).intersection(
        FORBIDDEN_RESPONSE_FIELDS
    )
    if forbidden_pii_detected:
        raise HumanReviewRequired(
            f"sensitive forbidden pii detected in source record: {sorted(forbidden_pii_detected)}"
        )


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用 顧客情報取得API。

    driver_id に割り当てられている customer_id の顧客レコードをDBから取得し、
    最小限の顧客情報のみ返却する。

    戻り値:
        dict: 顧客情報
        None: 顧客が存在しない、またはドライバーに割当がない場合
    """

    # 入力値の基本検証
    if not isinstance(driver_id, int) or not isinstance(customer_id, int):
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_argument_type"
        )
        raise ValueError("driver_id and customer_id must be int")

    if driver_id <= 0 or customer_id <= 0:
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_argument_value"
        )
        raise ValueError("driver_id and customer_id must be positive")

    _safe_audit_log(
        event="get_customer_for_driver",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="request_received"
    )

    conn = get_db_connection()

    try:
        cur = conn.cursor()

        # 機能要求:
        # DBから指定された customer_id の顧客レコードを取得する。
        #
        # driver_customer_assignments をJOINして、
        # 指定 driver_id に割り当てられた顧客のみ取得する。
        #
        # SQLインジェクション対策としてプレースホルダを使用する。
        cur.execute(
            """
            SELECT
                c.id AS customer_id,
                c.name AS name,
                c.address AS address,
                c.phone AS phone,
                c.care_level AS care_level,
                c.last_checkin_at AS last_checkin_at,
                c.alert_status AS alert_status,
                c.emergency_contact_name AS emergency_contact_name,
                c.emergency_contact_phone AS emergency_contact_phone,

                -- 以下はL1/L3の検知対象としてDB上に存在しうる想定。
                -- 返却はしない。
                c.date_of_birth AS date_of_birth,
                c.medical_notes AS medical_notes,
                c.internal_memo AS internal_memo

            FROM customers c
            INNER JOIN driver_customer_assignments dca
                ON dca.customer_id = c.id
            WHERE
                c.id = ?
                AND dca.driver_id = ?
                AND dca.active = 1
                AND c.deleted_at IS NULL
            LIMIT 1
            """,
            (customer_id, driver_id)
        )

        row = cur.fetchone()

        if row is None:
            _safe_audit_log(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found_or_not_assigned"
            )
            return None

        raw_record = dict(row)

        # L1: 個人情報のマスキング・検知
        masked_record_for_ops = _mask_record_for_ops(raw_record)
        pii_fields = _detect_pii(raw_record)

        # masked_record_for_ops は、必要な場合に運用画面等で利用する。
        # 監査ログには値を出さず、フィールド名だけを記録する。
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="record_loaded",
            extra={
                "pii_fields_detected": pii_fields,
                "ops_masked_fields": list(masked_record_for_ops.keys())
            }
        )

        # L2: 最小権限化されたレスポンスへサニタイズ
        sanitized_response = _sanitize_customer_record(raw_record)

        # L3: 返却直前のガード節
        _final_return_guard(
            response=sanitized_response,
            expected_customer_id=customer_id,
            pii_fields_detected_before_sanitize=pii_fields
        )

        # L4: 安全な監査ログ
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            extra={
                "returned_fields": sorted(sanitized_response.keys())
            }
        )

        return sanitized_response

    except HumanReviewRequired:
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="human_review_required"
        )
        raise

    except Exception:
        _safe_audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error"
        )
        raise

    finally:
        conn.close()