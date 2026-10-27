import sqlite3
import logging
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# =========================================================
# 共通設定
# =========================================================

logger = logging.getLogger("safety_check_app.audit")
logger.setLevel(logging.INFO)

# 返却を許可するフィールドのみを明示する
# medical_history, credit_card などは含めない
ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "full_name",
    "age",
    "address",
    "phone_number",
    "emergency_contact_name",
    "emergency_contact_phone",
    "care_level",
}

# 絶対に返却してはいけないフィールド
FORBIDDEN_FIELDS = {
    "medical_history",
    "medical_notes",
    "diagnosis",
    "prescription",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "bank_account",
    "insurance_number",
    "my_number",
}

# ログにそのまま出さない個人情報フィールド
PII_FIELDS = {
    "full_name",
    "address",
    "phone_number",
    "emergency_contact_name",
    "emergency_contact_phone",
}

CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


class CustomerNotFoundError(Exception):
    pass


class UnauthorizedError(Exception):
    pass


class SecurityPolicyViolation(Exception):
    pass


# =========================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================================================

def hash_identifier(value: Any) -> str:
    """
    監査ログ用にIDをハッシュ化する。
    ログから直接個人や顧客を復元できないようにする。
    """
    raw = str(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def audit_log(event: str, driver_id: Any, customer_id: Any, metadata: Optional[Dict[str, Any]] = None) -> None:
    """
    安全な監査ログ。
    個人名、住所、電話番号、医療情報、カード情報などは記録しない。
    """
    log_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "driver_id_hash": hash_identifier(driver_id),
        "customer_id_hash": hash_identifier(customer_id),
        "metadata": metadata or {},
    }

    logger.info(json.dumps(log_record, ensure_ascii=False))


# =========================================================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================================================

def mask_value(value: Any) -> Any:
    if value is None:
        return None

    text = str(value)

    if len(text) <= 2:
        return "***"

    return text[0] + "***" + text[-1]


def mask_record_for_internal_use(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    業務運用・監査確認用に、個人情報をマスキングしたコピーを作る。
    返却データそのものではなく、内部確認や安全なデバッグに使う。
    """
    masked = {}

    for key, value in record.items():
        if key in PII_FIELDS:
            masked[key] = mask_value(value)
        else:
            masked[key] = value

    return masked


def detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    レコード内に個人情報フィールドが存在するか検知する。
    """
    return sorted([key for key in record.keys() if key in PII_FIELDS])


# =========================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================================================

def sanitize_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    返却可能なフィールドだけを残す。
    allowlist方式により、DBに機密カラムが存在しても返却されない。
    """
    return {
        key: value
        for key, value in record.items()
        if key in ALLOWED_CUSTOMER_FIELDS
    }


# =========================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================================================

def contains_credit_card_like_value(value: Any) -> bool:
    if value is None:
        return False

    if not isinstance(value, str):
        value = str(value)

    return bool(CREDIT_CARD_PATTERN.search(value))


def assert_safe_to_return(payload: Dict[str, Any]) -> None:
    """
    返却直前の最終防衛ライン。
    禁止フィールドやカード番号らしき値が混入していないか確認する。
    """
    forbidden_in_payload = FORBIDDEN_FIELDS.intersection(payload.keys())

    if forbidden_in_payload:
        raise SecurityPolicyViolation(
            f"Forbidden fields detected before response: {sorted(forbidden_in_payload)}"
        )

    for key, value in payload.items():
        if contains_credit_card_like_value(value):
            raise SecurityPolicyViolation(
                f"Credit-card-like value detected in response field: {key}"
            )


# =========================================================
# API本体
# =========================================================

def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    conn: sqlite3.Connection,
) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ用API。

    指定された driver_id が担当する customer_id の顧客情報をDBから取得し、
    medical_history や credit_card などの機密情報を含めず返却する。

    Parameters
    ----------
    driver_id : int
        ドライバーID
    customer_id : int
        顧客ID
    conn : sqlite3.Connection
        DB接続

    Returns
    -------
    Dict[str, Any]
        サニタイズ済みの顧客情報
    """

    audit_log(
        event="get_customer_for_driver.requested",
        driver_id=driver_id,
        customer_id=customer_id,
    )

    if not isinstance(driver_id, int) or not isinstance(customer_id, int):
        audit_log(
            event="get_customer_for_driver.invalid_parameter",
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise ValueError("driver_id and customer_id must be integers")

    conn.row_factory = sqlite3.Row

    # 重要:
    # SELECT * は使わない。
    # medical_history, credit_card などの機密カラムをDBから取得しない。
    sql = """
        SELECT
            c.id AS customer_id,
            c.full_name,
            c.age,
            c.address,
            c.phone_number,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.care_level
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.id
        WHERE
            c.id = ?
            AND a.driver_id = ?
            AND a.active = 1
        LIMIT 1
    """

    row = conn.execute(sql, (customer_id, driver_id)).fetchone()

    if row is None:
        audit_log(
            event="get_customer_for_driver.not_found_or_unauthorized",
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise CustomerNotFoundError("Customer not found or driver is not authorized")

    db_record = dict(row)

    # L1: 個人情報の検知・マスキング
    pii_fields = detect_pii_fields(db_record)
    masked_record = mask_record_for_internal_use(db_record)

    audit_log(
        event="get_customer_for_driver.record_loaded",
        driver_id=driver_id,
        customer_id=customer_id,
        metadata={
            "pii_fields_detected": pii_fields,
            "loaded_fields": sorted(db_record.keys()),
            # 値はマスキング済み。必要なければこの行自体を削除してもよい。
            "masked_preview": masked_record,
        },
    )

    # L2: allowlistによるサニタイズ
    sanitized = sanitize_customer_record(db_record)

    # L3: 返却直前のガード節
    assert_safe_to_return(sanitized)

    # L4: 安全な監査ログ
    audit_log(
        event="get_customer_for_driver.succeeded",
        driver_id=driver_id,
        customer_id=customer_id,
        metadata={
            "returned_fields": sorted(sanitized.keys()),
        },
    )

    return sanitized