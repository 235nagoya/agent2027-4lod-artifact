import os
import re
import uuid
import hmac
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional, List


DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_LOG_SALT = os.getenv("AUDIT_LOG_SALT", "change-this-in-production")

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)


class SecurityError(Exception):
    pass


class NotFoundOrUnauthorized(Exception):
    pass


# 返却禁止フィールド
SENSITIVE_FIELD_NAMES = {
    "medical_history",
    "medical_histories",
    "diagnosis",
    "disease",
    "medication",
    "allergy",
    "care_record",
    "nursing_note",
    "credit_card",
    "credit_card_number",
    "card_number",
    "card_cvv",
    "cvv",
    "my_number",
    "social_security_number",
    "bank_account",
}


# ドライバーに返してよい最小限のフィールド
# 注意: phone_number は直接返さず、マスク済みに変換する
ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "display_name",
    "address",
    "visit_window",
    "last_checkin_at",
    "safety_check_status",
}


CREDIT_CARD_LIKE_PATTERN = re.compile(
    r"\b(?:\d[ -]*?){13,19}\b"
)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_for_log(value: Any) -> str:
    """
    L4: ログ用の安全な識別子化。
    customer_id や driver_id を平文でログに残さない。
    """
    raw = str(value).encode("utf-8")
    salt = AUDIT_LOG_SALT.encode("utf-8")
    return hmac.new(salt, raw, hashlib.sha256).hexdigest()[:16]


def mask_phone_number(phone: Optional[str]) -> Optional[str]:
    """
    L1: 業務運用向けの個人情報マスキング。
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    return f"***-****-{digits[-4:]}"


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    L1: ログ・業務確認用の住所マスキング。
    実返却ではなく、安全なログや確認画面用。
    """
    if not address:
        return None

    if len(address) <= 6:
        return "***"

    return address[:3] + "***"


def detect_sensitive_keys(data: Dict[str, Any]) -> List[str]:
    """
    L1: DBから得たデータ内に禁止フィールドが混入していないか検知。
    """
    detected = []

    for key in data.keys():
        normalized = key.lower()
        if normalized in SENSITIVE_FIELD_NAMES:
            detected.append(key)

    return detected


def contains_credit_card_like_value(value: Any) -> bool:
    """
    値の中にクレジットカード番号らしき文字列がないか確認。
    """
    if value is None:
        return False

    if isinstance(value, str):
        return CREDIT_CARD_LIKE_PATTERN.search(value) is not None

    if isinstance(value, dict):
        return any(contains_credit_card_like_value(v) for v in value.values())

    if isinstance(value, list):
        return any(contains_credit_card_like_value(v) for v in value)

    return False


def sanitize_customer_for_driver(raw_customer: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: AI監査・最小権限化レイヤ。
    ドライバー業務に必要な情報のみを allowlist 方式で返却する。

    medical_history や credit_card は、
    そもそも allowlist に存在しないため返却されない。
    """

    sanitized = {}

    for key in ALLOWED_CUSTOMER_FIELDS:
        if key in raw_customer:
            sanitized[key] = raw_customer[key]

    # 電話番号は直接返さずマスクして返す。
    # 実通話が必要な場合は、別APIで call_token 等を発行する設計にする。
    if "phone_number" in raw_customer:
        sanitized["phone_number_masked"] = mask_phone_number(raw_customer["phone_number"])

    return sanitized


def guard_before_return(response_data: Dict[str, Any], trace_id: str) -> None:
    """
    L3: 人間介入レイヤ。
    返却直前に禁止フィールドやカード番号らしき値がないか確認し、
    違反があれば返却を止め、人間確認へエスカレーションする。
    """

    violations = []

    for key, value in response_data.items():
        if key.lower() in SENSITIVE_FIELD_NAMES:
            violations.append(f"forbidden_field:{key}")

        if contains_credit_card_like_value(value):
            violations.append(f"credit_card_like_value:{key}")

    if violations:
        notify_human_reviewer(trace_id=trace_id, violations=violations)

        logger.error(
            "customer_api_blocked_by_guard trace_id=%s violations=%s",
            trace_id,
            violations,
        )

        raise SecurityError("Sensitive data detected before response.")


def notify_human_reviewer(trace_id: str, violations: List[str]) -> None:
    """
    L3: 人間確認へのエスカレーション。
    実運用では Slack、PagerDuty、チケットシステム等に接続する。
    ここではログのみ。
    """
    logger.warning(
        "human_review_required trace_id=%s violations=%s",
        trace_id,
        violations,
    )


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    - 指定 customer_id の顧客情報をDBから取得する
    - driver_id に紐づく顧客のみ取得可能
    - medical_history や credit_card などの機密情報は返却しない
    - 4LoD:
        L1: 個人情報・機密情報の検知とマスキング
        L2: サニタイズによる最小権限化
        L3: 返却直前ガードと人間介入
        L4: 安全なログ記録と追跡
    """

    trace_id = str(uuid.uuid4())

    # L4: 安全な監査ログ。IDはハッシュ化し、個人情報は記録しない。
    logger.info(
        "customer_fetch_started trace_id=%s driver_hash=%s customer_hash=%s",
        trace_id,
        hash_for_log(driver_id),
        hash_for_log(customer_id),
    )

    query = """
        SELECT
            c.customer_id,
            c.display_name,
            c.address,
            c.phone_number,
            c.visit_window,
            c.last_checkin_at,
            c.safety_check_status
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.customer_id
        WHERE
            c.customer_id = ?
            AND a.driver_id = ?
            AND a.active = 1
        LIMIT 1
    """

    try:
        with get_db_connection() as conn:
            row = conn.execute(query, (customer_id, driver_id)).fetchone()

        if row is None:
            logger.info(
                "customer_fetch_not_found_or_unauthorized trace_id=%s driver_hash=%s customer_hash=%s",
                trace_id,
                hash_for_log(driver_id),
                hash_for_log(customer_id),
            )
            raise NotFoundOrUnauthorized("Customer not found or driver is not authorized.")

        raw_customer = dict(row)

        # L1: 機密フィールド混入検知
        detected_sensitive_keys = detect_sensitive_keys(raw_customer)
        if detected_sensitive_keys:
            logger.warning(
                "sensitive_keys_detected_in_db_result trace_id=%s keys=%s",
                trace_id,
                detected_sensitive_keys,
            )

        # L1: ログや業務確認用にマスクしたデータを作る。
        # 実ログには原則として値を出さない。必要な場合でもマスク済みのみ使う。
        masked_for_ops = {
            "customer_id_hash": hash_for_log(raw_customer.get("customer_id")),
            "display_name": "***",
            "address": mask_address(raw_customer.get("address")),
            "phone_number": mask_phone_number(raw_customer.get("phone_number")),
            "safety_check_status": raw_customer.get("safety_check_status"),
        }

        logger.info(
            "customer_record_loaded trace_id=%s ops_view=%s",
            trace_id,
            masked_for_ops,
        )

        # L2: サニタイズ。allowlist方式で最小限の情報だけに絞る。
        response_data = sanitize_customer_for_driver(raw_customer)

        # L3: 返却直前のガード節。
        guard_before_return(response_data, trace_id)

        # L4: 成功ログ。個人情報は出さない。
        logger.info(
            "customer_fetch_succeeded trace_id=%s driver_hash=%s customer_hash=%s returned_fields=%s",
            trace_id,
            hash_for_log(driver_id),
            hash_for_log(customer_id),
            sorted(response_data.keys()),
        )

        return response_data

    except Exception as exc:
        logger.exception(
            "customer_fetch_failed trace_id=%s driver_hash=%s customer_hash=%s error_type=%s",
            trace_id,
            hash_for_log(driver_id),
            hash_for_log(customer_id),
            type(exc).__name__,
        )
        raise