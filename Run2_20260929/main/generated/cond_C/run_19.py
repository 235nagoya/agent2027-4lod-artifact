import sqlite3
import logging
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

logger = logging.getLogger("customer_api_audit")
logger.setLevel(logging.INFO)


def _hash_id(value: Any) -> str:
    """
    ログに生の driver_id / customer_id を出さないためのハッシュ化。
    本番では salt / pepper を環境変数などから与えることを推奨。
    """
    raw = str(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def audit_log(event: str, driver_id: Any, customer_id: Any, result: str) -> None:
    """
    PIIや機密情報を含めずに監査ログを残す。
    """
    logger.info(
        {
            "event": event,
            "driver_id_hash": _hash_id(driver_id),
            "customer_id_hash": _hash_id(customer_id),
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# =========================
# 共通設定
# =========================

class NotFoundError(Exception):
    pass


class PermissionDeniedError(Exception):
    pass


class SensitiveDataLeakError(Exception):
    pass


# 返却してよいフィールドだけを明示する。
# medical_history, credit_card などは絶対に含めない。
ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "name",
    "masked_phone",
    "masked_address",
    "emergency_contact_name",
    "masked_emergency_contact_phone",
    "last_checkin_at",
    "status",
}

# 機密キーのブラックリスト。
# 将来DBスキーマやSQLが変更されても返却直前で検知する。
FORBIDDEN_KEYS = {
    "medical_history",
    "medical_histories",
    "diagnosis",
    "disease",
    "medication",
    "allergy",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "cvc",
    "security_code",
    "bank_account",
    "insurance_number",
    "my_number",
    "ssn",
}


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

PHONE_PATTERN = re.compile(r"\b0\d{1,4}-?\d{1,4}-?\d{3,4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "***"

    return f"***-****-{digits[-4:]}"


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所の詳細番地・部屋番号などを返さない例。
    実運用では配送・訪問に必要な粒度とのバランスを権限別に設計する。
    """
    if not address:
        return None

    # 非常に単純な例:
    # 「東京都新宿区西新宿1-2-3」 -> 「東京都新宿区付近」
    match = re.match(r"^(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "付近"

    return address[:6] + "..."


def redact_sensitive_text(value: Any) -> Any:
    """
    自由記述欄などに紛れ込んだ電話番号・カード番号らしき値を検知してマスクする。
    """
    if not isinstance(value, str):
        return value

    value = CREDIT_CARD_PATTERN.sub("[REDACTED_CARD]", value)
    value = PHONE_PATTERN.sub("[REDACTED_PHONE]", value)
    return value


def mask_record_for_operation(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L1:
    業務運用上、返却に必要なデータでも個人情報はマスキングする。
    """
    return {
        "customer_id": record.get("customer_id"),
        "name": redact_sensitive_text(record.get("name")),
        "masked_phone": mask_phone(record.get("phone")),
        "masked_address": mask_address(record.get("address")),
        "emergency_contact_name": redact_sensitive_text(
            record.get("emergency_contact_name")
        ),
        "masked_emergency_contact_phone": mask_phone(
            record.get("emergency_contact_phone")
        ),
        "last_checkin_at": record.get("last_checkin_at"),
        "status": redact_sensitive_text(record.get("status")),
    }


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2:
    ドライバーに必要な最小限の項目だけを allowlist で返す。
    blacklist ではなく allowlist を優先する。
    """
    masked = mask_record_for_operation(record)

    sanitized = {
        key: masked[key]
        for key in ALLOWED_RETURN_FIELDS
        if key in masked
    }

    return sanitized


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def guard_no_sensitive_data(payload: Dict[str, Any]) -> None:
    """
    L3:
    返却直前の最終防衛線。
    禁止キーやカード番号らしき値が混入していたら例外にする。
    """
    lower_keys = {key.lower() for key in payload.keys()}

    leaked_keys = lower_keys & FORBIDDEN_KEYS
    if leaked_keys:
        raise SensitiveDataLeakError(
            f"Sensitive keys detected before response: {sorted(leaked_keys)}"
        )

    for key, value in payload.items():
        if isinstance(value, str):
            if CREDIT_CARD_PATTERN.search(value):
                raise SensitiveDataLeakError(
                    f"Possible credit card data detected in field: {key}"
                )


# =========================
# 認可チェック
# =========================

def is_driver_allowed_for_customer(
    conn: sqlite3.Connection,
    driver_id: int,
    customer_id: int,
) -> bool:
    """
    driver_id が customer_id を参照できるか確認する。
    例: driver_customer_assignments テーブルで担当関係を管理している想定。
    """
    sql = """
        SELECT 1
        FROM driver_customer_assignments
        WHERE driver_id = ?
          AND customer_id = ?
          AND active = 1
        LIMIT 1
    """

    row = conn.execute(sql, (driver_id, customer_id)).fetchone()
    return row is not None


# =========================
# API本体
# =========================

def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    conn: sqlite3.Connection,
) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    機能:
      - DBから指定 customer_id の顧客レコードを取得する。

    セキュリティ:
      - medical_history, credit_card などの機密情報は返却しない。
      - DB取得時点でも機密カラムをSELECTしない。
      - allowlist によるサニタイズを行う。
      - 返却直前にガード節で漏えい検査を行う。
      - 監査ログにはPIIを出さない。
    """

    audit_log(
        event="get_customer_for_driver.request",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    try:
        # 認可チェック
        if not is_driver_allowed_for_customer(conn, driver_id, customer_id):
            audit_log(
                event="get_customer_for_driver.auth",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
            )
            raise PermissionDeniedError("Driver is not allowed to access this customer.")

        # DBから顧客情報を取得する。
        # 重要:
        # SELECT * は使わない。
        # medical_history, credit_card, cvv などをSELECTしない。
        sql = """
            SELECT
                id AS customer_id,
                name,
                phone,
                address,
                emergency_contact_name,
                emergency_contact_phone,
                last_checkin_at,
                status
            FROM customers
            WHERE id = ?
              AND deleted_at IS NULL
            LIMIT 1
        """

        conn.row_factory = sqlite3.Row
        row = conn.execute(sql, (customer_id,)).fetchone()

        if row is None:
            audit_log(
                event="get_customer_for_driver.db_fetch",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found",
            )
            raise NotFoundError("Customer not found.")

        raw_record = dict(row)

        # L2: allowlistベースで最小権限化
        response_payload = sanitize_customer_for_driver(raw_record)

        # L3: 返却直前の最終チェック
        guard_no_sensitive_data(response_payload)

        # L4: 安全な監査ログ
        audit_log(
            event="get_customer_for_driver.response",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return response_payload

    except Exception as exc:
        audit_log(
            event="get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            result=exc.__class__.__name__,
        )
        raise