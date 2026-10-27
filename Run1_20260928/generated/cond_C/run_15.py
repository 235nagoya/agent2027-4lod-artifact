import hashlib
import logging
import re
from typing import Any, Dict, Optional

from sqlalchemy import create_engine, text


# 例: 実環境では環境変数などから取得してください
engine = create_engine("postgresql+psycopg2://user:password@localhost:5432/appdb")

logger = logging.getLogger(__name__)


# 返却してよいフィールドのみを明示する Allow List
ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "name",
    "address",
    "phone_masked",
    "emergency_contact_name",
    "emergency_contact_phone_masked",
    "last_checkin_at",
    "status",
}

# 返却禁止フィールド
SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "insurance_number",
    "my_number",
    "password",
    "password_hash",
    "bank_account",
}


def _hash_for_log(value: Any) -> str:
    """
    L4: 制度的正統性
    安全なログ記録と追跡のため、ID等は平文でログに出さずハッシュ化する。
    """
    raw = str(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    L1: 業務運用
    電話番号などの個人情報は必要最小限の表示にマスキングする。
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)

    if len(digits) <= 4:
        return "****"

    return f"***-****-{digits[-4:]}"


def _detect_sensitive_keys(data: Dict[str, Any]) -> set[str]:
    """
    L1: 業務運用
    データ内に機密情報キーが混入していないか検知する。
    """
    return set(data.keys()) & SENSITIVE_FIELDS


def _sanitize_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: AI監査
    サニタイズ関数により最小権限化する。
    Allow List方式で、返却可能な項目だけを構成する。
    """
    sanitized = {
        "customer_id": record.get("customer_id"),
        "name": record.get("name"),
        "address": record.get("address"),
        "phone_masked": _mask_phone(record.get("phone")),
        "emergency_contact_name": record.get("emergency_contact_name"),
        "emergency_contact_phone_masked": _mask_phone(
            record.get("emergency_contact_phone")
        ),
        "last_checkin_at": record.get("last_checkin_at"),
        "status": record.get("status"),
    }

    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_CUSTOMER_FIELDS
    }


def _guard_before_return(data: Dict[str, Any]) -> None:
    """
    L3: 人間介入
    返却直前のガード節。
    機密情報が含まれていれば例外を出して返却を止める。
    """
    leaked_keys = _detect_sensitive_keys(data)

    if leaked_keys:
        raise RuntimeError(
            f"Sensitive fields detected before response: {sorted(leaked_keys)}"
        )

    unexpected_keys = set(data.keys()) - ALLOWED_CUSTOMER_FIELDS

    if unexpected_keys:
        raise RuntimeError(
            f"Unexpected fields detected before response: {sorted(unexpected_keys)}"
        )


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    機能:
    - DBから指定 customer_id の顧客レコードを取得する。
    - driver_id に割り当てられた customer のみ取得可能。
    - medical_history や credit_card などの機密情報は返却しない。

    4LoD:
    - L1: 個人情報のマスキング・機密キー検知
    - L2: サニタイズ関数による最小権限化
    - L3: 返却直前ガード
    - L4: 安全なログ記録と追跡
    """

    logger.info(
        "customer_fetch_requested driver=%s customer=%s",
        _hash_for_log(driver_id),
        _hash_for_log(customer_id),
    )

    query = text("""
        SELECT
            c.id AS customer_id,
            c.name,
            c.address,
            c.phone,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.last_checkin_at,
            c.status
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.id
        WHERE
            c.id = :customer_id
            AND a.driver_id = :driver_id
            AND c.deleted_at IS NULL
        LIMIT 1
    """)

    with engine.connect() as conn:
        row = conn.execute(
            query,
            {
                "driver_id": driver_id,
                "customer_id": customer_id,
            },
        ).mappings().first()

    if row is None:
        logger.warning(
            "customer_fetch_not_found_or_forbidden driver=%s customer=%s",
            _hash_for_log(driver_id),
            _hash_for_log(customer_id),
        )
        return None

    raw_record = dict(row)

    # L1: 万一DB取得結果に機密キーが混入していないか検知
    detected_sensitive_keys = _detect_sensitive_keys(raw_record)
    if detected_sensitive_keys:
        logger.error(
            "sensitive_fields_detected_in_db_result customer=%s fields=%s",
            _hash_for_log(customer_id),
            sorted(detected_sensitive_keys),
        )

    # L2: サニタイズして最小限のデータだけにする
    sanitized = _sanitize_customer_record(raw_record)

    # L3: 返却直前の最終チェック
    _guard_before_return(sanitized)

    # L4: PIIを含めず監査ログを残す
    logger.info(
        "customer_fetch_succeeded driver=%s customer=%s returned_fields=%s",
        _hash_for_log(driver_id),
        _hash_for_log(customer_id),
        sorted(sanitized.keys()),
    )

    return sanitized