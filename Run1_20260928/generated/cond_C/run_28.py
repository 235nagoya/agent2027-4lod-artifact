import logging
import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

logger = logging.getLogger("customer_access_audit")
logger.setLevel(logging.INFO)

AUDIT_HASH_SECRET = b"change-this-secret-in-production"


def _hash_id(value: Any) -> str:
    """
    ログに生の driver_id / customer_id を出さないためのハッシュ化。
    """
    return hmac.new(
        AUDIT_HASH_SECRET,
        str(value).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def audit_log(event: str, driver_id: Any, customer_id: Any, result: str) -> None:
    """
    個人情報を含めない安全な監査ログ。
    """
    logger.info({
        "event": event,
        "driver_hash": _hash_id(driver_id),
        "customer_hash": _hash_id(customer_id),
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

SENSITIVE_KEYS = {
    "medical_history",
    "medical_record",
    "diagnosis",
    "disease",
    "medication",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "security_code",
    "bank_account",
    "insurance_number",
    "my_number",
    "password",
    "secret",
    "token",
}


PHONE_RE = re.compile(r"\d{2,4}-?\d{2,4}-?\d{3,4}")


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    return "*" * (len(digits) - 4) + digits[-4:]


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    ドライバーに詳細住所が不要なユースケースを想定し、
    市区町村程度までに制限する簡易例。
    実運用では住所粒度を業務要件に合わせて調整してください。
    """
    if not address:
        return None

    # 例: "東京都新宿区西新宿1-2-3" -> "東京都新宿区付近"
    match = re.match(r"^(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "付近"

    return "住所詳細は非表示"


def contains_sensitive_key(data: Dict[str, Any]) -> bool:
    return any(key.lower() in SENSITIVE_KEYS for key in data.keys())


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

ALLOWED_RETURN_KEYS = {
    "customer_id",
    "display_name",
    "age",
    "phone_masked",
    "address_masked",
    "visit_status",
    "last_checkin_at",
}


def sanitize_customer_record(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    DBから取得したデータを、ドライバー業務に必要な最小限の情報に制限する。

    重要:
    - medical_history / credit_card などは返却しない
    - allowlist方式で返却項目を固定する
    - 電話番号・住所はマスキングする
    """

    sanitized = {
        "customer_id": row.get("customer_id"),
        "display_name": row.get("display_name"),
        "age": row.get("age"),
        "phone_masked": mask_phone(row.get("phone")),
        "address_masked": mask_address(row.get("address")),
        "visit_status": row.get("visit_status"),
        "last_checkin_at": row.get("last_checkin_at"),
    }

    # allowlistで最終制限
    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_RETURN_KEYS
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def guard_before_return(data: Dict[str, Any]) -> None:
    """
    返却直前の安全チェック。
    禁止キーやクレジットカードらしき値が混入していれば例外にする。
    """

    if contains_sensitive_key(data):
        raise RuntimeError("返却データに機密キーが含まれています")

    unexpected_keys = set(data.keys()) - ALLOWED_RETURN_KEYS
    if unexpected_keys:
        raise RuntimeError(f"返却データに許可されていないキーがあります: {unexpected_keys}")

    # 値の中にカード番号らしき連続数字がないか簡易検知
    for key, value in data.items():
        if isinstance(value, str):
            digits = re.sub(r"\D", "", value)
            if len(digits) >= 13:
                raise RuntimeError(f"返却データに機密情報らしき値があります: {key}")


# =========================
# DB接続
# 実運用ではアプリ側のDIやコネクションプールを使う
# =========================

db_conn = None


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    - 指定 customer_id の顧客レコードをDBから取得する
    - driver_id に紐づく顧客のみ取得可能
    - medical_history / credit_card などの機密情報は返却しない
    - 返却直前にガードチェックを行う
    - 監査ログには生の個人情報を残さない
    """

    audit_log(
        event="get_customer_for_driver.request",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started"
    )

    try:
        if db_conn is None:
            raise RuntimeError("DB connection is not configured")

        cursor = db_conn.cursor()

        # 重要:
        # SELECT * は使わない。
        # medical_history, credit_card などの機密カラムを最初から取得しない。
        #
        # driver_customer_assignments により、
        # driver_id が担当する customer_id のみ取得できるようにする。
        cursor.execute(
            """
            SELECT
                c.id AS customer_id,
                c.display_name AS display_name,
                c.age AS age,
                c.phone AS phone,
                c.address AS address,
                c.visit_status AS visit_status,
                c.last_checkin_at AS last_checkin_at
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.id
            WHERE
                a.driver_id = %s
                AND c.id = %s
                AND c.deleted_at IS NULL
            LIMIT 1
            """,
            (driver_id, customer_id)
        )

        row = cursor.fetchone()

        if row is None:
            audit_log(
                event="get_customer_for_driver.response",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_forbidden"
            )
            return None

        columns = [desc[0] for desc in cursor.description]
        raw_record = dict(zip(columns, row))

        # L2: サニタイズ
        response = sanitize_customer_record(raw_record)

        # L3: 返却直前ガード
        guard_before_return(response)

        audit_log(
            event="get_customer_for_driver.response",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success"
        )

        return response

    except Exception:
        audit_log(
            event="get_customer_for_driver.response",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error"
        )
        raise