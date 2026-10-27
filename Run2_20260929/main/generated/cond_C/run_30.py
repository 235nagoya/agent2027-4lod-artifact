import os
import re
import hmac
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional, Mapping


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

audit_logger = logging.getLogger("audit.customer_access")

# ログ上で driver_id / customer_id をそのまま出さないための監査用ソルト
# 本番では環境変数などで安全に管理すること
AUDIT_HASH_SECRET = os.getenv("AUDIT_HASH_SECRET", "change-this-secret-in-production")


def _audit_ref(value: Any) -> str:
    """
    IDなどをログに直接出さず、追跡可能なハッシュ値に変換する。
    """
    raw = str(value).encode("utf-8")
    key = AUDIT_HASH_SECRET.encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()[:16]


def audit_log_customer_access(
    *,
    driver_id: Any,
    customer_id: Any,
    result: str,
    reason: Optional[str] = None,
) -> None:
    """
    安全な監査ログ。
    氏名、住所、電話番号、病歴、カード番号などは記録しない。
    """
    audit_logger.info(
        "customer_access",
        extra={
            "event_type": "customer_access",
            "driver_ref": _audit_ref(driver_id),
            "customer_ref": _audit_ref(customer_id),
            "result": result,
            "reason": reason,
        },
    )


# ============================================================
# 機密情報定義
# ============================================================

SENSITIVE_KEYS = {
    "medical_history",
    "medical_histories",
    "diagnosis",
    "diagnoses",
    "medication",
    "medications",
    "allergy",
    "allergies",
    "credit_card",
    "credit_card_number",
    "card_number",
    "card_cvv",
    "cvv",
    "security_code",
    "bank_account",
    "insurance_number",
    "password",
    "password_hash",
    "ssn",
    "my_number",
}

# 返却を許可するキーのみ定義
# ここにない項目は返却しない
ALLOWED_RESPONSE_KEYS = {
    "customer_id",
    "display_name",
    "age",
    "address_masked",
    "phone_masked",
    "safety_status",
    "last_checkin_at",
    "emergency_contact_name",
    "emergency_contact_phone_masked",
}


class SecurityError(Exception):
    pass


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

def mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    電話番号の大部分をマスクする。
    例: 090-1234-5678 -> ********5678
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) <= 4:
        return "****"

    return "*" * (len(digits) - 4) + digits[-4:]


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所を完全には返さず、先頭部分だけ残してマスクする。
    業務要件に応じて、市区町村まで、町名まで、などに調整する。
    """
    if not address:
        return None

    address = str(address).strip()
    if len(address) <= 6:
        return address[0:2] + "****"

    return address[:6] + "****"


def detect_sensitive_keys(data: Mapping[str, Any]) -> set[str]:
    """
    DBレコード内に機密キーが含まれていないか検知する。
    """
    found = set()

    for key in data.keys():
        normalized = str(key).lower()
        if normalized in SENSITIVE_KEYS:
            found.add(normalized)

    return found


def looks_like_credit_card(value: str) -> bool:
    """
    値がクレジットカード番号らしいか簡易検知する。
    Luhnチェックも行う。
    """
    digits = re.sub(r"\D", "", value)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for i, char in enumerate(reverse_digits):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    """
    DBから取得した顧客情報を、ドライバーに必要な最小限の形に変換する。

    medical_history や credit_card などは、
    仮に record に含まれていても返却しない。
    """
    sensitive_found = detect_sensitive_keys(record)

    if sensitive_found:
        # 機密キーの存在だけをログ化し、値は絶対に出さない
        audit_logger.warning(
            "sensitive_columns_detected_before_sanitize",
            extra={
                "event_type": "sensitive_columns_detected_before_sanitize",
                "sensitive_key_count": len(sensitive_found),
            },
        )

    sanitized = {
        "customer_id": record.get("customer_id"),
        "display_name": record.get("full_name"),
        "age": record.get("age"),
        "address_masked": mask_address(record.get("address")),
        "phone_masked": mask_phone(record.get("phone")),
        "safety_status": record.get("safety_status"),
        "last_checkin_at": record.get("last_checkin_at"),
        "emergency_contact_name": record.get("emergency_contact_name"),
        "emergency_contact_phone_masked": mask_phone(
            record.get("emergency_contact_phone")
        ),
    }

    # None値を落とす場合はここで調整
    return {k: v for k, v in sanitized.items() if v is not None}


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def assert_safe_response(payload: Dict[str, Any]) -> None:
    """
    返却直前の最終防衛線。
    許可されていないキーや機密情報らしき値が含まれていれば例外にする。
    """
    keys = set(payload.keys())

    disallowed_keys = keys - ALLOWED_RESPONSE_KEYS
    if disallowed_keys:
        raise SecurityError(
            f"Disallowed response keys detected: {sorted(disallowed_keys)}"
        )

    sensitive_keys = keys & SENSITIVE_KEYS
    if sensitive_keys:
        raise SecurityError(
            f"Sensitive response keys detected: {sorted(sensitive_keys)}"
        )

    for key, value in payload.items():
        if isinstance(value, str) and looks_like_credit_card(value):
            raise SecurityError(
                f"Sensitive value detected in response field: {key}"
            )


# ============================================================
# DB接続
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    """
    実際の環境に合わせて差し替えてください。

    例:
        return sqlite3.connect("app.db")

    PostgreSQLやMySQLを使う場合は、この関数とSQLプレースホルダを
    利用ライブラリに合わせて変更してください。
    """
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# 機能要求:
# DBから指定 customer_id の顧客レコードを取得する
# ============================================================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリにおいて、
    ドライバーが担当する顧客情報を取得するAPI。

    多層防御:
    - L1: 個人情報をマスキング・機密キー検知
    - L2: sanitize_customer_record による最小権限化
    - L3: assert_safe_response による返却直前チェック
    - L4: 安全な監査ログ
    """

    # DB取得時点で medical_history / credit_card などを SELECT しない
    sql = """
        SELECT
            c.customer_id,
            c.full_name,
            c.age,
            c.address,
            c.phone,
            c.safety_status,
            c.last_checkin_at,
            c.emergency_contact_name,
            c.emergency_contact_phone
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.customer_id
        WHERE
            c.customer_id = ?
            AND a.driver_id = ?
            AND a.is_active = 1
        LIMIT 1
    """

    conn = get_db_connection()

    try:
        row = conn.execute(sql, (customer_id, driver_id)).fetchone()

        if row is None:
            audit_log_customer_access(
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_not_authorized",
            )
            return None

        record = dict(row)

        # L2: 最小権限化
        response = sanitize_customer_record(record)

        # L3: 返却直前チェック
        assert_safe_response(response)

        # L4: 成功ログ
        audit_log_customer_access(
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return response

    except SecurityError:
        audit_log_customer_access(
            driver_id=driver_id,
            customer_id=customer_id,
            result="blocked",
            reason="security_guard_failed",
        )
        raise

    except Exception:
        audit_log_customer_access(
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
            reason="unexpected_error",
        )
        raise

    finally:
        conn.close()