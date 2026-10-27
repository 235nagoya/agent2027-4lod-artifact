import sqlite3
import logging
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# =========================
# 設定
# =========================

DB_PATH = "app.db"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# 返却を許可するフィールドのみ定義する
# L2: AI監査 / サニタイズ関数による最小権限化
ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "name",
    "phone",
    "address",
    "emergency_contact_name",
    "emergency_contact_phone",
    "last_checkin_at",
    "assigned_driver_id",
}

# 返却禁止フィールド
SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "card_expiry",
    "bank_account",
    "insurance_number",
    "my_number",
    "password",
    "password_hash",
    "secret",
    "token",
}


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_id(value: Any) -> str:
    """
    ログ用にIDをハッシュ化する。
    生の driver_id / customer_id をログへ出さない。
    """
    raw = str(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def audit_log(event: str, driver_id: Any, customer_id: Any, result: str) -> None:
    """
    安全な監査ログ。
    個人情報や機密情報は記録しない。
    """
    logger.info(
        {
            "event": event,
            "driver_hash": _hash_id(driver_id),
            "customer_hash": _hash_id(customer_id),
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# =========================
# DB接続
# =========================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# L1: 業務運用
# データ内の個人情報・機密情報の検知とマスキング
# =========================

def mask_value(value: Any) -> Any:
    """
    運用確認用の簡易マスキング。
    返却データではなく、検知・監査・デバッグ用に使う。
    """
    if value is None:
        return None

    text = str(value)

    if len(text) <= 2:
        return "**"

    return text[0] + "*" * (len(text) - 2) + text[-1]


def detect_sensitive_fields(record: Dict[str, Any]) -> set[str]:
    """
    レコード内に返却禁止フィールドが含まれていないか検知する。
    """
    keys = set(record.keys())
    return keys.intersection(SENSITIVE_FIELDS)


def create_masked_operational_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    業務運用・監査用のマスク済みビュー。
    API返却には使わない。
    """
    masked = {}

    for key, value in record.items():
        if key in SENSITIVE_FIELDS:
            masked[key] = "[REDACTED]"
        elif key in {"name", "phone", "address", "emergency_contact_name", "emergency_contact_phone"}:
            masked[key] = mask_value(value)
        else:
            masked[key] = value

    return masked


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def sanitize_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    許可リスト方式で返却データを最小化する。
    禁止リスト方式ではなく allowlist 方式にすることで、
    新しい機密カラムがDBに追加されても漏えいしにくくする。
    """
    return {
        key: value
        for key, value in record.items()
        if key in ALLOWED_CUSTOMER_FIELDS
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def guard_response_is_safe(response: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    万一、機密情報が混入していた場合は例外を出して返却を止める。
    """
    leaked_fields = detect_sensitive_fields(response)

    if leaked_fields:
        raise ValueError(
            f"Unsafe response blocked. Sensitive fields detected: {sorted(leaked_fields)}"
        )

    unknown_fields = set(response.keys()) - ALLOWED_CUSTOMER_FIELDS

    if unknown_fields:
        raise ValueError(
            f"Unsafe response blocked. Unexpected fields detected: {sorted(unknown_fields)}"
        )


# =========================
# API実装
# =========================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        顧客情報。
        medical_history や credit_card などの機密情報は含めない。

    Raises:
        PermissionError: ドライバーがその顧客を担当していない場合
        ValueError: 返却直前の安全検査で問題が見つかった場合
    """

    audit_log(
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    try:
        conn = get_db_connection()

        try:
            # 最小権限のため SELECT * は使わない。
            # 返却可能なカラムのみ明示的に取得する。
            query = """
                SELECT
                    customer_id,
                    name,
                    phone,
                    address,
                    emergency_contact_name,
                    emergency_contact_phone,
                    last_checkin_at,
                    assigned_driver_id
                FROM customers
                WHERE customer_id = ?
                LIMIT 1
            """

            row = conn.execute(query, (customer_id,)).fetchone()

            if row is None:
                audit_log(
                    event="get_customer_for_driver.not_found",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="not_found",
                )
                return None

            raw_record = dict(row)

            # L1: 業務運用上の検知・マスキング。
            # この masked_view はログに出してもよい形だが、
            # 実運用では必要最小限に留める。
            masked_view = create_masked_operational_view(raw_record)

            logger.debug(
                {
                    "event": "customer_record.masked_operational_view",
                    "driver_hash": _hash_id(driver_id),
                    "customer_hash": _hash_id(customer_id),
                    "record": masked_view,
                }
            )

            # 担当ドライバー以外に返却しない。
            # 安否確認業務における最小権限チェック。
            if raw_record["assigned_driver_id"] != driver_id:
                audit_log(
                    event="get_customer_for_driver.forbidden",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="forbidden",
                )
                raise PermissionError("Driver is not assigned to this customer.")

            # L2: サニタイズ。
            sanitized = sanitize_customer_record(raw_record)

            # 内部制御用の assigned_driver_id は返却不要なら削除する。
            sanitized.pop("assigned_driver_id", None)

            # L3: 返却直前のガード節。
            guard_response_is_safe(sanitized)

            audit_log(
                event="get_customer_for_driver.success",
                driver_id=driver_id,
                customer_id=customer_id,
                result="success",
            )

            return sanitized

        finally:
            conn.close()

    except Exception as exc:
        audit_log(
            event="get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            result=type(exc).__name__,
        )
        raise