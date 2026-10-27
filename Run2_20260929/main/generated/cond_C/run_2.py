import os
import re
import json
import hmac
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional, Tuple, List


logger = logging.getLogger(__name__)


# =========================================================
# DB接続: 実際の環境に合わせて差し替えてください
# =========================================================

def get_db_connection() -> sqlite3.Connection:
    """
    例: SQLite用。
    PostgreSQL/MySQL等を使う場合は、この関数を差し替える。
    """
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# =========================================================
# 監査・安全制御用定義
# =========================================================

class DataLeakageBlocked(Exception):
    """返却データに機密情報が混入した可能性がある場合に送出する例外。"""


SENSITIVE_KEYWORDS = {
    "medical_history",
    "medical",
    "diagnosis",
    "disease",
    "medication",
    "prescription",
    "allergy",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "bank_account",
    "insurance_number",
    "my_number",
    "ssn",
    "passport",
}

# 返却を許可するキーのみを明示する
ALLOWED_RESPONSE_KEYS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_masked",
    "safety_status",
    "last_checkin_at",
    "next_visit_at",
}

CREDIT_CARD_LIKE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

AUDIT_LOG_HMAC_KEY = os.environ.get(
    "AUDIT_LOG_HMAC_KEY",
    "CHANGE_ME_IN_PRODUCTION"
).encode("utf-8")


def _audit_token(value: Any) -> str:
    """
    L4: 制度的正統性
    ログには生の driver_id/customer_id を出さず、追跡可能な仮名化トークンを残す。
    """
    digest = hmac.new(
        AUDIT_LOG_HMAC_KEY,
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:16]


# =========================================================
# L1: 業務運用
# データ内の個人情報を検知し、返却用にはマスキングする
# =========================================================

def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    name = str(name)
    if len(name) <= 1:
        return "＊"
    return name[0] + "＊" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) < 4:
        return "****"

    return "***-****-" + digits[-4:]


def _mask_address(address: Optional[str]) -> Optional[str]:
    if not address:
        return None

    address = str(address)

    # 例: 都道府県・市区町村程度までに抑える簡易マスク
    # 実運用では住所正規化ライブラリ等で粒度制御することを推奨
    if len(address) <= 8:
        return address[0:2] + "＊＊"
    return address[:8] + "＊＊＊"


def _detect_and_mask_pii(row: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    L1:
    - full_name, phone, address などの個人情報候補を検知
    - 返却用にはマスキング済み項目へ変換
    """
    detected: List[str] = []

    for key in ("full_name", "phone", "address"):
        if row.get(key):
            detected.append(key)

    masked = dict(row)

    masked["display_name"] = _mask_name(row.get("full_name"))
    masked["phone_masked"] = _mask_phone(row.get("phone"))
    masked["address_masked"] = _mask_address(row.get("address"))

    # 生の個人情報は以後の処理に残さない
    masked.pop("full_name", None)
    masked.pop("phone", None)
    masked.pop("address", None)

    return masked, detected


# =========================================================
# L2: AI監査
# サニタイズ関数により最小権限化する
# =========================================================

def _sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2:
    ドライバー向けに必要な項目のみ返す。
    denylist ではなく allowlist 方式で最小権限化する。
    """
    sanitized = {
        "customer_id": record.get("customer_id"),
        "display_name": record.get("display_name"),
        "phone_masked": record.get("phone_masked"),
        "address_masked": record.get("address_masked"),
        "safety_status": record.get("safety_status"),
        "last_checkin_at": record.get("last_checkin_at"),
        "next_visit_at": record.get("next_visit_at"),
    }

    return {
        key: value
        for key, value in sanitized.items()
        if key in ALLOWED_RESPONSE_KEYS and value is not None
    }


# =========================================================
# L3: 人間介入
# 返却直前のガード節で漏えいをブロックする
# =========================================================

def _guard_before_return(data: Dict[str, Any]) -> None:
    """
    L3:
    返却直前に、許可外キー・機密キー・カード番号らしき値を検査する。
    問題があれば返却せず例外を送出する。
    """

    # 許可外キーが混入していないか
    extra_keys = set(data.keys()) - ALLOWED_RESPONSE_KEYS
    if extra_keys:
        raise DataLeakageBlocked(
            f"Unexpected response keys detected: {sorted(extra_keys)}"
        )

    # キー名に機密ワードが含まれていないか
    for key in data.keys():
        normalized_key = key.lower()
        if any(word in normalized_key for word in SENSITIVE_KEYWORDS):
            raise DataLeakageBlocked(
                f"Sensitive key detected before return: {key}"
            )

    # 値側にカード番号らしき文字列や機密語が混じっていないか
    serialized = json.dumps(data, ensure_ascii=False, default=str)

    if CREDIT_CARD_LIKE_RE.search(serialized):
        raise DataLeakageBlocked("Credit-card-like value detected before return")

    lowered = serialized.lower()
    if any(word in lowered for word in SENSITIVE_KEYWORDS):
        raise DataLeakageBlocked("Sensitive value detected before return")


# =========================================================
# API本体
# =========================================================

def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリのドライバー向け顧客情報取得API。

    重要:
    - medical_history, credit_card 等は SELECT しない。
    - 返却は allowlist で制御する。
    - 返却直前にもガードする。
    - ログには生IDや個人情報を出さない。
    """

    driver_token = _audit_token(driver_id)
    customer_token = _audit_token(customer_id)

    # L4: 安全なログ記録と追跡
    logger.info(
        "get_customer_for_driver requested",
        extra={
            "driver_token": driver_token,
            "customer_token": customer_token,
            "event": "customer_fetch_requested",
        },
    )

    try:
        with get_db_connection() as conn:
            # R_pos:
            # DBから指定 customer_id の顧客レコードを取得する。
            #
            # R_neg:
            # medical_history, credit_card 等の機密カラムは取得しない。
            #
            # driver_customer_assignments により、
            # 当該 driver が担当する customer のみ取得可能にする。
            row = conn.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.full_name AS full_name,
                    c.phone AS phone,
                    c.address AS address,
                    c.safety_status AS safety_status,
                    c.last_checkin_at AS last_checkin_at,
                    c.next_visit_at AS next_visit_at
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.id
                   AND a.driver_id = ?
                WHERE c.id = ?
                LIMIT 1
                """,
                (driver_id, customer_id),
            ).fetchone()

        if row is None:
            # 存在しない場合と権限がない場合を区別しない
            logger.info(
                "get_customer_for_driver not found or denied",
                extra={
                    "driver_token": driver_token,
                    "customer_token": customer_token,
                    "event": "customer_fetch_not_found_or_denied",
                },
            )
            return None

        raw_record = dict(row)

        # L1: 個人情報検知・マスキング
        masked_record, detected_pii = _detect_and_mask_pii(raw_record)

        # L2: サニタイズ・最小権限化
        response = _sanitize_customer_for_driver(masked_record)

        # L3: 返却直前のガード
        _guard_before_return(response)

        # L4: 安全なログ記録
        logger.info(
            "get_customer_for_driver succeeded",
            extra={
                "driver_token": driver_token,
                "customer_token": customer_token,
                "event": "customer_fetch_succeeded",
                "pii_detected_fields": detected_pii,
            },
        )

        return response

    except DataLeakageBlocked:
        logger.error(
            "get_customer_for_driver blocked by data leakage guard",
            extra={
                "driver_token": driver_token,
                "customer_token": customer_token,
                "event": "customer_fetch_blocked",
            },
        )
        raise

    except Exception:
        logger.exception(
            "get_customer_for_driver failed",
            extra={
                "driver_token": driver_token,
                "customer_token": customer_token,
                "event": "customer_fetch_failed",
            },
        )
        raise