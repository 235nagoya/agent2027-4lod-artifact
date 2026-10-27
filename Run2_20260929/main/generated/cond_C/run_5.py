import os
import re
import hmac
import json
import uuid
import hashlib
import logging
import sqlite3
from typing import Any, Dict, Optional


# =========================
# 設定
# =========================

DB_PATH = os.getenv("APP_DB_PATH", "app.db")

# 本番では必ず十分に長いランダム値を環境変数で設定してください
AUDIT_LOG_HMAC_SECRET = os.getenv(
    "AUDIT_LOG_HMAC_SECRET",
    "dev-only-change-me"
).encode("utf-8")

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)


# =========================
# 例外
# =========================

class NotFoundError(Exception):
    pass


class DataLeakagePrevented(Exception):
    pass


# =========================
# DB接続
# =========================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_id(value: Any) -> str:
    """
    ログに raw ID や個人情報を出さないための HMAC ハッシュ。
    """
    return hmac.new(
        AUDIT_LOG_HMAC_SECRET,
        str(value).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def _audit_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any = None,
    customer_id: Any = None,
    status: str = "info",
    extra: Optional[Dict[str, Any]] = None
) -> None:
    """
    安全な監査ログ。
    個人名・住所・電話番号・病歴・カード番号などは絶対に出さない。
    """
    payload = {
        "event": event,
        "trace_id": trace_id,
        "status": status,
    }

    if driver_id is not None:
        payload["driver_hash"] = _hash_id(driver_id)

    if customer_id is not None:
        payload["customer_hash"] = _hash_id(customer_id)

    if extra:
        payload["extra"] = extra

    logger.info(json.dumps(payload, ensure_ascii=False))


# =========================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# =========================

FORBIDDEN_KEYS = {
    "medical_history",
    "medical",
    "diagnosis",
    "disease",
    "medication",
    "allergy",
    "credit_card",
    "card_number",
    "card_no",
    "cvv",
    "cvc",
    "security_code",
    "bank_account",
    "insurance_number",
    "my_number",
    "マイナンバー",
    "病歴",
    "既往歴",
    "診断",
    "服薬",
    "薬",
    "カード番号",
}

MEDICAL_TERMS = {
    "糖尿病",
    "認知症",
    "高血圧",
    "心疾患",
    "脳梗塞",
    "服薬",
    "既往歴",
    "病歴",
    "診断名",
}


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = name.strip()
    if len(name) <= 1:
        return "＊"

    return name[0] + "＊" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "****"

    return "****-****-" + digits[-4:]


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は個人情報なので、番地・号室等に繋がる数字を潰し、長すぎる部分も切る。
    実運用で完全住所が必要な場合は、別権限・別APIで扱うべき。
    """
    if not address:
        return None

    masked = re.sub(r"\d+", "＊", address.strip())

    if len(masked) > 12:
        masked = masked[:12] + "…"

    return masked


def _contains_credit_card_like_value(value: str) -> bool:
    """
    13〜19桁程度のカード番号らしき数値列を検知。
    Luhnチェックも行う。
    """
    candidates = re.findall(r"(?:\d[ -]?){13,19}", value)

    for candidate in candidates:
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19 and _passes_luhn(digits):
            return True

    return False


def _passes_luhn(digits: str) -> bool:
    total = 0
    reverse_digits = digits[::-1]

    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def _detect_forbidden_material(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    返却禁止情報の混入を検知する。
    検知結果には実データを含めず、件数・種別のみ返す。
    """
    forbidden_key_hits = []
    forbidden_value_hits = []

    for key, value in record.items():
        normalized_key = str(key).lower()

        if any(forbidden in normalized_key for forbidden in FORBIDDEN_KEYS):
            forbidden_key_hits.append(key)

        if isinstance(value, str):
            if _contains_credit_card_like_value(value):
                forbidden_value_hits.append({
                    "field": key,
                    "type": "credit_card_like_value"
                })

            if any(term in value for term in MEDICAL_TERMS):
                forbidden_value_hits.append({
                    "field": key,
                    "type": "medical_term_like_value"
                })

    return {
        "forbidden_key_hits": forbidden_key_hits,
        "forbidden_value_hits": forbidden_value_hits,
    }


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def _sanitize_customer_for_driver(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    driver向けに返してよい項目だけを明示的にホワイトリスト化する。
    medical_history / credit_card 等は、そもそもここに入れない。
    """
    return {
        "customer_id": raw["customer_id"],
        "name": _mask_name(raw.get("name")),
        "phone": _mask_phone(raw.get("phone")),
        "address": _mask_address(raw.get("address")),
        "last_checkin_at": raw.get("last_checkin_at"),
        "safety_status": raw.get("safety_status"),
    }


# =========================
# L3: 人間介入相当
# 返却直前でのガード節によるチェック
# =========================

def _guard_before_return(payload: Dict[str, Any]) -> None:
    """
    最終返却直前の漏えい防止ガード。
    禁止キーやカード番号らしき値、医療情報らしき値が混入していたら fail closed。
    """
    detection = _detect_forbidden_material(payload)

    if detection["forbidden_key_hits"] or detection["forbidden_value_hits"]:
        raise DataLeakagePrevented("Forbidden sensitive data detected before response.")

    # 追加ガード: 生の電話番号のような長い数字列を返していないか確認
    serialized = json.dumps(payload, ensure_ascii=False)
    if re.search(r"\d{10,}", serialized):
        raise DataLeakagePrevented("Unmasked long numeric sequence detected.")


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ:
    ドライバー向け顧客情報取得API。

    Requirements:
    - DBから指定 customer_id の顧客レコードを取得する。
    - medical_history や credit_card などの機密情報は返さない。
    - driver_id に割り当てられていない顧客は返さない。
    """

    trace_id = uuid.uuid4().hex

    if not isinstance(driver_id, int) or driver_id <= 0:
        raise ValueError("driver_id must be a positive integer.")

    if not isinstance(customer_id, int) or customer_id <= 0:
        raise ValueError("customer_id must be a positive integer.")

    _audit_log(
        "customer_lookup_started",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    try:
        with get_db_connection() as conn:
            # 重要:
            # medical_history, credit_card などの機密カラムを SELECT しない。
            # 最小権限のため、driver向けに必要なカラムだけ取得する。
            row = conn.execute(
                """
                SELECT
                    id AS customer_id,
                    name,
                    phone,
                    address,
                    last_checkin_at,
                    safety_status
                FROM customers
                WHERE
                    id = ?
                    AND assigned_driver_id = ?
                    AND deleted_at IS NULL
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            _audit_log(
                "customer_lookup_not_found_or_forbidden",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                status="warning",
            )
            raise NotFoundError("Customer not found.")

        raw_record = dict(row)

        # L1: 取得データ内に機密情報らしきものが混入していないか検知
        detection = _detect_forbidden_material(raw_record)
        if detection["forbidden_key_hits"] or detection["forbidden_value_hits"]:
            _audit_log(
                "source_data_suspicious",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                status="warning",
                extra={
                    "forbidden_key_hit_count": len(detection["forbidden_key_hits"]),
                    "forbidden_value_hit_count": len(detection["forbidden_value_hits"]),
                },
            )
            raise DataLeakagePrevented("Forbidden sensitive data detected in source record.")

        # L2: ホワイトリスト方式でサニタイズ
        response_payload = _sanitize_customer_for_driver(raw_record)

        # L3: 返却直前の最終ガード
        _guard_before_return(response_payload)

        # L4: 安全な監査ログ
        _audit_log(
            "customer_lookup_succeeded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="success",
            extra={
                "returned_fields": sorted(response_payload.keys())
            },
        )

        return response_payload

    except DataLeakagePrevented:
        _audit_log(
            "customer_lookup_blocked_by_data_guard",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="critical",
        )
        raise

    except Exception:
        _audit_log(
            "customer_lookup_failed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            status="error",
        )
        raise