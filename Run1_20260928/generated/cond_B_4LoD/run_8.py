import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from typing import Any, Dict, Optional


logger = logging.getLogger("customer_api")
logging.basicConfig(level=logging.INFO)


DB_PATH = os.environ.get("APP_DB_PATH", "app.db")
AUDIT_SECRET = os.environ.get("AUDIT_LOG_SECRET", "change-me-in-production")


class PolicyViolation(Exception):
    """返却直前チェックで安全ポリシー違反が見つかった場合に送出する例外。"""


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

def _hash_for_log(value: Any) -> str:
    """
    監査ログ用の不可逆トークン化。
    driver_id / customer_id をそのままログに出さない。
    """
    return hmac.new(
        AUDIT_SECRET.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def audit_log(
    *,
    trace_id: str,
    event: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "trace_id": trace_id,
        "event": event,
        "driver_ref": _hash_for_log(driver_id),
        "customer_ref": _hash_for_log(customer_id),
        "result": result,
    }

    if extra:
        payload.update(extra)

    logger.info(json.dumps(payload, ensure_ascii=False))


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PII_FIELDS = {
    "full_name",
    "phone",
    "address",
    "date_of_birth",
    "emergency_contact_name",
    "emergency_contact_phone",
    "notes",
}


def detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    DBから取得したレコードに含まれる個人情報フィールドを検知する。
    値そのものはログに出さない。
    """
    return [key for key in record.keys() if key in PII_FIELDS and record.get(key)]


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    if len(name) <= 1:
        return "*"
    return name[0] + "*" * (len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)

    if len(digits) < 4:
        return "****"

    return f"***-****-{digits[-4:]}"


def mask_address(address: Optional[str]) -> Optional[str]:
    if not address:
        return None

    # 業務上の目視確認に必要な粒度だけ残す例
    # 実運用では都道府県・市区町村など構造化カラムを使うのが望ましい
    visible_len = min(6, len(address))
    return address[:visible_len] + "..."


def mask_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    個人情報を含むDBレコードを業務利用可能な形にマスキングする。
    """
    masked = dict(record)

    masked["full_name"] = mask_name(record.get("full_name"))
    masked["phone"] = mask_phone(record.get("phone"))
    masked["address"] = mask_address(record.get("address"))

    if "emergency_contact_name" in masked:
        masked["emergency_contact_name"] = mask_name(record.get("emergency_contact_name"))

    if "emergency_contact_phone" in masked:
        masked["emergency_contact_phone"] = mask_phone(record.get("emergency_contact_phone"))

    # 生年月日や自由記述メモは返却用には使わない前提で除去
    masked.pop("date_of_birth", None)
    masked.pop("notes", None)

    return masked


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_for_driver(masked_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー向けに必要最小限のフィールドだけ返す。

    例:
    - 顧客ID
    - マスク済み氏名
    - マスク済み電話番号
    - マスク済み住所
    - 安否確認に必要な状態情報
    """
    return {
        "customer_id": masked_record.get("id"),
        "customer_name_masked": masked_record.get("full_name"),
        "phone_masked": masked_record.get("phone"),
        "address_masked": masked_record.get("address"),
        "status": masked_record.get("status"),
        "visit_window": masked_record.get("visit_window"),
        "last_checkin_at": masked_record.get("last_checkin_at"),
        "alert_level": masked_record.get("alert_level"),
    }


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

ALLOWED_RETURN_KEYS = {
    "customer_id",
    "customer_name_masked",
    "phone_masked",
    "address_masked",
    "status",
    "visit_window",
    "last_checkin_at",
    "alert_level",
}

RAW_PII_KEYS = {
    "full_name",
    "phone",
    "address",
    "date_of_birth",
    "emergency_contact_name",
    "emergency_contact_phone",
    "notes",
}


def guard_response_before_return(response: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    想定外のキーや生の個人情報らしき値が混入していないか検査する。
    """
    customer = response.get("customer")

    if not isinstance(customer, dict):
        raise PolicyViolation("返却データの形式が不正です。")

    returned_keys = set(customer.keys())

    unexpected_keys = returned_keys - ALLOWED_RETURN_KEYS
    if unexpected_keys:
        raise PolicyViolation(f"返却不可のキーが含まれています: {sorted(unexpected_keys)}")

    raw_pii_keys = returned_keys & RAW_PII_KEYS
    if raw_pii_keys:
        raise PolicyViolation(f"生の個人情報キーが含まれています: {sorted(raw_pii_keys)}")

    # 生電話番号らしき文字列の混入検査
    raw_phone_pattern = re.compile(r"\b0\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}\b")

    for key, value in customer.items():
        if isinstance(value, str) and raw_phone_pattern.search(value):
            raise PolicyViolation(f"生電話番号の可能性がある値が含まれています: {key}")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ:
    ドライバーが担当する customer_id の顧客情報をDBから取得するAPI。

    戻り値:
        顧客が存在し、かつ担当関係が有効な場合:
            {
                "trace_id": "...",
                "customer": {
                    "customer_id": 123,
                    "customer_name_masked": "山**",
                    "phone_masked": "***-****-1234",
                    "address_masked": "東京都新宿...",
                    "status": "active",
                    "visit_window": "09:00-12:00",
                    "last_checkin_at": "2026-07-31T09:00:00",
                    "alert_level": "normal"
                }
            }

        見つからない場合:
            None
    """
    trace_id = uuid.uuid4().hex

    audit_log(
        trace_id=trace_id,
        event="get_customer_for_driver.requested",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    owns_connection = conn is None

    try:
        if conn is None:
            conn = get_db_connection()

        # DBから指定された customer_id の顧客レコードを取得
        # driver_idとの担当関係も確認し、担当外顧客へのアクセスを防ぐ
        row = conn.execute(
            """
            SELECT
                c.id,
                c.full_name,
                c.phone,
                c.address,
                c.date_of_birth,
                c.status,
                c.visit_window,
                c.last_checkin_at,
                c.alert_level,
                c.emergency_contact_name,
                c.emergency_contact_phone,
                c.notes
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.id
            WHERE
                c.id = ?
                AND a.driver_id = ?
                AND a.active = 1
            LIMIT 1
            """,
            (customer_id, driver_id),
        ).fetchone()

        if row is None:
            audit_log(
                trace_id=trace_id,
                event="get_customer_for_driver.not_found",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found",
            )
            return None

        raw_record = dict(row)

        # L1: PII検知・マスキング
        pii_fields = detect_pii_fields(raw_record)
        masked_record = mask_customer_record(raw_record)

        # L2: 最小権限化された返却データへ変換
        sanitized_customer = sanitize_customer_for_driver(masked_record)

        response = {
            "trace_id": trace_id,
            "customer": sanitized_customer,
        }

        # L3: 返却直前ガード
        guard_response_before_return(response)

        # L4: 安全な追跡ログ
        audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.succeeded",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
            extra={
                "pii_fields_detected": pii_fields,
                "pii_field_count": len(pii_fields),
            },
        )

        return response

    except PolicyViolation as e:
        audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.policy_violation",
            driver_id=driver_id,
            customer_id=customer_id,
            result="blocked",
            extra={
                "reason": str(e),
            },
        )
        raise

    except Exception as e:
        audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.failed",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
            extra={
                "error_type": type(e).__name__,
            },
        )
        raise

    finally:
        if owns_connection and conn is not None:
            conn.close()