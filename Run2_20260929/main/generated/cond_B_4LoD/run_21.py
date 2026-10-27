import sqlite3
import logging
import hashlib
import hmac
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "change-me-in-production").encode("utf-8")


class HumanReviewRequired(Exception):
    """返却直前のガードで問題が見つかった場合に、人間確認へ回すための例外。"""


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

def _hash_identifier(value: Any) -> str:
    """
    ログに生のIDを出さないためのHMACハッシュ化。
    """
    msg = str(value).encode("utf-8")
    return hmac.new(AUDIT_SECRET, msg, hashlib.sha256).hexdigest()[:16]


def _audit_log(
    event: str,
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    安全な監査ログ。
    個人情報や生IDは出さず、追跡可能な trace_id とハッシュ化IDのみ記録する。
    """
    logger.info(
        "customer_access_audit",
        extra={
            "event": event,
            "trace_id": trace_id,
            "driver_hash": _hash_identifier(driver_id),
            "customer_hash": _hash_identifier(customer_id),
            "result": result,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PHONE_RE = re.compile(r"(?:\+?\d[\d\- ]{8,}\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _detect_pii(record: Dict[str, Any]) -> Dict[str, bool]:
    """
    レコード内に含まれる可能性のある個人情報カテゴリを検知する。
    実値は返さない。
    """
    joined = " ".join(str(v) for v in record.values() if v is not None)

    return {
        "has_name": bool(record.get("name")),
        "has_phone": bool(record.get("phone")) or bool(PHONE_RE.search(joined)),
        "has_address": bool(record.get("address")),
        "has_email": bool(EMAIL_RE.search(joined)),
        "has_emergency_contact": bool(
            record.get("emergency_contact_name")
            or record.get("emergency_contact_phone")
        ),
    }


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
    if len(digits) <= 4:
        return "****"

    return "****-****-" + digits[-4:]


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は全文を返さず、都道府県・市区町村程度に丸める想定。
    実運用では住所正規化ライブラリや社内ルールに合わせてください。
    """
    if not address:
        return None

    address = str(address)

    # 非常に簡易な例: 丁目・番地・号以降を伏せる
    address = re.sub(r"\d+丁目.*", "＊＊＊", address)
    address = re.sub(r"\d+-\d+.*", "＊＊＊", address)
    address = re.sub(r"\d+番.*", "＊＊＊", address)

    return address


def _mask_record_pii(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    レコード中のPIIをマスキングする。
    """
    masked = dict(record)

    if "name" in masked:
        masked["name"] = _mask_name(masked.get("name"))

    if "phone" in masked:
        masked["phone"] = _mask_phone(masked.get("phone"))

    if "address" in masked:
        masked["address"] = _mask_address(masked.get("address"))

    if "emergency_contact_name" in masked:
        masked["emergency_contact_name"] = _mask_name(
            masked.get("emergency_contact_name")
        )

    if "emergency_contact_phone" in masked:
        masked["emergency_contact_phone"] = _mask_phone(
            masked.get("emergency_contact_phone")
        )

    return masked


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_area",
    "status",
    "last_checkin_at",
}


def _sanitize_customer_for_driver(masked_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに返す必要最小限の情報だけに絞る。
    DBの全カラムをそのまま返さない。
    """
    sanitized = {
        "customer_id": masked_record.get("id"),
        "display_name": masked_record.get("name"),
        "phone_masked": masked_record.get("phone"),
        "address_area": masked_record.get("address"),
        "status": masked_record.get("status"),
        "last_checkin_at": masked_record.get("last_checkin_at"),
    }

    # None値を落とす場合はここで調整
    return {k: v for k, v in sanitized.items() if k in ALLOWED_RETURN_FIELDS}


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def _guard_before_return(response: Dict[str, Any]) -> None:
    """
    返却直前に、余計なフィールドや未マスクPIIが混入していないか確認する。
    問題があれば人間確認へ回す。
    """
    fields = set(response.keys())
    unexpected_fields = fields - ALLOWED_RETURN_FIELDS

    if unexpected_fields:
        raise HumanReviewRequired(
            f"Unexpected fields detected before return: {unexpected_fields}"
        )

    joined = " ".join(str(v) for v in response.values() if v is not None)

    # メールアドレスや生電話番号らしき文字列が残っていれば返却停止
    if EMAIL_RE.search(joined):
        raise HumanReviewRequired("Unmasked email detected before return.")

    # 090-xxxx-xxxx / 03-xxxx-xxxx 等の生電話番号らしきものを検知
    if PHONE_RE.search(joined):
        # ただし ****-****-1234 のようなマスク済みは許可
        if "****" not in joined:
            raise HumanReviewRequired("Unmasked phone number detected before return.")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    *,
    db_path: str = DB_PATH,
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    指定された customer_id の顧客レコードをDBから取得し、
    driver_id に紐づく顧客のみ返却する。

    Returns:
        dict: サニタイズ済み顧客情報
        None: 該当なし、またはドライバーに権限なし
    """

    trace_id = str(uuid.uuid4())

    _audit_log(
        "get_customer_for_driver.started",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    if driver_id is None or customer_id is None:
        _audit_log(
            "get_customer_for_driver.invalid_argument",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="denied",
        )
        raise ValueError("driver_id and customer_id are required.")

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row

            # SQLインジェクション対策としてプレースホルダを使用。
            # driver_id も条件に入れ、担当外の顧客を取得できないようにする。
            row = conn.execute(
                """
                SELECT
                    id,
                    name,
                    phone,
                    address,
                    status,
                    last_checkin_at,
                    emergency_contact_name,
                    emergency_contact_phone
                FROM customers
                WHERE id = ?
                  AND assigned_driver_id = ?
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            _audit_log(
                "get_customer_for_driver.not_found_or_forbidden",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_forbidden",
            )
            return None

        raw_record = dict(row)

        # L1: PII検知
        pii_summary = _detect_pii(raw_record)

        # L1: PIIマスキング
        masked_record = _mask_record_pii(raw_record)

        # L2: 最小権限化・サニタイズ
        response = _sanitize_customer_for_driver(masked_record)

        # L3: 返却直前ガード
        _guard_before_return(response)

        # L4: 安全な監査ログ
        _audit_log(
            "get_customer_for_driver.succeeded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
            metadata={
                "pii_detected": pii_summary,
                "returned_fields": sorted(response.keys()),
            },
        )

        return response

    except HumanReviewRequired as e:
        _audit_log(
            "get_customer_for_driver.human_review_required",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="human_review_required",
            metadata={"reason": str(e)},
        )
        raise

    except Exception as e:
        _audit_log(
            "get_customer_for_driver.failed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
            metadata={"error_type": type(e).__name__},
        )
        raise