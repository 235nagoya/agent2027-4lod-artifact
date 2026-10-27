import os
import re
import json
import hmac
import uuid
import hashlib
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

logger = logging.getLogger("safety_app.audit")
logger.setLevel(logging.INFO)

# 本番では環境変数やKMSから取得してください
AUDIT_HASH_SECRET = os.getenv("AUDIT_HASH_SECRET", "change-me-in-production")


class CustomerAccessError(Exception):
    pass


class CustomerNotFoundError(CustomerAccessError):
    pass


class PermissionDeniedError(CustomerAccessError):
    pass


class HumanReviewRequiredError(CustomerAccessError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_identifier(value: Any) -> str:
    """
    ログに driver_id / customer_id をそのまま出さないためのHMACハッシュ化。
    """
    raw = str(value).encode("utf-8")
    secret = AUDIT_HASH_SECRET.encode("utf-8")
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()


def audit_log(
    *,
    event: str,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    L4: 個人情報を含めず、追跡可能な監査ログを残す。
    """
    payload = {
        "ts": _utc_now_iso(),
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id),
        "customer_hash": _hash_identifier(customer_id),
        "outcome": outcome,
        "reason": reason,
        "extra": extra or {},
    }
    logger.info(json.dumps(payload, ensure_ascii=False))


def create_human_review_ticket(
    *,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    reason: str,
) -> None:
    """
    L3: 人間介入が必要な場合のチケット作成スタブ。
    実運用ではチケット管理システムや管理者通知に接続する。
    """
    audit_log(
        event="human_review_ticket_created",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="pending_review",
        reason=reason,
    )


# ============================================================
# L1: 業務運用 - データ内の個人情報を検知・マスキング
# ============================================================

PHONE_RE = re.compile(r"(\+?\d[\d\-\s]{7,}\d)")
EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def detect_pii(value: Any) -> bool:
    """
    簡易的なPII検知。
    実運用では住所・氏名・医療情報などの検知ルールを拡張する。
    """
    if value is None:
        return False

    text = str(value)
    if PHONE_RE.search(text):
        return True
    if EMAIL_RE.search(text):
        return True

    return False


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "***"

    return "***-****-" + digits[-4:]


def mask_email(email: Optional[str]) -> Optional[str]:
    if not email or "@" not in email:
        return None

    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"

    return f"{masked_local}@{domain}"


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    # 例: 山田太郎 -> 山**
    return name[0] + "**"


def reduce_address(address: Optional[str]) -> Optional[str]:
    """
    配送・訪問担当者向けに必要最低限の住所表現にする例。
    本番では町丁目まで、建物名・部屋番号を落とすなど要件に合わせる。
    """
    if not address:
        return None

    # 簡易例: 空白より前だけを返す
    return address.split()[0]


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_for_driver(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに返してよい最小限の顧客情報へ変換する。

    rawにはDBから取得したフルレコードが入る想定だが、
    返却値には直接的なPIIやセンシティブ情報を含めない。
    """
    sanitized = {
        "customer_id": raw.get("customer_id"),
        "display_name": mask_name(raw.get("full_name")),
        "phone_masked": mask_phone(raw.get("phone")),
        "email_masked": mask_email(raw.get("email")),
        "address_area": reduce_address(raw.get("address")),
        "visit_note": raw.get("driver_visit_note"),
        "safety_status": raw.get("safety_status"),
        "last_checkin_at": raw.get("last_checkin_at"),
    }

    # None値を落としてレスポンスを最小化
    sanitized = {k: v for k, v in sanitized.items() if v is not None}

    return sanitized


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

DISALLOWED_RESPONSE_FIELDS = {
    "full_name",
    "phone",
    "email",
    "address",
    "date_of_birth",
    "medical_history",
    "medical_notes",
    "emergency_contact_phone",
    "emergency_contact_name",
}


def guard_response_before_return(
    *,
    response: Dict[str, Any],
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
) -> None:
    """
    返却直前の安全確認。
    問題がある場合は人間レビューに回す。
    """

    # 生PIIフィールドが混入していないか確認
    leaked_fields = DISALLOWED_RESPONSE_FIELDS.intersection(response.keys())
    if leaked_fields:
        reason = f"disallowed fields in response: {sorted(leaked_fields)}"
        create_human_review_ticket(
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason=reason,
        )
        raise HumanReviewRequiredError(reason)

    # 値の中に電話番号・メールアドレスらしきものが残っていないか確認
    pii_like_fields = []
    for key, value in response.items():
        # mask済みの phone_masked / email_masked は許容
        if key in {"phone_masked", "email_masked"}:
            continue
        if detect_pii(value):
            pii_like_fields.append(key)

    if pii_like_fields:
        reason = f"pii-like values detected in response: {pii_like_fields}"
        create_human_review_ticket(
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason=reason,
        )
        raise HumanReviewRequiredError(reason)


# ============================================================
# DB utility
# ============================================================

def dict_from_row(cursor: sqlite3.Cursor, row: sqlite3.Row) -> Dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def get_db_connection() -> sqlite3.Connection:
    """
    サンプルではSQLite。
    本番ではPostgreSQL/MySQL等の接続に置き換える。
    """
    db_path = os.getenv("DB_PATH", "app.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    処理概要:
    1. driver_id と customer_id の担当関係を確認
    2. DBから指定 customer_id の顧客レコードを取得
    3. PIIを検知・マスキング
    4. ドライバー向けに最小限の情報へサニタイズ
    5. 返却直前にガード節で安全確認
    6. 安全な監査ログを記録
    """

    trace_id = str(uuid.uuid4())

    audit_log(
        event="get_customer_for_driver_started",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    conn = get_db_connection()

    try:
        # driver_customer_assignments で担当関係を確認しつつ、
        # customers から指定 customer_id のレコードを取得する。
        #
        # 注意:
        # - SQLインジェクション対策としてプレースホルダを使用
        # - driver_id と customer_id の紐づき確認を同時に実施
        sql = """
            SELECT
                c.id AS customer_id,
                c.full_name,
                c.phone,
                c.email,
                c.address,
                c.safety_status,
                c.last_checkin_at,
                c.driver_visit_note
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.id
            WHERE
                c.id = ?
                AND a.driver_id = ?
                AND a.is_active = 1
            LIMIT 1
        """

        cur = conn.execute(sql, (customer_id, driver_id))
        row = cur.fetchone()

        if row is None:
            # 顧客不存在か、担当外かを外部には区別しない設計も可能。
            audit_log(
                event="get_customer_for_driver_denied_or_not_found",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="denied_or_not_found",
            )
            raise CustomerNotFoundError("customer not found or access denied")

        raw_customer = dict(row)

        # L1: DBから取得したデータのPII検知状況を安全に記録
        pii_detected_fields = [
            key for key, value in raw_customer.items()
            if detect_pii(value)
        ]

        audit_log(
            event="customer_record_loaded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="loaded",
            extra={
                "pii_detected_field_count": len(pii_detected_fields),
                # フィールド名のみ。値はログに出さない。
                "pii_detected_fields": pii_detected_fields,
            },
        )

        # L2: 最小権限化されたレスポンスに変換
        response = sanitize_customer_for_driver(raw_customer)

        # L3: 返却直前のガード節
        guard_response_before_return(
            response=response,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
        )

        # L4: 成功ログ
        audit_log(
            event="get_customer_for_driver_succeeded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            extra={
                "returned_fields": sorted(response.keys()),
            },
        )

        return response

    except HumanReviewRequiredError:
        audit_log(
            event="get_customer_for_driver_blocked_for_human_review",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason="human_review_required",
        )
        raise

    except CustomerAccessError:
        raise

    except Exception as exc:
        audit_log(
            event="get_customer_for_driver_failed",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
            reason=exc.__class__.__name__,
        )
        raise

    finally:
        conn.close()