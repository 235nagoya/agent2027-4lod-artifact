import os
import re
import json
import hmac
import uuid
import sqlite3
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ============================================================
# 基本設定
# ============================================================

DB_PATH = os.environ.get("APP_DB_PATH", "app.db")
AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", "CHANGE_ME_IN_PRODUCTION")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ============================================================
# 例外
# ============================================================

class CustomerNotFoundError(Exception):
    pass


class SecurityGuardError(Exception):
    pass


# ============================================================
# PII検知用
# ============================================================

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\b0\d{1,4}-?\d{1,4}-?\d{4}\b")

PII_FIELD_NAMES = {
    "full_name",
    "phone_number",
    "email",
    "address",
    "emergency_contact_name",
    "emergency_contact_phone",
}

ALLOWED_RESPONSE_KEYS = {
    "trace_id",
    "customer",
}

ALLOWED_CUSTOMER_KEYS = {
    "customer_id",
    "display_name",
    "phone_hint",
    "address_hint",
    "safety_status",
    "last_confirmed_at",
    "special_notes",
}


# ============================================================
# DB接続
# ============================================================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# ============================================================

def _hmac_identifier(value: Any) -> str:
    """
    ログ・監査用の識別子ハッシュ。
    driver_id / customer_id をそのままログに出さない。
    """
    raw = str(value).encode("utf-8")
    key = AUDIT_HMAC_KEY.encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def safe_log(
    *,
    event: str,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: Optional[str] = None,
) -> None:
    """
    個人情報や生IDを出さない安全なアプリケーションログ。
    """
    payload = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hmac_identifier(driver_id),
        "customer_hash": _hmac_identifier(customer_id),
        "outcome": outcome,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(json.dumps(payload, ensure_ascii=False))


def ensure_audit_table(conn: sqlite3.Connection) -> None:
    """
    サンプル用。
    本番ではマイグレーション管理で作成することを推奨。
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT NOT NULL,
            event TEXT NOT NULL,
            driver_hash TEXT NOT NULL,
            customer_hash TEXT NOT NULL,
            outcome TEXT NOT NULL,
            details_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )


def write_audit_log(
    conn: sqlite3.Connection,
    *,
    trace_id: str,
    event: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    監査証跡用DBログ。
    生の氏名・電話番号・住所・メールアドレスは保存しない。
    """
    ensure_audit_table(conn)

    conn.execute(
        """
        INSERT INTO api_audit_logs (
            trace_id,
            event,
            driver_hash,
            customer_hash,
            outcome,
            details_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            trace_id,
            event,
            _hmac_identifier(driver_id),
            _hmac_identifier(customer_id),
            outcome,
            json.dumps(details or {}, ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        ),
    )


# ============================================================
# L1: 業務運用
# データ内の個人情報を検知・マスキング
# ============================================================

def detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    DBから取得したレコード内にPIIらしき値が存在するか検知する。
    値そのものは返さず、フィールド名のみ返す。
    """
    detected = set()

    for key, value in record.items():
        if value is None:
            continue

        if key in PII_FIELD_NAMES:
            detected.add(key)
            continue

        if isinstance(value, str):
            if EMAIL_RE.search(value) or PHONE_RE.search(value):
                detected.add(key)

    return sorted(detected)


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

    return "***-****-" + digits[-4:]


def mask_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None

    if "@" not in email:
        return "***"

    local, domain = email.split("@", 1)
    if not local:
        return "***@" + domain

    return local[0] + "***@" + domain


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は詳細番地を返さず、概略だけにする。
    例: 東京都新宿区西新宿1-2-3 -> 東京都新宿区...
    """
    if not address:
        return None

    match = re.match(r"(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "..."

    return address[:6] + "..."


def redact_pii_in_text(text: Optional[str]) -> Optional[str]:
    """
    自由記述欄に含まれる可能性があるメール・電話番号を除去する。
    """
    if not text:
        return None

    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)

    # 過剰な自由記述流出を防ぐため長さ制限
    return text[:200]


def mask_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    業務運用上扱う中間データをマスキングする。
    """
    return {
        **record,
        "full_name": mask_name(record.get("full_name")),
        "phone_number": mask_phone(record.get("phone_number")),
        "email": mask_email(record.get("email")),
        "address": mask_address(record.get("address")),
        "special_notes": redact_pii_in_text(record.get("special_notes")),
    }


# ============================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_for_driver(masked_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバー向けに必要最小限の項目だけ返す。
    DBレコードをそのまま返さない。
    """
    return {
        "customer_id": masked_record["customer_id"],
        "display_name": masked_record.get("full_name"),
        "phone_hint": masked_record.get("phone_number"),
        "address_hint": masked_record.get("address"),
        "safety_status": masked_record.get("safety_status"),
        "last_confirmed_at": masked_record.get("last_confirmed_at"),
        "special_notes": masked_record.get("special_notes"),
    }


# ============================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# ============================================================

def guard_response_before_return(response: Dict[str, Any]) -> None:
    """
    返却直前の最終チェック。
    意図しないPIIフィールドや生の電話番号・メールアドレスが
    混入していないことを確認する。
    """
    top_keys = set(response.keys())
    if not top_keys.issubset(ALLOWED_RESPONSE_KEYS):
        raise SecurityGuardError(f"unexpected top-level keys: {top_keys - ALLOWED_RESPONSE_KEYS}")

    customer = response.get("customer")
    if not isinstance(customer, dict):
        raise SecurityGuardError("customer must be an object")

    customer_keys = set(customer.keys())
    if not customer_keys.issubset(ALLOWED_CUSTOMER_KEYS):
        raise SecurityGuardError(f"unexpected customer keys: {customer_keys - ALLOWED_CUSTOMER_KEYS}")

    # 生のPIIキー名が混入していないか確認
    forbidden_keys = customer_keys.intersection(PII_FIELD_NAMES)
    if forbidden_keys:
        raise SecurityGuardError(f"forbidden pii keys found: {forbidden_keys}")

    serialized = json.dumps(response, ensure_ascii=False)

    # 生メール・生電話番号らしき値が残っていないか確認
    if EMAIL_RE.search(serialized):
        raise SecurityGuardError("raw email-like value found in response")

    if PHONE_RE.search(serialized):
        raise SecurityGuardError("raw phone-like value found in response")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用API。

    指定された customer_id の顧客レコードをDBから取得し、
    4LoDに沿ってマスキング・監査・最小権限化・返却直前チェックを行う。

    戻り値:
        顧客情報が存在し、かつ driver_id に紐づく場合:
            {
                "trace_id": "...",
                "customer": {
                    "customer_id": 123,
                    "display_name": "山***",
                    "phone_hint": "***-****-1234",
                    "address_hint": "東京都新宿区...",
                    "safety_status": "OK",
                    "last_confirmed_at": "2026-07-31T09:00:00+09:00",
                    "special_notes": "..."
                }
            }

        見つからない場合:
            None
    """
    trace_id = str(uuid.uuid4())

    safe_log(
        event="get_customer_for_driver.start",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    with get_db_connection() as conn:
        write_audit_log(
            conn,
            trace_id=trace_id,
            event="get_customer_for_driver.start",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="started",
        )

        # ------------------------------------------------------------
        # DB取得
        # customer_id を指定して顧客レコードを取得する。
        # driver_customer_assignments により、driver_id に紐づく顧客のみ取得。
        # ------------------------------------------------------------
        row = conn.execute(
            """
            SELECT
                c.customer_id,
                c.full_name,
                c.phone_number,
                c.email,
                c.address,
                c.safety_status,
                c.last_confirmed_at,
                c.special_notes
            FROM customers c
            INNER JOIN driver_customer_assignments dca
                ON dca.customer_id = c.customer_id
            WHERE
                c.customer_id = ?
                AND dca.driver_id = ?
                AND dca.active = 1
            LIMIT 1
            """,
            (customer_id, driver_id),
        ).fetchone()

        if row is None:
            write_audit_log(
                conn,
                trace_id=trace_id,
                event="get_customer_for_driver.not_found",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found",
            )

            safe_log(
                event="get_customer_for_driver.not_found",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found",
            )

            return None

        raw_record = dict(row)

        # ------------------------------------------------------------
        # L1: 業務運用
        # PIIを検知し、マスキングした中間レコードを作る。
        # ------------------------------------------------------------
        pii_fields = detect_pii_fields(raw_record)
        masked_record = mask_customer_record(raw_record)

        write_audit_log(
            conn,
            trace_id=trace_id,
            event="get_customer_for_driver.pii_detected",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="detected",
            details={
                "pii_fields": pii_fields,
            },
        )

        # ------------------------------------------------------------
        # L2: AI監査
        # ドライバーに必要な最小項目だけにサニタイズする。
        # ------------------------------------------------------------
        sanitized_customer = sanitize_customer_for_driver(masked_record)

        response = {
            "trace_id": trace_id,
            "customer": sanitized_customer,
        }

        # ------------------------------------------------------------
        # L3: 人間介入
        # 返却直前のガード節。
        # ------------------------------------------------------------
        try:
            guard_response_before_return(response)
        except SecurityGuardError as exc:
            write_audit_log(
                conn,
                trace_id=trace_id,
                event="get_customer_for_driver.guard_failed",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="blocked",
                details={
                    "reason": str(exc),
                },
            )

            safe_log(
                event="get_customer_for_driver.guard_failed",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="blocked",
                reason=exc.__class__.__name__,
            )

            raise

        # ------------------------------------------------------------
        # L4: 制度的正統性
        # 成功時の安全な監査ログ。
        # ------------------------------------------------------------
        write_audit_log(
            conn,
            trace_id=trace_id,
            event="get_customer_for_driver.success",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            details={
                "returned_fields": sorted(sanitized_customer.keys()),
            },
        )

        safe_log(
            event="get_customer_for_driver.success",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
        )

        return response