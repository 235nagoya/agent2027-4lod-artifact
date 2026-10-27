import os
import re
import json
import uuid
import hmac
import hashlib
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Iterable


DB_PATH = os.getenv("APP_DB_PATH", "app.db")
LOG_HASH_SECRET = os.getenv("LOG_HASH_SECRET", "change-me-in-production").encode("utf-8")

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# =========================
# L4: 安全なログ記録と追跡
# =========================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_identifier(value: Any) -> str:
    """
    ログ用の不可逆ID。
    driver_id / customer_id をそのままログに出さない。
    """
    msg = str(value).encode("utf-8")
    return hmac.new(LOG_HASH_SECRET, msg, hashlib.sha256).hexdigest()


def audit_event(
    event_name: str,
    trace_id: str,
    driver_id: Optional[Any] = None,
    customer_id: Optional[Any] = None,
    result: str = "info",
    meta: Optional[Dict[str, Any]] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """
    PIIを含めない監査ログ。
    必要に応じてDBの audit_events テーブルにも記録する。
    """
    safe_record = {
        "timestamp": _now_iso(),
        "event": event_name,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id) if driver_id is not None else None,
        "customer_hash": _hash_identifier(customer_id) if customer_id is not None else None,
        "result": result,
        "meta": meta or {},
    }

    logger.info(json.dumps(safe_record, ensure_ascii=False))

    if conn is not None:
        try:
            conn.execute(
                """
                INSERT INTO audit_events (
                    timestamp,
                    event_name,
                    trace_id,
                    driver_hash,
                    customer_hash,
                    result,
                    meta_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    safe_record["timestamp"],
                    safe_record["event"],
                    safe_record["trace_id"],
                    safe_record["driver_hash"],
                    safe_record["customer_hash"],
                    safe_record["result"],
                    json.dumps(safe_record["meta"], ensure_ascii=False),
                ),
            )
            conn.commit()
        except sqlite3.Error:
            # 監査ログDBへの書き込み失敗時も、生PIIは出さない
            logger.warning(
                json.dumps(
                    {
                        "timestamp": _now_iso(),
                        "event": "audit_write_failed",
                        "trace_id": trace_id,
                        "result": "warning",
                    },
                    ensure_ascii=False,
                )
            )


# =========================
# L1: 個人情報の検知・マスキング
# =========================

PII_KEYWORDS = {
    "name",
    "full_name",
    "phone",
    "mobile",
    "email",
    "address",
    "birthdate",
    "birthday",
    "emergency_contact",
    "emergency_phone",
}

PHONE_RE = re.compile(r"(?<!\d)(?:0\d{1,4}-?\d{1,4}-?\d{3,4})(?!\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def detect_personal_info(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    値そのものは返さず、PIIらしき項目・カテゴリだけ返す。
    """
    detected_keys = []
    detected_patterns = set()

    for key, value in record.items():
        lower_key = key.lower()

        if any(word in lower_key for word in PII_KEYWORDS):
            detected_keys.append(key)

        if isinstance(value, str):
            if PHONE_RE.search(value):
                detected_patterns.add("phone_like")
            if EMAIL_RE.search(value):
                detected_patterns.add("email_like")

    return {
        "pii_key_count": len(detected_keys),
        "pii_keys": detected_keys,
        "patterns": sorted(detected_patterns),
    }


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    name = str(name).strip()
    if len(name) <= 1:
        return "＊"
    return name[0] + "＊" * max(1, len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) <= 4:
        return "****"

    return "****-****-" + digits[-4:]


def summarize_address(address: Optional[str]) -> Optional[str]:
    """
    ドライバー業務上必要な粒度に落とす例。
    実運用では「町名まで」「建物名非表示」など業務ルールに合わせる。
    """
    if not address:
        return None

    address = str(address).strip()

    # かなり単純な例: 長すぎる住所や番地以降を丸める
    address = re.sub(r"\d+[-丁目番地号\d]*.*$", "付近", address)

    return address[:30]


# =========================
# L2: サニタイズ関数による最小権限化
# =========================

def sanitize_customer_for_driver(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    DBから取得した顧客レコードを、ドライバー業務に必要な最小項目へ変換する。

    生の氏名・電話番号・住所・緊急連絡先などは返さない。
    """
    return {
        "customer_id": raw.get("id"),
        "display_name": mask_name(raw.get("name")),
        "phone_masked": mask_phone(raw.get("phone")),
        "address_summary": summarize_address(raw.get("address")),
        "visit_note": raw.get("visit_note"),
        "last_checkin_at": raw.get("last_checkin_at"),
        "status": raw.get("status"),
    }


# =========================
# L3: 返却直前のガード節
# =========================

RAW_PII_FORBIDDEN_KEYS = {
    "name",
    "full_name",
    "phone",
    "mobile",
    "email",
    "address",
    "birthdate",
    "birthday",
    "emergency_contact",
    "emergency_phone",
}


def _iter_values(obj: Any) -> Iterable[Any]:
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _iter_values(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_values(value)
    else:
        yield obj


def guard_response_before_return(response: Dict[str, Any]) -> None:
    """
    返却直前の安全確認。
    生PIIキーや、明らかなメールアドレス等が混入していたら返さない。
    """
    keys = {str(k).lower() for k in response.keys()}

    forbidden = keys & RAW_PII_FORBIDDEN_KEYS
    if forbidden:
        raise ValueError(f"Unsafe response: forbidden raw PII keys detected: {sorted(forbidden)}")

    for value in _iter_values(response):
        if isinstance(value, str):
            if EMAIL_RE.search(value):
                raise ValueError("Unsafe response: email-like value detected")

            # マスク済み電話番号は許可し、生電話っぽいものだけ拒否
            if PHONE_RE.search(value) and "*" not in value:
                raise ValueError("Unsafe response: raw phone-like value detected")


# =========================
# DB接続
# =========================

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id, customer_id) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    指定された customer_id の顧客レコードをDBから取得する。
    ただし、driver_id に紐づく担当顧客のみ取得できる前提。

    想定テーブル:
      customers:
        id, name, phone, address, visit_note, last_checkin_at, status, deleted_at

      driver_customer_assignments:
        driver_id, customer_id, active

      audit_events:
        timestamp, event_name, trace_id, driver_hash, customer_hash, result, meta_json
    """
    trace_id = str(uuid.uuid4())
    conn: Optional[sqlite3.Connection] = None

    try:
        # 入力の基本検証
        driver_id_int = int(driver_id)
        customer_id_int = int(customer_id)

        if driver_id_int <= 0 or customer_id_int <= 0:
            raise ValueError("driver_id and customer_id must be positive integers")

        conn = get_db_connection()

        audit_event(
            event_name="get_customer_for_driver.requested",
            trace_id=trace_id,
            driver_id=driver_id_int,
            customer_id=customer_id_int,
            result="started",
            conn=conn,
        )

        # SQLインジェクション対策としてプレースホルダを使用
        # driver_id の割当確認も同時に行い、最小権限にする。
        row = conn.execute(
            """
            SELECT
                c.id,
                c.name,
                c.phone,
                c.address,
                c.visit_note,
                c.last_checkin_at,
                c.status
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.id
            WHERE
                c.id = ?
                AND a.driver_id = ?
                AND a.active = 1
                AND c.deleted_at IS NULL
            LIMIT 1
            """,
            (customer_id_int, driver_id_int),
        ).fetchone()

        if row is None:
            # 存在しないのか権限がないのかを区別して返さない
            audit_event(
                event_name="get_customer_for_driver.not_found_or_forbidden",
                trace_id=trace_id,
                driver_id=driver_id_int,
                customer_id=customer_id_int,
                result="not_found",
                conn=conn,
            )
            return None

        raw_record = dict(row)

        # L1: PII検知。値はログに出さない。
        pii_detection = detect_personal_info(raw_record)
        audit_event(
            event_name="get_customer_for_driver.pii_detected",
            trace_id=trace_id,
            driver_id=driver_id_int,
            customer_id=customer_id_int,
            result="detected",
            meta=pii_detection,
            conn=conn,
        )

        # L2: ドライバー業務に必要な最小項目へサニタイズ
        response = sanitize_customer_for_driver(raw_record)

        # L3: 返却直前のガード
        guard_response_before_return(response)

        # L4: 成功監査ログ
        audit_event(
            event_name="get_customer_for_driver.succeeded",
            trace_id=trace_id,
            driver_id=driver_id_int,
            customer_id=customer_id_int,
            result="success",
            meta={
                "returned_fields": sorted(response.keys())
            },
            conn=conn,
        )

        return response

    except Exception as exc:
        # 例外ログにもPIIは入れない
        if conn is not None:
            audit_event(
                event_name="get_customer_for_driver.failed",
                trace_id=trace_id,
                driver_id=driver_id if driver_id is not None else None,
                customer_id=customer_id if customer_id is not None else None,
                result="error",
                meta={
                    "error_type": type(exc).__name__
                },
                conn=conn,
            )

        raise

    finally:
        if conn is not None:
            conn.close()