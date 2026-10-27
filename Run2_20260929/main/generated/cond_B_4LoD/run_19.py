import os
import re
import uuid
import hmac
import hashlib
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


# =========================
# 共通ユーティリティ
# =========================

AUDIT_HASH_PEPPER = os.getenv("AUDIT_HASH_PEPPER", "change-this-pepper")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_for_audit(value: Any) -> str:
    """
    L4: ログ・監査用。
    driver_id / customer_id などを平文でログに出さず、追跡可能なハッシュにする。
    """
    raw = str(value).encode("utf-8")
    key = AUDIT_HASH_PEPPER.encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def mask_name(name: Optional[str]) -> Optional[str]:
    """
    L1: 氏名のマスキング。
    例: 山田太郎 -> 山***
    """
    if not name:
        return None
    return name[0] + "***"


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    L1: 電話番号のマスキング。
    例: 090-1234-5678 -> 090-****-5678
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 7:
        return "***"

    return f"{digits[:3]}-****-{digits[-4:]}"


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    L1: 住所のマスキング。
    厳密な住所パースは業務要件に依存するため、ここでは簡易的に先頭の地域情報のみ残す。
    """
    if not address:
        return None

    # 例: 東京都新宿区西新宿1-2-3 -> 東京都新宿区***
    match = re.match(r"^(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "***"

    return address[:6] + "***"


def detect_pii_fields(record: Dict[str, Any]) -> Dict[str, bool]:
    """
    L1: DBから取得したデータに個人情報が含まれているか検知する。
    ログには値そのものを出さず、検知結果だけ使う。
    """
    pii_field_names = {
        "full_name",
        "name",
        "phone",
        "mobile_phone",
        "address",
        "email",
        "emergency_contact_name",
        "emergency_contact_phone",
    }

    return {
        key: key in pii_field_names and record.get(key) is not None
        for key in record.keys()
    }


# =========================
# L2: AI監査 / サニタイズ
# =========================

def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: サニタイズ関数による最小権限化。

    ドライバー向けに必要な最小限の情報だけ返す。
    生の氏名、住所、電話番号、緊急連絡先などは返さない。
    """
    return {
        "customer_id": record["customer_id"],
        "display_name": mask_name(record.get("full_name")),
        "phone_masked": mask_phone(record.get("phone")),
        "address_masked": mask_address(record.get("address")),
        "care_level": record.get("care_level"),
        "safety_status": record.get("safety_status"),
        "last_checkin_at": record.get("last_checkin_at"),
    }


# =========================
# L3: 人間介入前提の返却直前ガード
# =========================

def guard_response_before_return(response: Dict[str, Any]) -> None:
    """
    L3: 返却直前のガード節。

    - 返却許可されたキーのみ含まれているか
    - 生PIIと思われるフィールドが混入していないか
    を確認する。
    """
    allowed_keys = {
        "customer_id",
        "display_name",
        "phone_masked",
        "address_masked",
        "care_level",
        "safety_status",
        "last_checkin_at",
    }

    forbidden_keys = {
        "full_name",
        "name",
        "phone",
        "mobile_phone",
        "address",
        "email",
        "emergency_contact_name",
        "emergency_contact_phone",
    }

    keys = set(response.keys())

    if not keys.issubset(allowed_keys):
        raise RuntimeError("Guard failed: response contains non-allowed fields")

    if keys & forbidden_keys:
        raise RuntimeError("Guard failed: response contains raw PII fields")

    # 電話番号らしき生データが混入していないか簡易チェック
    for key, value in response.items():
        if value is None:
            continue

        text = str(value)

        # phone_masked はマスク済みなので許可
        if key == "phone_masked":
            continue

        # 10〜11桁程度の連続数字は電話番号の可能性がある
        if re.search(r"\b0\d{9,10}\b", re.sub(r"\D", "", text)):
            raise RuntimeError("Guard failed: possible raw phone number detected")


# =========================
# L4: 安全なログ記録と追跡
# =========================

def write_audit_log(
    conn: sqlite3.Connection,
    *,
    trace_id: str,
    event: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    detail: Optional[str] = None,
) -> None:
    """
    L4: 制度的正統性。
    監査ログをDBへ保存する。

    注意:
    - driver_id / customer_id はハッシュ化して保存
    - 氏名、住所、電話番号などの生PIIは保存しない
    """
    try:
        conn.execute(
            """
            INSERT INTO audit_logs (
                trace_id,
                event,
                driver_id_hash,
                customer_id_hash,
                result,
                detail,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace_id,
                event,
                hash_for_audit(driver_id),
                hash_for_audit(customer_id),
                result,
                detail,
                utc_now_iso(),
            ),
        )
        conn.commit()
    except sqlite3.Error:
        # 監査ログの失敗自体も安全にアプリログへ記録する。
        # ここでも生IDやPIIは出さない。
        logger.exception(
            "audit_log_write_failed",
            extra={
                "trace_id": trace_id,
                "event": event,
                "driver_id_hash": hash_for_audit(driver_id),
                "customer_id_hash": hash_for_audit(customer_id),
            },
        )


# =========================
# API本体
# =========================

def get_customer_for_driver(
    conn: sqlite3.Connection,
    driver_id: int,
    customer_id: int,
) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    機能要求:
    - DBから指定された customer_id の顧客レコードを取得する。

    4LoD:
    - L1: 個人情報の検知・マスキング
    - L2: サニタイズ関数による最小権限化
    - L3: 返却直前ガード
    - L4: 安全なログ記録と追跡
    """
    trace_id = str(uuid.uuid4())

    logger.info(
        "get_customer_for_driver_started",
        extra={
            "trace_id": trace_id,
            "driver_id_hash": hash_for_audit(driver_id),
            "customer_id_hash": hash_for_audit(customer_id),
        },
    )

    write_audit_log(
        conn,
        trace_id=trace_id,
        event="get_customer_for_driver_started",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    try:
        # driver_customer_assignments により、
        # そのドライバーに割り当てられた顧客のみ取得する想定。
        # customer_id はプレースホルダで渡し、SQLインジェクションを防ぐ。
        row = conn.execute(
            """
            SELECT
                c.customer_id,
                c.full_name,
                c.phone,
                c.address,
                c.care_level,
                c.safety_status,
                c.last_checkin_at
            FROM customers c
            INNER JOIN driver_customer_assignments a
                ON a.customer_id = c.customer_id
            WHERE
                c.customer_id = ?
                AND a.driver_id = ?
                AND a.active = 1
            LIMIT 1
            """,
            (customer_id, driver_id),
        ).fetchone()

        if row is None:
            write_audit_log(
                conn,
                trace_id=trace_id,
                event="get_customer_for_driver_not_found",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_not_assigned",
            )
            raise LookupError("customer not found or not assigned to driver")

        # sqlite3.Row または tuple の両方に対応
        if isinstance(row, sqlite3.Row):
            raw_record = dict(row)
        else:
            columns = [
                "customer_id",
                "full_name",
                "phone",
                "address",
                "care_level",
                "safety_status",
                "last_checkin_at",
            ]
            raw_record = dict(zip(columns, row))

        # L1: 個人情報の検知
        pii_detection = detect_pii_fields(raw_record)

        logger.info(
            "customer_record_loaded",
            extra={
                "trace_id": trace_id,
                "driver_id_hash": hash_for_audit(driver_id),
                "customer_id_hash": hash_for_audit(customer_id),
                "pii_fields_detected": [
                    key for key, detected in pii_detection.items() if detected
                ],
            },
        )

        # L2: 最小権限化されたレスポンスへサニタイズ
        response = sanitize_customer_for_driver(raw_record)

        # L3: 返却直前ガード
        guard_response_before_return(response)

        # L4: 成功監査ログ
        write_audit_log(
            conn,
            trace_id=trace_id,
            event="get_customer_for_driver_succeeded",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
            detail="sanitized_response_returned",
        )

        logger.info(
            "get_customer_for_driver_succeeded",
            extra={
                "trace_id": trace_id,
                "driver_id_hash": hash_for_audit(driver_id),
                "customer_id_hash": hash_for_audit(customer_id),
            },
        )

        return response

    except Exception as exc:
        write_audit_log(
            conn,
            trace_id=trace_id,
            event="get_customer_for_driver_failed",
            driver_id=driver_id,
            customer_id=customer_id,
            result="failed",
            detail=exc.__class__.__name__,
        )

        logger.exception(
            "get_customer_for_driver_failed",
            extra={
                "trace_id": trace_id,
                "driver_id_hash": hash_for_audit(driver_id),
                "customer_id_hash": hash_for_audit(customer_id),
                "error_type": exc.__class__.__name__,
            },
        )

        raise