import hashlib
import json
import logging
import re
import uuid
from datetime import date, datetime
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.engine import Engine


# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)


AUDIT_SALT = "replace-with-secure-random-secret"


def hash_for_audit(value: Any) -> str:
    """
    監査ログ用の不可逆ハッシュ。
    driver_id / customer_id をそのままログに出さない。
    """
    raw = f"{AUDIT_SALT}:{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def safe_audit_log(
    *,
    trace_id: str,
    event: str,
    driver_id: Any,
    customer_id: Any,
    outcome: str,
    reason: Optional[str] = None,
    pii_detected_fields: Optional[list[str]] = None,
) -> None:
    """
    安全な監査ログ。
    個人情報や生IDは記録しない。
    """
    log_record = {
        "trace_id": trace_id,
        "event": event,
        "driver_hash": hash_for_audit(driver_id),
        "customer_hash": hash_for_audit(customer_id),
        "outcome": outcome,
        "reason": reason,
        "pii_detected_fields": pii_detected_fields or [],
        "logged_at": datetime.utcnow().isoformat() + "Z",
    }

    logger.info(json.dumps(log_record, ensure_ascii=False))


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PII_PATTERNS = {
    "phone": re.compile(r"0\d{1,4}-?\d{1,4}-?\d{3,4}"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "postal_code": re.compile(r"\d{3}-?\d{4}"),
}


PII_FIELD_NAMES = {
    "name",
    "full_name",
    "phone",
    "email",
    "address",
    "birth_date",
    "emergency_contact",
    "medical_notes",
}


def detect_pii_fields(record: Dict[str, Any]) -> list[str]:
    """
    レコード内に個人情報らしき値が含まれるか検知する。
    検知結果は監査ログにフィールド名のみ残す。
    値そのものはログに出さない。
    """
    detected = set()

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            detected.add(key)

        if isinstance(value, str):
            for _, pattern in PII_PATTERNS.items():
                if pattern.search(value):
                    detected.add(key)

    return sorted(detected)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    電話番号をマスキングする。
    例: 090-1234-5678 -> ***-****-5678
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "****"

    return "***-****-" + digits[-4:]


def mask_name(name: Optional[str]) -> Optional[str]:
    """
    氏名を部分マスキングする。
    例: 山田太郎 -> 山***
    """
    if not name:
        return None

    return name[0] + "***"


def calculate_age_band(birth_date: Optional[date]) -> Optional[str]:
    """
    生年月日そのものは返さず、年代に変換する。
    """
    if not birth_date:
        return None

    today = date.today()
    age = today.year - birth_date.year - (
        (today.month, today.day) < (birth_date.month, birth_date.day)
    )

    decade = age // 10 * 10
    return f"{decade}代"


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

DRIVER_ALLOWED_FIELDS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address",
    "age_band",
    "status",
    "visit_note",
}


def sanitize_customer_for_driver(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    ドライバーに必要な最小限の情報だけ返す。

    注意:
    - birth_date は返さず age_band に変換
    - phone はマスキングして返す
    - emergency_contact / medical_notes 等は返さない
    """
    sanitized = {
        "customer_id": record["customer_id"],
        "display_name": mask_name(record.get("full_name")),
        "phone_masked": mask_phone(record.get("phone")),
        "address": record.get("address"),
        "age_band": calculate_age_band(record.get("birth_date")),
        "status": record.get("status"),
        "visit_note": record.get("visit_note"),
    }

    return sanitized


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

class AccessDeniedError(Exception):
    pass


class CustomerNotFoundError(Exception):
    pass


class UnsafeResponseError(Exception):
    pass


def guard_before_return(
    *,
    sanitized: Dict[str, Any],
    driver_id: Any,
    customer_id: Any,
    assignment_active: bool,
) -> None:
    """
    返却直前の最終ガード。
    - ドライバーが当該顧客を担当しているか
    - 返却フィールドが許可リスト内か
    - customer_id のすり替わりがないか
    """
    if not assignment_active:
        raise AccessDeniedError("driver is not assigned to this customer")

    if sanitized.get("customer_id") != customer_id:
        raise UnsafeResponseError("customer_id mismatch detected")

    unexpected_fields = set(sanitized.keys()) - DRIVER_ALLOWED_FIELDS
    if unexpected_fields:
        raise UnsafeResponseError(
            f"unexpected response fields: {sorted(unexpected_fields)}"
        )


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(
    engine: Engine,
    driver_id: int,
    customer_id: int,
) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    DBから指定された customer_id の顧客レコードを取得し、
    driver_id がその顧客を担当している場合のみ、
    最小権限化された顧客情報を返す。
    """
    trace_id = str(uuid.uuid4())

    safe_audit_log(
        trace_id=trace_id,
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="started",
    )

    try:
        # SQLインジェクション対策としてパラメータバインドを使う
        sql = text("""
            SELECT
                c.id AS customer_id,
                c.full_name AS full_name,
                c.phone AS phone,
                c.address AS address,
                c.birth_date AS birth_date,
                c.status AS status,
                c.visit_note AS visit_note,
                dca.active AS assignment_active
            FROM customers c
            LEFT JOIN driver_customer_assignments dca
                ON dca.customer_id = c.id
               AND dca.driver_id = :driver_id
            WHERE c.id = :customer_id
            LIMIT 1
        """)

        with engine.connect() as conn:
            row = conn.execute(
                sql,
                {
                    "driver_id": driver_id,
                    "customer_id": customer_id,
                },
            ).mappings().first()

        if row is None:
            safe_audit_log(
                trace_id=trace_id,
                event="get_customer_for_driver.not_found",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="failed",
                reason="customer_not_found",
            )
            raise CustomerNotFoundError("customer not found")

        raw_record = dict(row)

        # L1: PII検知
        pii_detected_fields = detect_pii_fields(raw_record)

        safe_audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.db_record_loaded",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="loaded",
            pii_detected_fields=pii_detected_fields,
        )

        assignment_active = bool(raw_record.get("assignment_active"))

        # L2: 最小権限化
        sanitized = sanitize_customer_for_driver(raw_record)

        # L3: 返却直前のガード
        guard_before_return(
            sanitized=sanitized,
            driver_id=driver_id,
            customer_id=customer_id,
            assignment_active=assignment_active,
        )

        # L4: 安全な成功ログ
        safe_audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.success",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            pii_detected_fields=pii_detected_fields,
        )

        return {
            "trace_id": trace_id,
            "customer": sanitized,
        }

    except AccessDeniedError:
        safe_audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.access_denied",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="failed",
            reason="access_denied",
        )
        raise

    except UnsafeResponseError as e:
        safe_audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.unsafe_response_blocked",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="blocked",
            reason=str(e),
        )
        raise

    except Exception as e:
        safe_audit_log(
            trace_id=trace_id,
            event="get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
            reason=e.__class__.__name__,
        )
        raise