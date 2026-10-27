import os
import re
import hmac
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


# ============================================================
# DB setup
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://app:pass@localhost/appdb")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


# ============================================================
# Exceptions
# ============================================================

class NotFoundError(Exception):
    pass


class AccessDeniedError(Exception):
    pass


class HumanReviewRequired(Exception):
    pass


# ============================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# - 個人情報をログに直接出さない
# - driver_id / customer_id は HMAC でハッシュ化
# - trace_id で追跡可能にする
# ============================================================

AUDIT_HASH_KEY = os.getenv("AUDIT_HASH_KEY", "change-me-in-production").encode("utf-8")


def _hash_for_audit(value: Any) -> str:
    raw = str(value).encode("utf-8")
    return hmac.new(AUDIT_HASH_KEY, raw, hashlib.sha256).hexdigest()


def audit_log(
    db,
    *,
    trace_id: str,
    event: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    reason: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    safe_extra = extra or {}

    db.execute(
        text("""
            INSERT INTO audit_logs (
                trace_id,
                event,
                actor_type,
                actor_hash,
                subject_type,
                subject_hash,
                result,
                reason,
                extra_json,
                created_at
            )
            VALUES (
                :trace_id,
                :event,
                'driver',
                :actor_hash,
                'customer',
                :subject_hash,
                :result,
                :reason,
                :extra_json,
                :created_at
            )
        """),
        {
            "trace_id": trace_id,
            "event": event,
            "actor_hash": _hash_for_audit(driver_id),
            "subject_hash": _hash_for_audit(customer_id),
            "result": result,
            "reason": reason,
            "extra_json": json.dumps(safe_extra, ensure_ascii=False),
            "created_at": datetime.now(timezone.utc),
        },
    )


# ============================================================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# ============================================================

PHONE_RE = re.compile(r"(0\d{1,4}-?\d{1,4}-?\d{3,4})")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
POSTAL_RE = re.compile(r"\d{3}-?\d{4}")


def detect_pii(value: Any) -> list[str]:
    if value is None:
        return []

    s = str(value)
    findings = []

    if PHONE_RE.search(s):
        findings.append("phone")

    if EMAIL_RE.search(s):
        findings.append("email")

    if POSTAL_RE.search(s):
        findings.append("postal_code")

    return findings


def mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    if len(name) <= 1:
        return "＊"

    return name[0] + "＊" * (len(name) - 1)


def mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)

    if len(digits) < 4:
        return "****"

    return "****-****-" + digits[-4:]


def mask_address(address: Optional[str]) -> Optional[str]:
    if not address:
        return None

    # 実運用では住所正規化ライブラリ等で都道府県・市区町村レベルに丸めるのが望ましい。
    # ここでは簡易的に番地以降を伏せる。
    masked = re.sub(r"\d+([-−ー]\d+)*", "＊＊", address)
    return masked


def mask_free_text(text_value: Optional[str]) -> Optional[str]:
    if not text_value:
        return None

    s = PHONE_RE.sub("[phone_masked]", text_value)
    s = EMAIL_RE.sub("[email_masked]", s)
    s = POSTAL_RE.sub("[postal_masked]", s)

    return s


def mask_and_detect_customer_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    pii_findings: Dict[str, list[str]] = {}

    for key, value in raw.items():
        findings = detect_pii(value)
        if findings:
            pii_findings[key] = findings

    masked = {
        **raw,
        "full_name": mask_name(raw.get("full_name")),
        "phone": mask_phone(raw.get("phone")),
        "address": mask_address(raw.get("address")),
        "emergency_note": mask_free_text(raw.get("emergency_note")),
        "_pii_findings": pii_findings,
    }

    return masked


# ============================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# - ドライバー向けに必要最小限のフィールドだけ返す
# - DBレコードをそのまま返さない
# ============================================================

def sanitize_customer_for_driver(masked: Dict[str, Any]) -> Dict[str, Any]:
    """
    Driver が安否確認業務で参照するための最小権限ビュー。
    内部ID、同意状態、削除フラグ、監査用メタ情報などは返さない。
    """

    return {
        "customer_id": masked["id"],
        "display_name": masked.get("full_name"),
        "phone": masked.get("phone"),
        "address": masked.get("address"),
        "care_level": masked.get("care_level"),
        "last_checkin_at": masked.get("last_checkin_at").isoformat()
        if masked.get("last_checkin_at") else None,
        "visit_note": masked.get("emergency_note"),
    }


# ============================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# - 権限外データが混入していないか
# - マスキングされていない電話番号・メール等が残っていないか
# - 問題があれば返却せず、人間レビュー対象にする
# ============================================================

ALLOWED_RESPONSE_KEYS = {
    "customer_id",
    "display_name",
    "phone",
    "address",
    "care_level",
    "last_checkin_at",
    "visit_note",
}


def guard_before_return(response: Dict[str, Any]) -> None:
    unexpected_keys = set(response.keys()) - ALLOWED_RESPONSE_KEYS

    if unexpected_keys:
        raise HumanReviewRequired(
            f"Unexpected fields in response: {sorted(unexpected_keys)}"
        )

    for key, value in response.items():
        if value is None:
            continue

        findings = detect_pii(value)

        # phone は mask_phone 済みの形式のみ許可する
        if key == "phone":
            raw = str(value)
            if PHONE_RE.fullmatch(raw):
                raise HumanReviewRequired("Unmasked phone number detected")
            continue

        # その他フィールドに電話番号・メール・郵便番号が残っていたらレビュー
        if findings:
            raise HumanReviewRequired(
                f"PII detected before return: field={key}, findings={findings}"
            )


# ============================================================
# Main API
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ用:
    指定された customer_id の顧客レコードをDBから取得し、
    driver_id に紐づくドライバー向けの最小権限ビューとして返す。
    """

    trace_id = str(uuid.uuid4())

    with SessionLocal() as db:
        try:
            audit_log(
                db,
                trace_id=trace_id,
                event="get_customer_for_driver.start",
                driver_id=driver_id,
                customer_id=customer_id,
                result="started",
            )

            # ------------------------------------------------------------
            # DBから指定 customer_id の顧客レコードを取得
            # driver_customer_assignments により、
            # そのドライバーが対象顧客を担当していることも確認する。
            # ------------------------------------------------------------
            row = db.execute(
                text("""
                    SELECT
                        c.id,
                        c.full_name,
                        c.phone,
                        c.address,
                        c.care_level,
                        c.last_checkin_at,
                        c.emergency_note,
                        c.consent_status
                    FROM customers c
                    INNER JOIN driver_customer_assignments a
                        ON a.customer_id = c.id
                    WHERE
                        c.id = :customer_id
                        AND a.driver_id = :driver_id
                        AND c.deleted_at IS NULL
                    LIMIT 1
                """),
                {
                    "driver_id": driver_id,
                    "customer_id": customer_id,
                },
            ).mappings().first()

            if row is None:
                audit_log(
                    db,
                    trace_id=trace_id,
                    event="get_customer_for_driver.fetch",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="denied_or_not_found",
                    reason="record_not_found_or_not_assigned",
                )
                db.commit()
                raise NotFoundError("Customer not found or not assigned to this driver")

            raw_customer = dict(row)

            if raw_customer.get("consent_status") != "active":
                audit_log(
                    db,
                    trace_id=trace_id,
                    event="get_customer_for_driver.consent_check",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="denied",
                    reason="inactive_consent",
                )
                db.commit()
                raise AccessDeniedError("Customer consent is not active")

            # L1: 個人情報の検知・マスキング
            masked_customer = mask_and_detect_customer_record(raw_customer)

            audit_log(
                db,
                trace_id=trace_id,
                event="get_customer_for_driver.pii_detection",
                driver_id=driver_id,
                customer_id=customer_id,
                result="completed",
                extra={
                    "pii_fields": list(masked_customer.get("_pii_findings", {}).keys())
                },
            )

            # L2: 最小権限化されたレスポンスへサニタイズ
            response = sanitize_customer_for_driver(masked_customer)

            # L3: 返却直前のガード節
            guard_before_return(response)

            # L4: 安全な監査ログ
            audit_log(
                db,
                trace_id=trace_id,
                event="get_customer_for_driver.success",
                driver_id=driver_id,
                customer_id=customer_id,
                result="success",
            )

            db.commit()

            return {
                "trace_id": trace_id,
                "customer": response,
            }

        except HumanReviewRequired as e:
            audit_log(
                db,
                trace_id=trace_id,
                event="get_customer_for_driver.human_review_required",
                driver_id=driver_id,
                customer_id=customer_id,
                result="blocked",
                reason=str(e),
            )
            db.commit()
            raise

        except Exception:
            db.rollback()
            raise