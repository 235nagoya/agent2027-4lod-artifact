import os
import re
import json
import uuid
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    create_engine,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    JSON,
    select,
    exists,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
    Session,
)

# ============================================================
# DB / Logger
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://user:pass@localhost/app")
AUDIT_PEPPER = os.getenv("AUDIT_PEPPER", "change-me-in-production")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)


# ============================================================
# SQLAlchemy Models
# ============================================================

class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # 個人情報を含み得る項目
    full_name: Mapped[str] = mapped_column(String(255))
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    emergency_contact_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    emergency_contact_phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    care_notes: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)

    status: Mapped[str] = mapped_column(String(50), default="active")
    consent_to_share: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DriverCustomerAssignment(Base):
    """
    driver_id と customer_id の割当。
    ドライバーが担当している顧客だけを参照可能にするために使う。
    """
    __tablename__ = "driver_customer_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    driver_id: Mapped[int] = mapped_column(Integer, index=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditEvent(Base):
    """
    L4: 制度的正統性のための監査ログ。
    生の個人情報は保存しない。
    """
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(100))
    actor_type: Mapped[str] = mapped_column(String(50), default="driver")
    actor_hash: Mapped[str] = mapped_column(String(128))
    target_hash: Mapped[str] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(50))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ============================================================
# Exceptions
# ============================================================

class CustomerNotFound(Exception):
    pass


class AccessDenied(Exception):
    pass


class HumanReviewRequired(Exception):
    pass


# ============================================================
# L4: 安全なログ記録と追跡
# ============================================================

def _hash_identifier(value: Any) -> str:
    """
    ログ・監査用の不可逆ハッシュ。
    driver_id / customer_id をそのままログに出さない。
    """
    msg = str(value).encode("utf-8")
    key = AUDIT_PEPPER.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def safe_audit_log(
    db: Session,
    *,
    trace_id: str,
    event_type: str,
    driver_id: int,
    customer_id: int,
    outcome: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    L4: 安全なログ記録。
    - 生の氏名、電話番号、住所、メール等は記録しない。
    - driver_id / customer_id はハッシュ化する。
    - trace_id で後追い可能にする。
    """
    details = details or {}

    safe_record = {
        "trace_id": trace_id,
        "event_type": event_type,
        "actor_type": "driver",
        "actor_hash": _hash_identifier(driver_id),
        "target_hash": _hash_identifier(customer_id),
        "outcome": outcome,
        "details": details,
    }

    # アプリケーションログにもPIIなしで出力
    logger.info(json.dumps(safe_record, ensure_ascii=False))

    # 監査DBにもPIIなしで保存
    try:
        db.add(
            AuditEvent(
                trace_id=trace_id,
                event_type=event_type,
                actor_type="driver",
                actor_hash=safe_record["actor_hash"],
                target_hash=safe_record["target_hash"],
                outcome=outcome,
                details=details,
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("failed_to_write_audit_event")


# ============================================================
# L1: 業務運用 - 個人情報の検知・マスキング
# ============================================================

PHONE_RE = re.compile(r"(?<!\d)(?:\+81[-\s]?)?0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}(?!\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MY_NUMBER_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")  # マイナンバー等の12桁番号検知用


def detect_pii(value: Optional[str]) -> list[str]:
    """
    文字列中に含まれる可能性のあるPIIを検知する。
    """
    if not value:
        return []

    found = []

    if PHONE_RE.search(value):
        found.append("phone")

    if EMAIL_RE.search(value):
        found.append("email")

    if MY_NUMBER_RE.search(value):
        found.append("12_digit_identifier")

    return found


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
        return "***"

    return "***-****-" + digits[-4:]


def mask_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None

    if "@" not in email:
        return "***"

    local, domain = email.split("@", 1)
    first = local[:1] if local else "*"

    return f"{first}***@{domain}"


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は再識別性が高いため、詳細住所は返さない。
    業務上必要なら、別途権限レベルや当日訪問中フラグ等で制御する。
    """
    if not address:
        return None

    return "住所登録あり（詳細非表示）"


def mask_free_text(text: Optional[str]) -> Optional[str]:
    """
    care_notes 等の自由記述に混入した電話番号・メール等をマスキングする。
    """
    if not text:
        return None

    text = EMAIL_RE.sub("[EMAIL_MASKED]", text)
    text = PHONE_RE.sub("[PHONE_MASKED]", text)
    text = MY_NUMBER_RE.sub("[ID_MASKED]", text)

    return text


def l1_mask_and_detect_customer(customer: Customer) -> tuple[Dict[str, Any], Dict[str, list[str]]]:
    """
    L1: DBから取得した顧客レコードに含まれるPIIを検知し、
    返却候補データをマスキングする。
    """
    pii_report = {
        "full_name": detect_pii(customer.full_name),
        "phone": detect_pii(customer.phone),
        "email": detect_pii(customer.email),
        "address": detect_pii(customer.address),
        "emergency_contact_name": detect_pii(customer.emergency_contact_name),
        "emergency_contact_phone": detect_pii(customer.emergency_contact_phone),
        "care_notes": detect_pii(customer.care_notes),
    }

    masked = {
        "customer_id": customer.id,
        "full_name": mask_name(customer.full_name),
        "phone": mask_phone(customer.phone),
        "email": mask_email(customer.email),
        "address": mask_address(customer.address),
        "emergency_contact_name": mask_name(customer.emergency_contact_name),
        "emergency_contact_phone": mask_phone(customer.emergency_contact_phone),
        "care_notes": mask_free_text(customer.care_notes),
        "status": customer.status,
        "consent_to_share": customer.consent_to_share,
    }

    return masked, pii_report


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

DRIVER_RETURN_ALLOWLIST = {
    "customer_id",
    "display_name",
    "phone",
    "address",
    "care_notes",
    "status",
    "trace_id",
}


def sanitize_customer_for_driver(masked_customer: Dict[str, Any], *, trace_id: str) -> Dict[str, Any]:
    """
    L2: ドライバー向けに最小限の項目だけを返す。
    DBレコードをそのまま返さない。

    返却対象:
    - customer_id
    - display_name
    - phone
    - address
    - care_notes
    - status
    - trace_id

    除外例:
    - email
    - emergency_contact_name
    - emergency_contact_phone
    - consent_to_share
    - created_at 等
    """
    return {
        "customer_id": masked_customer["customer_id"],
        "display_name": masked_customer["full_name"],
        "phone": masked_customer["phone"],
        "address": masked_customer["address"],
        "care_notes": masked_customer["care_notes"],
        "status": masked_customer["status"],
        "trace_id": trace_id,
    }


# ============================================================
# L3: 人間介入 - 返却直前ガード
# ============================================================

def create_human_review_ticket(
    db: Session,
    *,
    trace_id: str,
    driver_id: int,
    customer_id: int,
    reason: str,
    fields: Optional[list[str]] = None,
) -> None:
    """
    実運用ではチケットシステム、Slack、管理画面等に連携する。
    ここでは監査ログに HUMAN_REVIEW_REQUIRED として残す。
    """
    safe_audit_log(
        db,
        trace_id=trace_id,
        event_type="HUMAN_REVIEW_REQUIRED",
        driver_id=driver_id,
        customer_id=customer_id,
        outcome="blocked",
        details={
            "reason": reason,
            "fields": fields or [],
        },
    )


def l3_pre_return_guard(
    db: Session,
    *,
    payload: Dict[str, Any],
    trace_id: str,
    driver_id: int,
    customer_id: int,
    consent_to_share: bool,
) -> None:
    """
    L3: 返却直前のガード節。
    問題があれば人間レビューへ回し、API返却を止める。
    """

    # 1. 同意状態チェック
    if not consent_to_share:
        create_human_review_ticket(
            db,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason="customer_consent_missing",
        )
        raise HumanReviewRequired("customer consent is missing")

    # 2. allowlist以外のキーが混入していないか
    extra_keys = set(payload.keys()) - DRIVER_RETURN_ALLOWLIST
    if extra_keys:
        create_human_review_ticket(
            db,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason="unexpected_fields_in_response",
            fields=sorted(extra_keys),
        )
        raise HumanReviewRequired("unexpected fields in response")

    # 3. 返却文字列中に未マスクPIIらしきものが残っていないか
    pii_fields = []

    for key, value in payload.items():
        if isinstance(value, str):
            detected = detect_pii(value)
            if detected:
                pii_fields.append(key)

    if pii_fields:
        create_human_review_ticket(
            db,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            reason="possible_unmasked_pii_detected",
            fields=pii_fields,
        )
        raise HumanReviewRequired("possible unmasked PII detected")


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリ用:
    ドライバーが担当顧客情報を取得するAPI。

    4LoD:
    - L1: 個人情報の検知・マスキング
    - L2: サニタイズ関数による最小権限化
    - L3: 返却直前ガードと人間レビュー
    - L4: 安全な監査ログとtrace_idによる追跡
    """
    trace_id = str(uuid.uuid4())

    with SessionLocal() as db:
        safe_audit_log(
            db,
            trace_id=trace_id,
            event_type="GET_CUSTOMER_REQUESTED",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="started",
        )

        # ----------------------------------------------------
        # DBから指定 customer_id の顧客レコードを取得
        # ----------------------------------------------------
        customer = db.get(Customer, customer_id)

        if customer is None:
            safe_audit_log(
                db,
                trace_id=trace_id,
                event_type="GET_CUSTOMER_NOT_FOUND",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="not_found",
            )
            raise CustomerNotFound(f"customer_id={customer_id} was not found")

        # ドライバーが担当している顧客か確認
        assigned = db.scalar(
            select(
                exists().where(
                    DriverCustomerAssignment.driver_id == driver_id,
                    DriverCustomerAssignment.customer_id == customer_id,
                    DriverCustomerAssignment.active.is_(True),
                )
            )
        )

        if not assigned:
            safe_audit_log(
                db,
                trace_id=trace_id,
                event_type="GET_CUSTOMER_ACCESS_DENIED",
                driver_id=driver_id,
                customer_id=customer_id,
                outcome="denied",
                details={"reason": "driver_not_assigned_to_customer"},
            )
            raise AccessDenied("driver is not assigned to this customer")

        # ----------------------------------------------------
        # L1: 個人情報の検知・マスキング
        # ----------------------------------------------------
        masked_customer, pii_report = l1_mask_and_detect_customer(customer)

        detected_fields = [
            field for field, detected in pii_report.items()
            if detected
        ]

        safe_audit_log(
            db,
            trace_id=trace_id,
            event_type="L1_PII_DETECTION_COMPLETED",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="ok",
            details={
                # PIIそのものではなく、検知されたフィールド名だけを記録
                "detected_fields": detected_fields,
            },
        )

        # ----------------------------------------------------
        # L2: サニタイズ関数による最小権限化
        # ----------------------------------------------------
        payload = sanitize_customer_for_driver(masked_customer, trace_id=trace_id)

        safe_audit_log(
            db,
            trace_id=trace_id,
            event_type="L2_SANITIZE_COMPLETED",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="ok",
            details={
                "returned_fields": sorted(payload.keys()),
            },
        )

        # ----------------------------------------------------
        # L3: 返却直前でのガード節
        # ----------------------------------------------------
        l3_pre_return_guard(
            db,
            payload=payload,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            consent_to_share=customer.consent_to_share,
        )

        # ----------------------------------------------------
        # L4: 成功ログ
        # ----------------------------------------------------
        safe_audit_log(
            db,
            trace_id=trace_id,
            event_type="GET_CUSTOMER_SUCCEEDED",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="success",
            details={
                "returned_fields": sorted(payload.keys()),
            },
        )

        return payload