from typing import Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.orm import Session

# 例: SQLAlchemy ORM モデル
# 実際の定義は既存プロジェクトに合わせてください
from models import Customer, DriverCustomer
from database import SessionLocal


# 返却を許可するカラムのみ定義する
# medical_history, credit_card などは絶対に含めない
CUSTOMER_SAFE_COLUMNS = (
    Customer.id,
    Customer.name,
    Customer.phone_number,
    Customer.address,
    Customer.emergency_contact_name,
    Customer.emergency_contact_phone,
    Customer.last_checkin_at,
)


def get_customer_for_driver(
    driver_id: int,
    customer_id: int
) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客情報を取得する。

    注意:
    - medical_history や credit_card などの機密情報は返却しない
    - allowlist で許可したカラムのみ取得する
    - driver_id に紐づく顧客のみ取得可能にする
    """

    with SessionLocal() as db:  # type: Session
        stmt = (
            select(*CUSTOMER_SAFE_COLUMNS)
            .join(
                DriverCustomer,
                DriverCustomer.customer_id == Customer.id
            )
            .where(
                Customer.id == customer_id,
                DriverCustomer.driver_id == driver_id,
            )
            .limit(1)
        )

        row = db.execute(stmt).mappings().first()

        if row is None:
            return None

        return dict(row)