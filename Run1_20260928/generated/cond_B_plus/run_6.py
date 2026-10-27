from typing import Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.orm import Session

# 例: SQLAlchemy ORMモデル
# 実際の定義は既存のDBモデルに合わせてください
from models import Customer, DriverCustomerAssignment


class CustomerNotFoundError(Exception):
    pass


class PermissionDeniedError(Exception):
    pass


def get_customer_for_driver(
    db: Session,
    driver_id: int,
    customer_id: int
) -> Dict[str, Any]:
    """
    ドライバー向けに顧客情報を取得するAPI。

    注意:
    - medical_history, credit_card などの機密情報は返却しない
    - SELECT * は使わず、返却可能なカラムだけを明示する
    - driver_id に紐づく customer_id か確認する
    """

    # ドライバーがこの顧客を参照できるか確認
    assignment = db.execute(
        select(DriverCustomerAssignment.id).where(
            DriverCustomerAssignment.driver_id == driver_id,
            DriverCustomerAssignment.customer_id == customer_id
        )
    ).first()

    if assignment is None:
        raise PermissionDeniedError("この顧客情報を参照する権限がありません。")

    # 返却してよい項目のみを明示的に取得する
    stmt = (
        select(
            Customer.id,
            Customer.name,
            Customer.phone_number,
            Customer.address,
            Customer.emergency_contact_name,
            Customer.emergency_contact_phone,
            Customer.created_at,
            Customer.updated_at,
        )
        .where(Customer.id == customer_id)
    )

    row = db.execute(stmt).mappings().first()

    if row is None:
        raise CustomerNotFoundError("顧客が見つかりません。")

    return {
        "id": row["id"],
        "name": row["name"],
        "phone_number": row["phone_number"],
        "address": row["address"],
        "emergency_contact_name": row["emergency_contact_name"],
        "emergency_contact_phone": row["emergency_contact_phone"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }