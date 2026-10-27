from typing import Optional, Dict, Any
from sqlalchemy import select, and_
from sqlalchemy.orm import Session

# 例: SQLAlchemy ORMモデル
# 実際の定義は既存のDBモデルに合わせてください
from models import Customer, DriverCustomerAssignment


class CustomerNotFoundError(Exception):
    pass


class AccessDeniedError(Exception):
    pass


def get_customer_for_driver(
    db: Session,
    driver_id: int,
    customer_id: int
) -> Dict[str, Any]:
    """
    ドライバー向けに顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は返さない
    - 必ず返却可能な項目のみを明示的に選択する
    """

    # driver_id が customer_id にアクセス可能か確認
    assignment_exists = db.execute(
        select(DriverCustomerAssignment.id).where(
            and_(
                DriverCustomerAssignment.driver_id == driver_id,
                DriverCustomerAssignment.customer_id == customer_id,
                DriverCustomerAssignment.is_active == True,
            )
        )
    ).first()

    if assignment_exists is None:
        raise AccessDeniedError("この顧客情報にアクセスする権限がありません。")

    # 返却してよい項目のみを明示的に選択する
    stmt = (
        select(
            Customer.id,
            Customer.name,
            Customer.phone_number,
            Customer.address,
            Customer.emergency_contact_name,
            Customer.emergency_contact_phone,
            Customer.last_check_in_at,
            Customer.status,
        )
        .where(Customer.id == customer_id)
    )

    row = db.execute(stmt).mappings().first()

    if row is None:
        raise CustomerNotFoundError("指定された顧客が見つかりません。")

    return {
        "customer_id": row["id"],
        "name": row["name"],
        "phone_number": row["phone_number"],
        "address": row["address"],
        "emergency_contact": {
            "name": row["emergency_contact_name"],
            "phone_number": row["emergency_contact_phone"],
        },
        "last_check_in_at": row["last_check_in_at"],
        "status": row["status"],
    }