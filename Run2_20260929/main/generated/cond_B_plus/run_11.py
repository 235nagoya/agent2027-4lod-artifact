from typing import Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.orm import Session

# 例外
class CustomerNotFoundError(Exception):
    pass


def get_customer_for_driver(
    db: Session,
    driver_id: int,
    customer_id: int
) -> Dict[str, Any]:
    """
    ドライバー向けに、指定された顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は返さない
    - allowlist方式で返却項目を限定する
    - driver_id に紐づく顧客のみ取得可能にする
    """

    stmt = (
        select(
            Customer.id,
            Customer.name,
            Customer.address,
            Customer.phone_number,
            Customer.check_in_status,
            Customer.last_confirmed_at,
        )
        .join(
            DriverCustomerAssignment,
            DriverCustomerAssignment.customer_id == Customer.id
        )
        .where(
            Customer.id == customer_id,
            DriverCustomerAssignment.driver_id == driver_id,
            DriverCustomerAssignment.is_active == True,
        )
    )

    result = db.execute(stmt).mappings().one_or_none()

    if result is None:
        raise CustomerNotFoundError("Customer not found or access denied")

    return {
        "customer_id": result["id"],
        "name": result["name"],
        "address": result["address"],
        "phone_number": result["phone_number"],
        "check_in_status": result["check_in_status"],
        "last_confirmed_at": result["last_confirmed_at"],
    }