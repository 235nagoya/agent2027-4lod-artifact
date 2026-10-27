from typing import Any, Dict
from sqlalchemy import select
from sqlalchemy.orm import Session

# 例外
class CustomerNotFoundError(Exception):
    pass


# 既存のSQLAlchemyモデルを想定
# class Customer(Base):
#     __tablename__ = "customers"
#     id = Column(Integer, primary_key=True)
#     name = Column(String)
#     phone_number = Column(String)
#     address = Column(String)
#     emergency_contact_name = Column(String)
#     emergency_contact_phone = Column(String)
#     last_safety_check_at = Column(DateTime)
#     safety_status = Column(String)
#
#     # 以下は機密情報なので返却しない
#     medical_history = Column(Text)
#     credit_card = Column(String)
#
#
# class DriverCustomerAssignment(Base):
#     __tablename__ = "driver_customer_assignments"
#     driver_id = Column(Integer)
#     customer_id = Column(Integer)


# DBセッション生成関数を想定
# from db import SessionLocal
# from models import Customer, DriverCustomerAssignment


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は返さない
    - 安全のため、返却可能なカラムのみを明示的に select する
    """

    # 返却を許可するカラムのみを明示する
    safe_columns = [
        Customer.id,
        Customer.name,
        Customer.phone_number,
        Customer.address,
        Customer.emergency_contact_name,
        Customer.emergency_contact_phone,
        Customer.last_safety_check_at,
        Customer.safety_status,
    ]

    with SessionLocal() as db:
        stmt = (
            select(*safe_columns)
            .join(
                DriverCustomerAssignment,
                DriverCustomerAssignment.customer_id == Customer.id,
            )
            .where(Customer.id == customer_id)
            .where(DriverCustomerAssignment.driver_id == driver_id)
        )

        row = db.execute(stmt).mappings().one_or_none()

        if row is None:
            raise CustomerNotFoundError("Customer not found or not assigned to this driver")

        result = dict(row)

        # 防御的チェック: 万が一混入した場合も除外
        sensitive_fields = {
            "medical_history",
            "credit_card",
            "credit_card_number",
            "card_cvv",
            "insurance_number",
        }

        for field in sensitive_fields:
            result.pop(field, None)

        return result