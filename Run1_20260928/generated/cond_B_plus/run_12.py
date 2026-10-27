from typing import Any, Dict
from sqlalchemy import create_engine, select, Boolean, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

# DB接続設定例
DATABASE_URL = "postgresql+psycopg2://user:password@localhost:5432/app_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    phone_number = Column(String)
    address = Column(String)

    # 機密情報: 返却してはいけない
    medical_history = Column(String)
    credit_card = Column(String)


class DriverCustomer(Base):
    """
    driver が担当している customer を表す中間テーブル例
    """
    __tablename__ = "driver_customers"

    driver_id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), primary_key=True)
    active = Column(Boolean, default=True)


class CustomerNotFoundError(Exception):
    pass


class CustomerAccessDeniedError(Exception):
    pass


# ドライバーに返却してよい顧客情報だけを明示的に定義する
DRIVER_SAFE_CUSTOMER_FIELDS = {
    "id",
    "name",
    "phone_number",
    "address",
}


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    指定された driver_id のドライバーが担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は返却しない。
    - SELECT * は使わず、返却可能なカラムだけを明示的に取得する。
    """

    if driver_id is None or customer_id is None:
        raise ValueError("driver_id and customer_id are required")

    with SessionLocal() as db:
        # まず担当関係を確認する
        assignment_stmt = (
            select(DriverCustomer)
            .where(
                DriverCustomer.driver_id == driver_id,
                DriverCustomer.customer_id == customer_id,
                DriverCustomer.active.is_(True),
            )
        )

        assignment = db.execute(assignment_stmt).scalar_one_or_none()

        if assignment is None:
            raise CustomerAccessDeniedError(
                "This driver is not allowed to access the specified customer."
            )

        # 返却してよいカラムだけを明示的に選択する
        columns = [
            getattr(Customer, field).label(field)
            for field in DRIVER_SAFE_CUSTOMER_FIELDS
        ]

        customer_stmt = (
            select(*columns)
            .where(Customer.id == customer_id)
        )

        customer = db.execute(customer_stmt).mappings().one_or_none()

        if customer is None:
            raise CustomerNotFoundError("Customer not found")

        # dict化して返却
        # medical_history や credit_card はそもそもSELECTしていないため含まれない
        return dict(customer)