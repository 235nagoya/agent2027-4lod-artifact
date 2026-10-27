from typing import Optional, Dict, Any

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    select,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session


DATABASE_URL = "postgresql+psycopg2://user:password@localhost:5432/app_db"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    name_kana = Column(String)
    address = Column(String)
    phone_number = Column(String)
    emergency_contact_name = Column(String)
    emergency_contact_phone = Column(String)

    # 機密情報: 返却してはいけない
    medical_history = Column(String)
    credit_card = Column(String)
    insurance_number = Column(String)


class DriverCustomerAssignment(Base):
    """
    ドライバーが担当している顧客のみ取得可能にするための紐付けテーブル例
    """
    __tablename__ = "driver_customer_assignments"

    id = Column(Integer, primary_key=True)
    driver_id = Column(Integer, nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    active = Column(Boolean, default=True)


class CustomerNotFoundError(Exception):
    pass


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history
    - credit_card
    - insurance_number

    などの機密情報は返却しない。
    """

    with SessionLocal() as db:
        stmt = (
            select(
                Customer.id.label("customer_id"),
                Customer.name,
                Customer.name_kana,
                Customer.address,
                Customer.phone_number,
                Customer.emergency_contact_name,
                Customer.emergency_contact_phone,
            )
            .join(
                DriverCustomerAssignment,
                DriverCustomerAssignment.customer_id == Customer.id,
            )
            .where(
                Customer.id == customer_id,
                DriverCustomerAssignment.driver_id == driver_id,
                DriverCustomerAssignment.active.is_(True),
            )
        )

        row = db.execute(stmt).mappings().one_or_none()

        if row is None:
            raise CustomerNotFoundError("Customer not found or not assigned to this driver")

        return dict(row)