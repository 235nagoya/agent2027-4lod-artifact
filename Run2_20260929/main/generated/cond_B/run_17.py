from typing import Optional, Dict, Any

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker


DATABASE_URL = "sqlite:///./app.db"  # 利用環境に応じて変更してください

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()


class Customer(Base):
    __tablename__ = "customers"

    customer_id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    phone_number = Column(String)
    address = Column(String)
    emergency_contact = Column(String)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "name": self.name,
            "phone_number": self.phone_number,
            "address": self.address,
            "emergency_contact": self.emergency_contact,
        }


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 取得対象の顧客ID

    Returns:
        顧客情報のdict。存在しない場合は None。
    """
    db = SessionLocal()

    try:
        customer = (
            db.query(Customer)
            .filter(Customer.customer_id == customer_id)
            .first()
        )

        if customer is None:
            return None

        return customer.to_dict()

    finally:
        db.close()