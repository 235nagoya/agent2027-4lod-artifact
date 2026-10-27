from typing import Any, Dict, Optional

from sqlalchemy import Table, Column, Integer, String, Boolean, MetaData, ForeignKey, select
from sqlalchemy.orm import Session


metadata = MetaData()

# 顧客テーブル例
customers = Table(
    "customers",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String),
    Column("phone_number", String),
    Column("address", String),
    Column("emergency_contact_name", String),
    Column("emergency_contact_phone", String),

    # 機密情報: 返却してはいけない
    Column("medical_history", String),
    Column("credit_card", String),
)

# ドライバーと顧客の担当関係テーブル例
driver_customer_assignments = Table(
    "driver_customer_assignments",
    metadata,
    Column("driver_id", Integer, nullable=False),
    Column("customer_id", Integer, ForeignKey("customers.id"), nullable=False),
    Column("active", Boolean, default=True),
)


class CustomerNotFoundError(Exception):
    pass


def get_customer_for_driver(
    db: Session,
    driver_id: int,
    customer_id: int,
) -> Dict[str, Any]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history や credit_card などの機密情報は返却しない
    - SELECT * は使わず、返却可能なカラムだけを明示的に指定する
    """

    # 返却してよいカラムのみを許可リスト化
    allowed_columns = [
        customers.c.id,
        customers.c.name,
        customers.c.phone_number,
        customers.c.address,
        customers.c.emergency_contact_name,
        customers.c.emergency_contact_phone,
    ]

    stmt = (
        select(*allowed_columns)
        .select_from(
            customers.join(
                driver_customer_assignments,
                customers.c.id == driver_customer_assignments.c.customer_id,
            )
        )
        .where(customers.c.id == customer_id)
        .where(driver_customer_assignments.c.driver_id == driver_id)
        .where(driver_customer_assignments.c.active.is_(True))
    )

    row: Optional[Dict[str, Any]] = db.execute(stmt).mappings().one_or_none()

    if row is None:
        raise CustomerNotFoundError("Customer not found or access denied")

    result = dict(row)

    # 念のための防御的チェック
    forbidden_fields = {
        "medical_history",
        "credit_card",
        "credit_card_number",
        "card_number",
        "cvv",
        "password",
    }

    for field in forbidden_fields:
        result.pop(field, None)

    return result