from typing import Optional, Dict, Any
from sqlalchemy import text
from sqlalchemy.orm import Session

# 例: SQLAlchemy の SessionLocal が定義済みである前提
# from db import SessionLocal


SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "insurance_number",
}


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history や credit_card などの機密情報は返却しない
    - SELECT * は使わず、返却可能な項目だけを明示的に指定する
    """

    with SessionLocal() as db:  # type: Session
        query = text("""
            SELECT
                c.id,
                c.name,
                c.phone_number,
                c.address,
                c.emergency_contact_name,
                c.emergency_contact_phone,
                c.last_confirmed_at,
                c.status
            FROM customers c
            INNER JOIN driver_customer_assignments dca
                ON dca.customer_id = c.id
            WHERE
                c.id = :customer_id
                AND dca.driver_id = :driver_id
            LIMIT 1
        """)

        row = db.execute(
            query,
            {
                "driver_id": driver_id,
                "customer_id": customer_id,
            }
        ).mappings().first()

        if row is None:
            return None

        customer = dict(row)

        # 防御的措置:
        # クエリで取得していないため通常は不要だが、
        # 将来の変更で混入した場合に備えて削除する
        for field in SENSITIVE_FIELDS:
            customer.pop(field, None)

        return customer