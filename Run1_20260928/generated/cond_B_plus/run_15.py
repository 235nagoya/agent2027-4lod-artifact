from typing import Optional, Dict, Any
from sqlalchemy import text
from sqlalchemy.engine import Engine

# 例: SQLAlchemy の Engine
# engine = create_engine(DB_URL)
engine: Engine = None  # 実際のアプリ側で設定してください


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    ドライバー向けに顧客情報を取得するAPI。

    注意:
    - medical_history, credit_card などの機密情報は返却しない
    - driver_id に紐づく customer_id のみ取得する
    """

    query = text("""
        SELECT
            c.id AS customer_id,
            c.full_name,
            c.phone_number,
            c.address,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.last_checkin_at,
            c.status
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = :customer_id
            AND dca.driver_id = :driver_id
        LIMIT 1
    """)

    with engine.connect() as conn:
        row = conn.execute(
            query,
            {
                "driver_id": driver_id,
                "customer_id": customer_id,
            }
        ).mappings().first()

    if row is None:
        return None

    return dict(row)