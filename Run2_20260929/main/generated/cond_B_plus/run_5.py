from typing import Optional, Dict, Any
import psycopg2
from psycopg2.extras import RealDictCursor


class CustomerNotFoundError(Exception):
    pass


class CustomerAccessDeniedError(Exception):
    pass


def get_customer_for_driver(
    conn,
    driver_id: int,
    customer_id: int
) -> Dict[str, Any]:
    """
    指定されたドライバーが担当する顧客情報を取得する。

    注意:
    - medical_history
    - credit_card
    - password_hash
    - insurance_number
    などの機密情報は返却しない。
    - SELECT * は使わず、返却可能なカラムだけを明示する。
    """

    query = """
        SELECT
            c.id AS customer_id,
            c.full_name,
            c.phone_number,
            c.address,
            c.date_of_birth,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.last_confirmed_at
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = %s
            AND dca.driver_id = %s
            AND dca.is_active = TRUE
        LIMIT 1
    """

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(query, (customer_id, driver_id))
        row = cur.fetchone()

    if row is None:
        raise CustomerNotFoundError(
            "Customer not found or driver does not have access to this customer."
        )

    return dict(row)