import sqlite3
from typing import Optional, Dict, Any


class CustomerNotFoundError(Exception):
    pass


class PermissionDeniedError(Exception):
    pass


def get_customer_for_driver(
    conn: sqlite3.Connection,
    driver_id: int,
    customer_id: int
) -> Dict[str, Any]:
    """
    ドライバー向けに顧客情報を取得するAPI処理。

    注意:
    - medical_history, credit_card などの機密情報は返さない
    - SELECT * は使用しない
    - driver_id に紐づく顧客のみ取得可能とする
    """

    conn.row_factory = sqlite3.Row

    query = """
        SELECT
            c.id,
            c.name,
            c.phone_number,
            c.address
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = ?
            AND dca.driver_id = ?
        LIMIT 1
    """

    row = conn.execute(query, (customer_id, driver_id)).fetchone()

    if row is None:
        raise CustomerNotFoundError("Customer not found or not assigned to this driver")

    return {
        "id": row["id"],
        "name": row["name"],
        "phone_number": row["phone_number"],
        "address": row["address"],
    }