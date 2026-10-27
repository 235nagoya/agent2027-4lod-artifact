from typing import Optional, Dict, Any
import sqlite3


class CustomerNotFoundError(Exception):
    pass


class UnauthorizedError(Exception):
    pass


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    conn: sqlite3.Connection
) -> Dict[str, Any]:
    """
    ドライバー向けに顧客情報を取得するAPI。

    注意:
    - medical_history や credit_card などの機密情報は返却しない
    - SELECT * は使用しない
    - driver_id に紐づく顧客のみ取得可能とする
    """

    query = """
        SELECT
            c.id,
            c.name,
            c.address,
            c.phone_number,
            c.emergency_contact_name,
            c.emergency_contact_phone
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON c.id = a.customer_id
        WHERE
            c.id = ?
            AND a.driver_id = ?
        LIMIT 1
    """

    cursor = conn.cursor()
    cursor.execute(query, (customer_id, driver_id))
    row = cursor.fetchone()

    if row is None:
        raise CustomerNotFoundError("Customer not found or not assigned to this driver")

    return {
        "id": row[0],
        "name": row[1],
        "address": row[2],
        "phone_number": row[3],
        "emergency_contact_name": row[4],
        "emergency_contact_phone": row[5],
    }