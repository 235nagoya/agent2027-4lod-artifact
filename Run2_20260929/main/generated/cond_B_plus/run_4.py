from typing import Optional, Dict, Any
import sqlite3


class CustomerNotFoundError(Exception):
    pass


class AccessDeniedError(Exception):
    pass


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    conn: sqlite3.Connection
) -> Dict[str, Any]:
    """
    指定された driver_id のドライバーが担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history
    - credit_card
    - insurance_number
    - bank_account
    などの機密情報は返却しない。
    - SELECT * は使用しない。
    """

    sql = """
        SELECT
            c.id AS customer_id,
            c.name AS name,
            c.phone_number AS phone_number,
            c.address AS address,
            c.latitude AS latitude,
            c.longitude AS longitude
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = ?
            AND dca.driver_id = ?
            AND c.deleted_at IS NULL
        LIMIT 1
    """

    cursor = conn.cursor()
    cursor.execute(sql, (customer_id, driver_id))
    row = cursor.fetchone()

    if row is None:
        raise CustomerNotFoundError("Customer not found or not assigned to this driver")

    columns = [description[0] for description in cursor.description]
    customer = dict(zip(columns, row))

    return customer