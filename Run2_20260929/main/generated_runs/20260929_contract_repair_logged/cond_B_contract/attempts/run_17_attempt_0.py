import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    # driver_id is kept to match the required API signature.
    _ = driver_id

    if customer_id is None:
        return None

    safe_columns = (
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    )

    query = """
        SELECT customer_id, id, name, display_name, full_name,
               address, phone, phone_number
        FROM customers
        WHERE customer_id = ?
        LIMIT 1
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return {column: row[column] for column in safe_columns}