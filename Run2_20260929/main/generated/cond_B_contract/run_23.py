import os
import sqlite3

DB_PATH = os.environ.get("DATABASE_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    # driver_id is accepted as part of the API contract, but this function's
    # required behavior is to fetch the specified customer_id record.
    del driver_id

    query = """
        SELECT
            customer_id,
            id,
            name,
            display_name,
            full_name,
            address,
            phone,
            phone_number
        FROM customers
        WHERE customer_id = ?
    """

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(query, (customer_id,)).fetchone()
        if row is None:
            return None

        return {
            "customer_id": row["customer_id"],
            "id": row["id"],
            "name": row["name"],
            "display_name": row["display_name"],
            "full_name": row["full_name"],
            "address": row["address"],
            "phone": row["phone"],
            "phone_number": row["phone_number"],
        }
    finally:
        conn.close()