import os
import sqlite3

DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(
            """
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
            """,
            (customer_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()