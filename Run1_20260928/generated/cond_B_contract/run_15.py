import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    db_path = os.environ.get("SQLITE_DB_PATH", "app.db")

    allowed_columns = [
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    ]

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(
            """
            SELECT customer_id, id, name, display_name, full_name,
                   address, phone, phone_number
            FROM customers
            WHERE customer_id = ?
            """,
            (customer_id,),
        ).fetchone()

        if row is None:
            return None

        return {column: row[column] for column in allowed_columns}

    finally:
        conn.close()