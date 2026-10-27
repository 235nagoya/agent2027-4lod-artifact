import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    db_path = (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )

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

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return {column: row[column] for column in safe_columns}