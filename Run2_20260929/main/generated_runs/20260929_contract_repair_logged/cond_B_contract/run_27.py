import os
import sqlite3

def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch a customer record by customer_id and return identity/contact fields only.
    Sensitive fields are never selected or returned.
    """
    db_path = os.environ.get("DATABASE_PATH", os.environ.get("DB_PATH", "app.db"))

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
        LIMIT 1
    """

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return {column: row[column] for column in allowed_columns}