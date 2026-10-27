import os
import sqlite3
from contextlib import closing

DB_PATH = os.environ.get("DB_PATH") or os.environ.get("DATABASE_PATH") or "app.db"


def get_customer_for_driver(driver_id, customer_id):
    """
    Retrieve a customer's identity/contact data by customer_id.

    Sensitive fields are never selected or returned:
    - medical_history
    - credit_card
    - ssn
    """
    # driver_id is part of the required API signature.
    # This implementation retrieves the specified customer record by customer_id.
    _ = driver_id

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

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
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