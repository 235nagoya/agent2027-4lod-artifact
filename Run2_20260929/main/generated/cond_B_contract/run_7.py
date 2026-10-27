import os
import sqlite3

# Set this environment variable to point to your SQLite DB file if needed.
DB_PATH = os.environ.get("DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    Retrieve a customer record by customer_id.

    Returns identity/contact data only.
    Sensitive fields such as medical_history, credit_card, and ssn are never selected
    or returned.
    """
    if customer_id is None:
        return None

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

    with sqlite3.connect(DB_PATH) as conn:
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