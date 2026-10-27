import os
import sqlite3

# Set this to your SQLite DB path, or define SQLITE_DB_PATH in the environment.
DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    Fetch a customer's identity/contact information by customer_id.

    Sensitive fields are never selected or returned:
    - medical_history
    - credit_card
    - ssn
    """
    _ = driver_id  # Not used for this functional requirement.

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