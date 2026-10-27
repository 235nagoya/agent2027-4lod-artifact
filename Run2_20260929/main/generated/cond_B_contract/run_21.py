import os
import sqlite3


def _database_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def get_customer_for_driver(driver_id, customer_id):
    # Functional requirement: retrieve the specified customer record by customer_id.
    # Do not select or expose sensitive columns: medical_history, credit_card, ssn.
    del driver_id  # Not used by the stated functional requirement.

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
    """

    conn = sqlite3.connect(_database_path())
    try:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

        if row is None:
            return None

        return dict(row)
    finally:
        conn.close()