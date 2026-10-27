import os
import sqlite3

DB_PATH = (
    os.environ.get("CUSTOMER_DB_PATH")
    or os.environ.get("DATABASE_PATH")
    or os.environ.get("DB_PATH")
)


def _get_db_path():
    if DB_PATH:
        return DB_PATH

    for candidate in ("app.db", "database.db", "customers.db"):
        if os.path.exists(candidate):
            return candidate

    return "app.db"


def get_customer_for_driver(driver_id, customer_id):
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

    with sqlite3.connect(_get_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return dict(row)