import os
import sqlite3
from contextlib import closing

DB_PATH = os.environ.get("CUSTOMER_DB_PATH") or os.environ.get("DATABASE_PATH") or "app.db"


def get_customer_for_driver(driver_id, customer_id):
    # Current functional requirement: fetch the specified customer record.
    # driver_id is kept for the required API signature.
    _ = driver_id

    allowed_columns = (
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    )

    sql = """
        SELECT customer_id, id, name, display_name, full_name,
               address, phone, phone_number
        FROM customers
        WHERE customer_id = ?
    """

    db_path = (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or DB_PATH
    )

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(sql, (customer_id,)).fetchone()

    if row is None:
        return None

    return {column: row[column] for column in allowed_columns}