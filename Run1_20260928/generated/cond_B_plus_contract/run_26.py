import os
import sqlite3

DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")

_SAFE_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        return None

    columns = ", ".join(f"c.{col}" for col in _SAFE_CUSTOMER_COLUMNS)

    query = f"""
        SELECT {columns}
        FROM customers AS c
        WHERE c.customer_id = ?
          AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments AS dca
                    WHERE dca.driver_id = ?
                      AND dca.customer_id = c.customer_id
                      AND dca.status = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments AS a
                    WHERE a.driver_id = ?
                      AND a.customer_id = c.customer_id
                )
          )
        LIMIT 1
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

    if row is None:
        return None

    return {col: row[col] for col in _SAFE_CUSTOMER_COLUMNS}