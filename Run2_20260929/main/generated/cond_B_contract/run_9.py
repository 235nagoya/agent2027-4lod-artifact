import os
import sqlite3

DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
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

    if not driver_id or not customer_id:
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        assigned = conn.execute(
            """
            SELECT 1
            FROM driver_customer_assignments
            WHERE driver_id = ?
              AND customer_id = ?
              AND COALESCE(status, 'active') = 'active'

            UNION

            SELECT 1
            FROM assignments
            WHERE driver_id = ?
              AND customer_id = ?

            LIMIT 1
            """,
            (driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assigned is None:
            return None

        row = conn.execute(
            f"""
            SELECT {", ".join(safe_columns)}
            FROM customers
            WHERE customer_id = ?
            """,
            (customer_id,),
        ).fetchone()

        if row is None:
            return None

        return {column: row[column] for column in safe_columns}