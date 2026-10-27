import sqlite3

DB_PATH = "app.db"


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        assignment = conn.execute(
            """
            SELECT 1
            FROM driver_customer_assignments
            WHERE driver_id = ?
              AND customer_id = ?
              AND status = 'active'

            UNION

            SELECT 1
            FROM assignments
            WHERE driver_id = ?
              AND customer_id = ?

            LIMIT 1
            """,
            (driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            return None

        row = conn.execute(
            """
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
            """,
            (customer_id,),
        ).fetchone()

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