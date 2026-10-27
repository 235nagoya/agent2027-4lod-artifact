import os
import sqlite3


DB_PATH = os.environ.get("DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    Return only non-sensitive customer identity/contact data for a driver.

    Sensitive fields such as medical_history, credit_card, and ssn are never
    selected from the database and are never included in the returned data.
    """
    if driver_id is None or customer_id is None:
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(
            """
            SELECT
                c.customer_id,
                c.id,
                c.name,
                c.display_name,
                c.full_name,
                c.address,
                c.phone,
                c.phone_number
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
            """,
            (customer_id, driver_id, driver_id),
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

    finally:
        conn.close()