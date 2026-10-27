import os
import sqlite3

DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    safe_columns = [
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    ]

    query = """
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
                    AND COALESCE(dca.status, 'active') = 'active'
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
        row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

    if row is None:
        return None

    return dict(zip(safe_columns, row))