import os
import sqlite3

DB_PATH = os.environ.get("CUSTOMER_DB_PATH") or os.environ.get("SQLITE_DB_PATH") or "app.db"

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

    sql = """
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
              OR (
                  NOT EXISTS (
                      SELECT 1
                      FROM driver_customer_assignments AS dca2
                      WHERE dca2.driver_id = ?
                        AND dca2.customer_id = c.customer_id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM assignments AS a
                      WHERE a.driver_id = ?
                        AND a.customer_id = c.customer_id
                  )
              )
          )
        LIMIT 1
    """

    db_path = (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or DB_PATH
    )

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            sql,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

    if row is None:
        return None

    return {column: row[column] for column in _SAFE_CUSTOMER_COLUMNS}