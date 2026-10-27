import os
import sqlite3

DB_PATH = (
    os.environ.get("CUSTOMER_DB_PATH")
    or os.environ.get("SQLITE_DB_PATH")
    or os.environ.get("DB_PATH")
    or "app.db"
)

_SAFE_COLUMNS = (
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
                      AND dca.customer_id = ?
                      AND dca.status = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments AS a
                    WHERE a.driver_id = ?
                      AND a.customer_id = ?
                )
          )
        LIMIT 1
    """

    params = (
        customer_id,
        driver_id,
        customer_id,
        driver_id,
        customer_id,
    )

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(sql, params).fetchone()

    if row is None:
        return None

    return {column: row[index] for index, column in enumerate(_SAFE_COLUMNS)}