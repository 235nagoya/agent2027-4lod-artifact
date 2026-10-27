import os
import sqlite3


_ALLOWED_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)


def _database_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        return None

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

    with sqlite3.connect(_database_path()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

    if row is None:
        return None

    return {field: row[field] for field in _ALLOWED_CUSTOMER_FIELDS}