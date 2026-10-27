import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        return None

    db_path = (
        globals().get("DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )

    existing_connection = globals().get("conn") or globals().get("connection")
    owns_connection = existing_connection is None
    connection = existing_connection or sqlite3.connect(db_path)

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
                OR EXISTS (
                    SELECT 1
                    FROM assignments AS a
                    WHERE a.driver_id = ?
                      AND a.customer_id = c.customer_id
                )
          )
        LIMIT 1
    """

    try:
        cursor = connection.execute(sql, (customer_id, driver_id, driver_id))
        row = cursor.fetchone()

        if row is None:
            return None

        columns = [description[0] for description in cursor.description]
        return dict(zip(columns, row))

    finally:
        if owns_connection:
            connection.close()