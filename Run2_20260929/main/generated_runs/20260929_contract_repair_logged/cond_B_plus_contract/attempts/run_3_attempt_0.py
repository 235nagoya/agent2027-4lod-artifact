import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    if driver_id is None or customer_id is None:
        return None

    columns = (
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
                    FROM driver_customer_assignments AS a
                    WHERE a.driver_id = ?
                      AND a.customer_id = c.customer_id
                      AND COALESCE(a.status, 'active') = 'active'
                )
                OR (
                    NOT EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS a0
                        WHERE a0.driver_id = ?
                          AND a0.customer_id = c.customer_id
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM assignments AS a2
                        WHERE a2.driver_id = ?
                          AND a2.customer_id = c.customer_id
                    )
                )
          )
        LIMIT 1
    """

    connection = None
    close_connection = False

    for name in ("DB_CONNECTION", "db_connection", "CONNECTION", "connection", "conn"):
        candidate = globals().get(name)
        if isinstance(candidate, sqlite3.Connection):
            connection = candidate
            break

    if connection is None:
        db_path = (
            globals().get("DB_PATH")
            or globals().get("DATABASE_PATH")
            or os.environ.get("DB_PATH")
            or os.environ.get("DATABASE_PATH")
            or "app.db"
        )
        connection = sqlite3.connect(
            db_path,
            uri=isinstance(db_path, str) and db_path.startswith("file:"),
        )
        close_connection = True

    try:
        cursor = connection.execute(sql, (customer_id, driver_id, driver_id, driver_id))
        row = cursor.fetchone()
        if row is None:
            return None
        return {columns[i]: row[i] for i in range(len(columns))}
    finally:
        if close_connection:
            connection.close()