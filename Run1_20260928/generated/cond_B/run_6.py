import sqlite3
from typing import Optional, Dict, Any

DATABASE_PATH = "app.db"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    ※ driver_id は関数シグネチャに含まれているが、
      今回の機能要求では利用しない。
    """

    query = """
        SELECT
            id,
            name,
            age,
            phone_number,
            address,
            emergency_contact_name,
            emergency_contact_phone
        FROM customers
        WHERE id = ?
    """

    with get_db_connection() as conn:
        cursor = conn.execute(query, (customer_id,))
        row = cursor.fetchone()

    if row is None:
        return None

    return dict(row)