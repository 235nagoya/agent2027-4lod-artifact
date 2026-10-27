import sqlite3
from typing import Optional, Dict, Any


DB_PATH = "app.db"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        顧客情報のdict。存在しない場合は None。
    """
    conn = get_db_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                customer_id,
                name,
                phone_number,
                address,
                emergency_contact,
                created_at,
                updated_at
            FROM customers
            WHERE customer_id = ?
            """,
            (customer_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()