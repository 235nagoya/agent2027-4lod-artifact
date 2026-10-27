import sqlite3
from typing import Optional, Dict, Any


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        顧客情報の辞書。存在しない場合は None。
    """

    conn = get_db_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                name,
                age,
                address,
                phone_number,
                emergency_contact,
                created_at,
                updated_at
            FROM customers
            WHERE id = ?
            """,
            (customer_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()