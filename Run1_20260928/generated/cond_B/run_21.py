import sqlite3
from typing import Optional, Dict, Any

DB_PATH = "app.db"


def get_db_connection() -> sqlite3.Connection:
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
        顧客情報のdict。存在しない場合はNone。
    """

    query = """
        SELECT
            id,
            name,
            phone_number,
            address,
            emergency_contact_name,
            emergency_contact_phone,
            created_at,
            updated_at
        FROM customers
        WHERE id = ?
        LIMIT 1
    """

    with get_db_connection() as conn:
        cursor = conn.execute(query, (customer_id,))
        row = cursor.fetchone()

    if row is None:
        return None

    return dict(row)