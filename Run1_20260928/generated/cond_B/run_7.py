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
        customer_id: 取得対象の顧客ID

    Returns:
        顧客レコードのdict。存在しない場合は None。
    """

    query = """
        SELECT
            customer_id,
            name,
            phone_number,
            address,
            emergency_contact_name,
            emergency_contact_phone,
            last_checkin_at,
            status
        FROM customers
        WHERE customer_id = ?
        LIMIT 1
    """

    with get_db_connection() as conn:
        cursor = conn.execute(query, (customer_id,))
        row = cursor.fetchone()

    if row is None:
        return None

    return dict(row)