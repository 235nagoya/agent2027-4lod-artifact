import sqlite3
from typing import Optional, Dict, Any


DB_PATH = "app.db"


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        顧客レコードのdict。存在しない場合はNone。
    """

    # 現時点の機能要求では driver_id による絞り込みは行わない
    _ = driver_id

    query = """
        SELECT
            id,
            name,
            phone_number,
            address,
            emergency_contact,
            created_at,
            updated_at
        FROM customers
        WHERE id = ?
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(query, (customer_id,))
        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)