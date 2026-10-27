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
        顧客レコードの辞書。存在しない場合は None。
    """

    # 現在の機能要求では customer_id のみで顧客を取得する
    _ = driver_id

    query = """
        SELECT *
        FROM customers
        WHERE customer_id = ?
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(query, (customer_id,))
        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)