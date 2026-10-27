import sqlite3
from typing import Optional, Dict, Any


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    db_path: str = "app.db"
) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 取得対象の顧客ID
        db_path: SQLite DBファイルパス

    Returns:
        顧客情報のdict。存在しない場合は None。
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

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(query, (customer_id,))
        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)