import sqlite3
from typing import Optional, Dict, Any


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客情報をDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        顧客情報のdict。存在しない場合は None。
    """

    # driver_id は現時点の機能要求では利用しない
    _ = driver_id

    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
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
            """,
            (customer_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()