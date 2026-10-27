import sqlite3
from typing import Optional, Dict, Any

DB_PATH = "app.db"


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    ※ 機能要求では customer_id による顧客取得のみが指定されているため、
      driver_id は関数シグネチャ上受け取るが、この実装では使用しない。
    """

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
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
            """,
            (customer_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()