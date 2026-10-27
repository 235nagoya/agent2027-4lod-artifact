import sqlite3
from typing import Any

DB_PATH = "app.db"


def get_customer_for_driver(driver_id: int, customer_id: int) -> dict[str, Any] | None:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        顧客レコードのdict。存在しない場合は None。
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(
            """
            SELECT *
            FROM customers
            WHERE customer_id = ?
            LIMIT 1
            """,
            (customer_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)