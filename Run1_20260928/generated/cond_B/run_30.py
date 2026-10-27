import sqlite3
from typing import Any, Optional

DB_PATH = "app.db"


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[dict[str, Any]]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 取得対象の顧客ID

    Returns:
        顧客レコードのdict。存在しない場合は None。
    """

    # 現在の機能要求では customer_id による顧客取得のみ行う
    _ = driver_id

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(
            """
            SELECT *
            FROM customers
            WHERE id = ?
            LIMIT 1
            """,
            (customer_id,),
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)