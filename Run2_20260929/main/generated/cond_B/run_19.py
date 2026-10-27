import sqlite3
from typing import Optional, Dict, Any

DB_PATH = "app.db"


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客情報をDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        顧客レコードを辞書形式で返す。
        該当する顧客が存在しない場合は None を返す。
    """

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                *
            FROM
                customers
            WHERE
                customer_id = ?
            """,
            (customer_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()