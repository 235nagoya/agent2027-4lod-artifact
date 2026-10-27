import sqlite3
from contextlib import closing

DATABASE_PATH = "app.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客レコードをDBから取得する。

    Args:
        driver_id: ドライバーID
        customer_id: 顧客ID

    Returns:
        dict | None: 顧客情報。存在しない場合は None。
    """

    query = """
        SELECT
            *
        FROM
            customers
        WHERE
            customer_id = ?
    """

    with closing(get_db_connection()) as conn:
        cursor = conn.execute(query, (customer_id,))
        row = cursor.fetchone()

    if row is None:
        return None

    return dict(row)