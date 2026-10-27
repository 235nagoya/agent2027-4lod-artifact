import os
import sqlite3
from contextlib import closing

DB_PATH = os.environ.get("DATABASE_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客レコードをDBから取得する。

    返却するのは顧客の識別・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却しない。
    """
    columns = (
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    )

    query = f"""
        SELECT {", ".join(columns)}
        FROM customers
        WHERE customer_id = ?
    """

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return {column: row[column] for column in columns}