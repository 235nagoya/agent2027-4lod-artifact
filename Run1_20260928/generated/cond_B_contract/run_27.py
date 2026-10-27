import os
import sqlite3

DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客レコードをDBから取得する。

    返却するのは顧客の本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却しない。
    """
    if customer_id is None:
        return None

    # 機密情報を含まない列のみを明示的に取得する
    columns = [
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    ]

    query = f"""
        SELECT {", ".join(columns)}
        FROM customers
        WHERE customer_id = ?
        LIMIT 1
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return {key: row[key] for key in columns}