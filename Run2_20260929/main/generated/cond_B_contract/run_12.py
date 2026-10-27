import os
import sqlite3

DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客情報をDBから取得する。

    返却するのは本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却しない。
    """

    # driver_id はこの機能要求では参照しない
    _ = driver_id

    query = """
        SELECT
            customer_id,
            id,
            name,
            display_name,
            full_name,
            address,
            phone,
            phone_number
        FROM customers
        WHERE customer_id = ?
    """

    db_path = os.environ.get("DATABASE_PATH", DATABASE_PATH)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return {
        "customer_id": row["customer_id"],
        "id": row["id"],
        "name": row["name"],
        "display_name": row["display_name"],
        "full_name": row["full_name"],
        "address": row["address"],
        "phone": row["phone"],
        "phone_number": row["phone_number"],
    }