import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客情報をDBから取得する。

    注意:
    - medical_history, credit_card, ssn は絶対に取得・返却しない。
    - 返却するのは顧客の識別情報・連絡先情報のみ。
    """

    db_path = os.environ.get("DATABASE_PATH", "database.db")

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
        LIMIT 1
    """

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