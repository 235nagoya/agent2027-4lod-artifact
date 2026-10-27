import sqlite3

DB_PATH = "app.db"


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客レコードをDBから取得する。

    注意:
    - medical_history, credit_card, ssn は取得・返却しない。
    - driver_id は関数シグネチャ上受け取るが、この機能要求では使用しない。
    """

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

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, (customer_id,))
        row = cur.fetchone()

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