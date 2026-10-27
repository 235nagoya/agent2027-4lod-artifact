import os
import sqlite3

# 必要に応じて環境変数 DATABASE_PATH でDBファイルを指定してください。
DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客情報をDBから取得する。

    返却するのは本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却しない。
    """
    _ = driver_id  # 現行の機能要求では使用しない

    if customer_id is None:
        return None

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

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, (customer_id,)).fetchone()

    if row is None:
        return None

    return dict(row)