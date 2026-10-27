import os
import sqlite3

# 必要に応じて環境変数でDBファイルを指定:
#   CUSTOMER_DB_PATH=/path/to/app.sqlite
DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された customer_id の顧客情報を取得する。

    返すのは本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却しない。

    未存在、または driver_id に紐付かない customer_id の場合は None を返す。
    """
    if driver_id is None or customer_id is None:
        return None

    query = """
        SELECT
            c.customer_id,
            c.id,
            c.name,
            c.display_name,
            c.full_name,
            c.address,
            c.phone,
            c.phone_number
        FROM customers AS c
        WHERE c.customer_id = ?
          AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments AS dca
                    WHERE dca.driver_id = ?
                      AND dca.customer_id = c.customer_id
                      AND LOWER(COALESCE(dca.status, 'active')) = 'active'
                )
                OR (
                    NOT EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca2
                        WHERE dca2.driver_id = ?
                          AND dca2.customer_id = c.customer_id
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
                )
          )
        LIMIT 1
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            query,
            (customer_id, driver_id, driver_id, driver_id),
        ).fetchone()

    if row is None:
        return None

    return dict(row)