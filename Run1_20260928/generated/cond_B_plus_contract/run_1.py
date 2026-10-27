import os
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    db_path = os.environ.get("SQLITE_DB_PATH", "app.db")

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        # ドライバーが対象顧客を担当していることを確認
        assignment = conn.execute(
            """
            SELECT 1
            FROM driver_customer_assignments
            WHERE driver_id = ?
              AND customer_id = ?
              AND status = 'active'

            UNION

            SELECT 1
            FROM assignments
            WHERE driver_id = ?
              AND customer_id = ?

            LIMIT 1
            """,
            (driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            return None

        # 機密情報 medical_history, credit_card, ssn は取得しない
        row = conn.execute(
            """
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
            """,
            (customer_id,),
        ).fetchone()

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