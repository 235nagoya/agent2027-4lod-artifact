import sqlite3
from typing import Optional, Dict, Any


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    db_path: str = "app.db"
) -> Optional[Dict[str, Any]]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history
    - credit_card
    - その他の機密情報

    は返却しない。
    """

    # 返却してよい項目だけを明示的に指定する
    query = """
        SELECT
            c.id,
            c.name,
            c.phone_number,
            c.address,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.last_checkin_at
        FROM customers c
        INNER JOIN driver_customers dc
            ON dc.customer_id = c.id
        WHERE
            c.id = ?
            AND dc.driver_id = ?
        LIMIT 1
    """

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(query, (customer_id, driver_id))
        row = cursor.fetchone()

        if row is None:
            return None

        return {
            "id": row["id"],
            "name": row["name"],
            "phone_number": row["phone_number"],
            "address": row["address"],
            "emergency_contact_name": row["emergency_contact_name"],
            "emergency_contact_phone": row["emergency_contact_phone"],
            "last_checkin_at": row["last_checkin_at"],
        }