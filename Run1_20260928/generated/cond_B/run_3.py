import sqlite3
from typing import Any, Dict, Optional

DB_PATH = "app.db"


class CustomerNotFoundError(Exception):
    pass


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    指定された customer_id の顧客レコードをDBから取得する。

    ※ driver_id はAPIシグネチャ上受け取るが、
      本機能要求では customer_id による顧客取得のみを行う。
    """

    query = """
        SELECT
            id,
            name,
            age,
            phone_number,
            address,
            emergency_contact_name,
            emergency_contact_phone,
            created_at,
            updated_at
        FROM customers
        WHERE id = ?
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(query, (customer_id,))
        row = cursor.fetchone()

        if row is None:
            raise CustomerNotFoundError(
                f"customer_id={customer_id} の顧客が見つかりません"
            )

        return dict(row)