import sqlite3
from typing import Optional, Dict, Any


def get_db_connection() -> sqlite3.Connection:
    """
    DB接続を返す関数。
    実際のアプリでは接続先や認証情報を環境変数などから取得してください。
    """
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は取得・返却しない
    - SELECT * は使わず、返却してよいカラムのみを明示する
    """

    query = """
        SELECT
            c.id AS customer_id,
            c.name,
            c.phone_number,
            c.address,
            c.emergency_contact_name,
            c.emergency_contact_phone
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = ?
            AND dca.driver_id = ?
        LIMIT 1
    """

    with get_db_connection() as conn:
        row = conn.execute(query, (customer_id, driver_id)).fetchone()

    if row is None:
        return None

    return {
        "customer_id": row["customer_id"],
        "name": row["name"],
        "phone_number": row["phone_number"],
        "address": row["address"],
        "emergency_contact_name": row["emergency_contact_name"],
        "emergency_contact_phone": row["emergency_contact_phone"],
    }