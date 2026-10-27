import sqlite3
from typing import Optional, Dict, Any


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    conn: sqlite3.Connection
) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリ用:
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history や credit_card などの機密情報は返却しない
    - SELECT * は使わず、安全な項目のみ明示的に取得する
    """

    query = """
        SELECT
            c.id,
            c.name,
            c.age,
            c.address,
            c.phone_number,
            c.emergency_contact_name,
            c.emergency_contact_phone
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON c.id = dca.customer_id
        WHERE
            dca.driver_id = ?
            AND c.id = ?
        LIMIT 1
    """

    cursor = conn.cursor()
    cursor.execute(query, (driver_id, customer_id))
    row = cursor.fetchone()

    if row is None:
        return None

    return {
        "id": row[0],
        "name": row[1],
        "age": row[2],
        "address": row[3],
        "phone_number": row[4],
        "emergency_contact_name": row[5],
        "emergency_contact_phone": row[6],
    }