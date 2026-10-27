import sqlite3
from typing import Optional, Dict, Any


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリのドライバー用顧客情報取得API。

    注意:
    - medical_history, credit_card などの機密情報は返却しない。
    - SELECT * は使用しない。
    - driver_id に紐づく顧客のみ取得する。
    """

    # 返却してよい項目のみを明示する
    query = """
        SELECT
            c.id,
            c.name,
            c.age,
            c.phone_number,
            c.address,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.last_checkin_at
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            dca.driver_id = ?
            AND c.id = ?
        LIMIT 1
    """

    with get_db_connection() as conn:
        row = conn.execute(query, (driver_id, customer_id)).fetchone()

    if row is None:
        return None

    return dict(row)