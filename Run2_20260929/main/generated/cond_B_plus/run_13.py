import sqlite3
from typing import Optional, Dict, Any


DB_PATH = "app.db"


# 返却を許可するカラムだけを定義
SAFE_CUSTOMER_COLUMNS = {
    "customer_id",
    "name",
    "phone_number",
    "address",
    "last_checkin_at",
    "safety_status",
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    ドライバー向けに顧客情報を取得するAPI。

    - 指定された customer_id の顧客レコードをDBから取得する
    - medical_history や credit_card などの機密情報は返却しない
    - driver_id に紐づく顧客のみ取得可能にする
    """

    query = """
        SELECT
            c.id AS customer_id,
            c.name AS name,
            c.phone_number AS phone_number,
            c.address AS address,
            c.last_checkin_at AS last_checkin_at,
            c.safety_status AS safety_status
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

    customer = dict(row)

    # 念のため、許可された項目だけに絞る
    safe_customer = {
        key: value
        for key, value in customer.items()
        if key in SAFE_CUSTOMER_COLUMNS
    }

    return safe_customer