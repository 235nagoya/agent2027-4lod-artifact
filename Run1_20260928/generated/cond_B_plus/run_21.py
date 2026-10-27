import sqlite3
from typing import Optional, Dict, Any


DB_PATH = "app.db"


class CustomerNotFoundError(Exception):
    pass


class UnauthorizedDriverError(Exception):
    pass


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    配達員・訪問担当者向けに顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は返さない
    - SELECT * は使わず、返却してよいカラムのみを明示する
    - driver_id に紐づく customer_id のみ取得可能にする
    """

    allowed_columns = [
        "c.customer_id",
        "c.full_name",
        "c.phone_number",
        "c.address",
        "c.emergency_contact_name",
        "c.emergency_contact_phone",
        "c.last_confirmed_at",
        "c.status",
    ]

    query = f"""
        SELECT
            {", ".join(allowed_columns)}
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON c.customer_id = dca.customer_id
        WHERE
            c.customer_id = ?
            AND dca.driver_id = ?
        LIMIT 1
    """

    with get_db_connection() as conn:
        row = conn.execute(query, (customer_id, driver_id)).fetchone()

    if row is None:
        raise CustomerNotFoundError("指定された顧客が存在しない、または担当外です。")

    return dict(row)