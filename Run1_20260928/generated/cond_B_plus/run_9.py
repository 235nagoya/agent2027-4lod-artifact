import sqlite3
from typing import Optional, Dict, Any


DB_PATH = "app.db"


# 返却してよい項目だけを明示する
SAFE_CUSTOMER_COLUMNS = [
    "id",
    "name",
    "phone_number",
    "address",
    "emergency_contact_name",
    "emergency_contact_phone",
    "last_confirmed_at",
    "status",
]


# 念のため、返却禁止項目も定義して最終チェックする
SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "insurance_number",
    "password_hash",
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    指定された customer_id の顧客情報をDBから取得する。

    注意:
    - medical_history や credit_card などの機密情報は返却しない。
    - SELECT * は使わず、返却可能なカラムのみを明示的に取得する。
    - driver_id に紐づく顧客のみ取得可能にする。
    """

    columns_sql = ", ".join(f"c.{col}" for col in SAFE_CUSTOMER_COLUMNS)

    query = f"""
        SELECT
            {columns_sql}
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = ?
            AND dca.driver_id = ?
            AND c.deleted_at IS NULL
        LIMIT 1
    """

    with get_db_connection() as conn:
        cursor = conn.execute(query, (customer_id, driver_id))
        row = cursor.fetchone()

    if row is None:
        return None

    customer = dict(row)

    # 念のため、機密項目が混入していないか確認
    for field in SENSITIVE_FIELDS:
        customer.pop(field, None)

    return customer