import sqlite3
from typing import Optional, Dict, Any


DATABASE_PATH = "app.db"


# 返却してよい顧客情報だけを許可リスト化する
SAFE_CUSTOMER_COLUMNS = [
    "id",
    "name",
    "phone_number",
    "address",
    "emergency_contact_name",
    "emergency_contact_phone",
    "last_safety_check_at",
    "status",
]

# 念のため、機密項目は返却前にも除外する
SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "insurance_number",
    "password",
    "password_hash",
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(
    driver_id: int,
    customer_id: int
) -> Optional[Dict[str, Any]]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history や credit_card などの機密情報は返却しない。
    - SELECT * は使用せず、返却可能なカラムのみ明示的に取得する。
    - driver_id に紐づく顧客だけを取得対象にする。
    """

    columns_sql = ", ".join([f"c.{col} AS {col}" for col in SAFE_CUSTOMER_COLUMNS])

    query = f"""
        SELECT
            {columns_sql}
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

    # 防御的に機密項目を除外
    for field in SENSITIVE_FIELDS:
        customer.pop(field, None)

    return customer