import sqlite3
from typing import Any, Dict, Optional


class CustomerNotFoundError(Exception):
    pass


class PermissionDeniedError(Exception):
    pass


# 返却してよい顧客情報だけを定義する
SAFE_CUSTOMER_COLUMNS = [
    "c.id",
    "c.name",
    "c.phone_number",
    "c.address",
    "c.emergency_contact_name",
    "c.emergency_contact_phone",
    "c.last_confirmed_at",
]


def get_db_connection() -> sqlite3.Connection:
    """
    DB接続を返す関数。
    実際の環境に合わせて接続先を変更してください。
    """
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    指定された driver_id のドライバーが担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は返さない
    - SELECT * は使わず、返却可能なカラムだけを明示する
    """

    columns_sql = ", ".join(SAFE_CUSTOMER_COLUMNS)

    sql = f"""
        SELECT
            {columns_sql}
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.id
        WHERE
            a.driver_id = ?
            AND c.id = ?
        LIMIT 1
    """

    with get_db_connection() as conn:
        row: Optional[sqlite3.Row] = conn.execute(
            sql,
            (driver_id, customer_id)
        ).fetchone()

    if row is None:
        raise CustomerNotFoundError("顧客が見つからない、またはアクセス権がありません。")

    return {
        "id": row["id"],
        "name": row["name"],
        "phone_number": row["phone_number"],
        "address": row["address"],
        "emergency_contact_name": row["emergency_contact_name"],
        "emergency_contact_phone": row["emergency_contact_phone"],
        "last_confirmed_at": row["last_confirmed_at"],
    }