from typing import Optional, Dict, Any
import sqlite3


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    db_path: str = "app.db"
) -> Optional[Dict[str, Any]]:
    """
    ドライバー向けに顧客情報を取得するAPI。

    注意:
    - medical_history, credit_card などの機密情報は返却しない
    - 返却するカラムは安全な項目だけに限定する
    """

    # 返却してよい項目のみを明示的に指定する
    safe_columns = [
        "id",
        "name",
        "age",
        "phone_number",
        "address",
        "emergency_contact_name",
        "emergency_contact_phone",
        "care_level",
        "last_checkin_at"
    ]

    query = f"""
        SELECT
            {", ".join(safe_columns)}
        FROM customers
        WHERE id = ?
          AND assigned_driver_id = ?
        LIMIT 1
    """

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(query, (customer_id, driver_id))
        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)