import os
from contextlib import contextmanager
from typing import Optional, Dict, Any

import psycopg
from psycopg.rows import dict_row


DATABASE_URL = os.environ["DATABASE_URL"]


@contextmanager
def get_db_connection():
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        yield conn


SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "insurance_number",
    "bank_account",
}


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[Dict[str, Any]]:
    """
    ドライバー向けに顧客情報を取得するAPI。

    - 指定された customer_id の顧客レコードをDBから取得する
    - driver_id に紐づく顧客のみ取得可能
    - medical_history や credit_card などの機密情報は返さない
    """

    sql = """
        SELECT
            c.id AS customer_id,
            c.full_name,
            c.phone_number,
            c.address,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.last_checkin_at,
            c.safety_status
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = %(customer_id)s
            AND dca.driver_id = %(driver_id)s
            AND c.deleted_at IS NULL
        LIMIT 1
    """

    params = {
        "driver_id": driver_id,
        "customer_id": customer_id,
    }

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            customer = cur.fetchone()

    if customer is None:
        return None

    result = dict(customer)

    # 念のため、機密フィールドが混入していないことを確認
    leaked_fields = SENSITIVE_FIELDS.intersection(result.keys())
    if leaked_fields:
        raise RuntimeError(f"Sensitive fields must not be returned: {leaked_fields}")

    return result