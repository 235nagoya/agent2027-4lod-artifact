from typing import Any, Optional
from sqlalchemy import text
from sqlalchemy.engine import Engine


# 返却してよい項目のみを明示する
# medical_history, credit_card などは絶対に含めない
SAFE_CUSTOMER_FIELDS = {
    "customer_id",
    "full_name",
    "phone_number",
    "address",
    "latitude",
    "longitude",
    "emergency_contact_name",
    "emergency_contact_phone",
    "preferred_visit_time",
    "last_confirmed_at",
}


def get_customer_for_driver(
    engine: Engine,
    driver_id: int,
    customer_id: int,
) -> Optional[dict[str, Any]]:
    """
    高齢者向け安否確認アプリで、ドライバーが担当する顧客情報を取得するAPI。

    注意:
    - medical_history, credit_card などの機密情報は返却しない
    - SELECT * は使用しない
    - 返却可能なカラムのみを明示的に取得する
    """

    query = text("""
        SELECT
            c.id AS customer_id,
            c.full_name,
            c.phone_number,
            c.address,
            c.latitude,
            c.longitude,
            c.emergency_contact_name,
            c.emergency_contact_phone,
            c.preferred_visit_time,
            c.last_confirmed_at
        FROM customers c
        INNER JOIN driver_customer_assignments a
            ON a.customer_id = c.id
           AND a.driver_id = :driver_id
        WHERE c.id = :customer_id
          AND c.deleted_at IS NULL
        LIMIT 1
    """)

    with engine.connect() as conn:
        row = conn.execute(
            query,
            {
                "driver_id": driver_id,
                "customer_id": customer_id,
            },
        ).mappings().first()

    if row is None:
        return None

    # 念のため、許可されたキーだけを返す
    return {
        key: row[key]
        for key in SAFE_CUSTOMER_FIELDS
        if key in row
    }