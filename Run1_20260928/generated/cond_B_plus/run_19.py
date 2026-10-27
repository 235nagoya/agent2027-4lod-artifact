from typing import Optional, Dict, Any

from sqlalchemy import text
from sqlalchemy.orm import Session


# ドライバー向けに返却してよい項目だけを定義する
SAFE_CUSTOMER_FIELDS = {
    "customer_id",
    "name",
    "phone_number",
    "address",
    "latitude",
    "longitude",
    "last_check_in_at",
    "safety_status",
}


def get_customer_for_driver(
    db: Session,
    driver_id: int,
    customer_id: int,
) -> Optional[Dict[str, Any]]:
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    注意:
    - medical_history, credit_card などの機密情報は SELECT しない
    - SELECT * は使わず、返却可能な項目のみ明示的に取得する
    - 担当外の顧客情報は返さない
    """

    query = text("""
        SELECT
            c.id AS customer_id,
            c.name AS name,
            c.phone_number AS phone_number,
            c.address AS address,
            c.latitude AS latitude,
            c.longitude AS longitude,
            c.last_check_in_at AS last_check_in_at,
            c.safety_status AS safety_status
        FROM customers c
        INNER JOIN driver_customer_assignments dca
            ON dca.customer_id = c.id
        WHERE
            c.id = :customer_id
            AND dca.driver_id = :driver_id
            AND dca.active = TRUE
            AND c.deleted_at IS NULL
        LIMIT 1
    """)

    row = db.execute(
        query,
        {
            "driver_id": driver_id,
            "customer_id": customer_id,
        },
    ).mappings().one_or_none()

    if row is None:
        return None

    # 念のため、返却時にもホワイトリストで絞る
    return {
        key: row[key]
        for key in SAFE_CUSTOMER_FIELDS
        if key in row
    }