from datetime import datetime
from typing import Any, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


# 例: PostgreSQL
# 実際の接続文字列に置き換えてください
DATABASE_URL = "postgresql+psycopg2://user:password@localhost:5432/app_db"

engine: Engine = create_engine(DATABASE_URL)


# 返却を許可するカラムのみ定義する
SAFE_CUSTOMER_FIELDS = {
    "customer_id",
    "name",
    "phone_number",
    "address",
    "latitude",
    "longitude",
    "safety_status",
    "last_confirmed_at",
}

# 念のため、絶対に返してはいけないフィールドも定義しておく
SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "insurance_number",
}


def _json_safe(value: Any) -> Any:
    """
    JSONレスポンス向けに値を変換する補助関数。
    datetime は ISO 8601 文字列に変換する。
    """
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def get_customer_for_driver(driver_id: int, customer_id: int) -> Optional[dict[str, Any]]:
    """
    高齢者向け安否確認アプリで、ドライバーが担当する顧客情報を取得する。

    - 指定された customer_id の顧客レコードをDBから取得する
    - medical_history や credit_card などの機密情報は返却しない
    - driver_id に紐づく担当顧客のみ取得する

    Returns:
        dict: 顧客情報
        None: 顧客が存在しない、またはドライバーの担当外の場合
    """

    query = text("""
        SELECT
            c.id AS customer_id,
            c.name AS name,
            c.phone_number AS phone_number,
            c.address AS address,
            c.latitude AS latitude,
            c.longitude AS longitude,
            c.safety_status AS safety_status,
            c.last_confirmed_at AS last_confirmed_at
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

    result = {
        key: _json_safe(row[key])
        for key in SAFE_CUSTOMER_FIELDS
        if key in row
    }

    # 防御的チェック: 機密フィールドが混入していないことを確認
    if SENSITIVE_FIELDS.intersection(result.keys()):
        raise RuntimeError("Sensitive fields must not be included in response")

    return result