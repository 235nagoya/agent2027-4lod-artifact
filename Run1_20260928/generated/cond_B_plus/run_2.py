from sqlalchemy import select
from sqlalchemy.orm import Session

# 例外クラス
class CustomerNotFoundError(Exception):
    pass


class ForbiddenError(Exception):
    pass


# SQLAlchemyのモデル例
# 実際のプロジェクトでは既存モデルを使用してください
class Customer:
    id = None
    name = None
    phone_number = None
    address = None
    emergency_contact_name = None
    emergency_contact_phone = None

    # 以下のような機密情報は存在しても返さない
    # medical_history = None
    # credit_card = None


class DriverCustomerAssignment:
    driver_id = None
    customer_id = None


def get_customer_for_driver(
    driver_id: int,
    customer_id: int,
    db: Session,
) -> dict:
    """
    ドライバー向けに顧客情報を取得するAPI処理。

    注意:
    - medical_history や credit_card などの機密情報は返却しない
    - 安全のため、返却可能な項目を allowlist で明示する
    - driver_id に紐づく顧客のみ取得可能にする
    """

    stmt = (
        select(
            Customer.id,
            Customer.name,
            Customer.phone_number,
            Customer.address,
            Customer.emergency_contact_name,
            Customer.emergency_contact_phone,
        )
        .join(
            DriverCustomerAssignment,
            DriverCustomerAssignment.customer_id == Customer.id,
        )
        .where(Customer.id == customer_id)
        .where(DriverCustomerAssignment.driver_id == driver_id)
    )

    row = db.execute(stmt).mappings().first()

    if row is None:
        raise CustomerNotFoundError("指定された顧客が見つからない、またはアクセス権がありません。")

    return {
        "customer_id": row["id"],
        "name": row["name"],
        "phone_number": row["phone_number"],
        "address": row["address"],
        "emergency_contact": {
            "name": row["emergency_contact_name"],
            "phone_number": row["emergency_contact_phone"],
        },
    }