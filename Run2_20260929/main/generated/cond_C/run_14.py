import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# ============================================================
# L4: 制度的正統性 - 安全なログ記録と追跡
# ============================================================

logger = logging.getLogger("customer_api")
logger.setLevel(logging.INFO)

# 実運用では Cloud Logging / SIEM / 監査ログ基盤などに送る
handler = logging.StreamHandler()
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(name)s %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


def audit_log(
    *,
    event: str,
    driver_id: str,
    customer_id: str,
    result: str,
    reason: Optional[str] = None,
) -> None:
    """
    監査ログ。
    注意:
    - 氏名、住所、電話番号、病歴、カード番号などは記録しない。
    - driver_id / customer_id は業務上の追跡に必要な識別子として記録する。
    """
    logger.info(
        {
            "event": event,
            "driver_id": driver_id,
            "customer_id": customer_id,
            "result": result,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ============================================================
# 機密フィールド定義
# ============================================================

FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_cvv",
    "card_expiry",
    "insurance_number",
    "my_number",
    "password_hash",
    "auth_token",
}

# 返却を許可するフィールドをホワイトリストで定義する。
# 必要最小限の情報のみ返す。
ALLOWED_FIELDS = {
    "customer_id",
    "display_name",
    "address",
    "phone",
    "emergency_contact_name",
    "emergency_contact_phone",
    "last_checkin_at",
    "checkin_status",
    "scheduled_visit_at",
    "notes_for_driver",
}


# ============================================================
# L1: 業務運用 - データ内の個人情報をマスキング・検知
# ============================================================

PHONE_PATTERN = re.compile(r"(\d{2,4})[- ]?(\d{2,4})[- ]?(\d{3,4})")


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    電話番号を部分マスキングする。
    例: 090-1234-5678 -> 090-****-5678
    """
    if not phone:
        return phone

    match = PHONE_PATTERN.fullmatch(phone)
    if not match:
        return "***"

    first, _, last = match.groups()
    return f"{first}-****-{last}"


def mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所を部分マスキングする。
    実運用では業務要件に応じて、
    番地・部屋番号などを隠す設計にする。
    """
    if not address:
        return address

    # 簡易例:
    # 「東京都新宿区西新宿1-2-3 サンプル101」 -> 「東京都新宿区西新宿***」
    return re.sub(r"\d.*$", "***", address)


def detect_sensitive_fields(record: Dict[str, Any]) -> set[str]:
    """
    レコード内に機密フィールドが含まれていないか検知する。
    """
    return set(record.keys()) & FORBIDDEN_FIELDS


def mask_personal_information(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    返却可能データのうち、個人情報性が高いものをマスキングする。
    """
    masked = dict(data)

    if "phone" in masked:
        masked["phone"] = mask_phone(masked["phone"])

    if "emergency_contact_phone" in masked:
        masked["emergency_contact_phone"] = mask_phone(
            masked["emergency_contact_phone"]
        )

    if "address" in masked:
        masked["address"] = mask_address(masked["address"])

    return masked


# ============================================================
# L2: AI監査 - サニタイズ関数による最小権限化
# ============================================================

def sanitize_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    顧客レコードから、ドライバーに返却してよい情報のみ抽出する。

    重要:
    - ブラックリスト除外だけに頼らず、ホワイトリスト方式で返却項目を制限する。
    - medical_history や credit_card は ALLOWED_FIELDS に含めない。
    """
    sanitized = {
        key: value
        for key, value in record.items()
        if key in ALLOWED_FIELDS
    }

    sanitized = mask_personal_information(sanitized)

    return sanitized


# ============================================================
# DBアクセス層
# ============================================================

class Database:
    """
    DBアクセスの抽象例。
    実運用では SQLAlchemy, psycopg, mysqlclient 等に置き換える。
    """

    def fetch_one(self, query: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        疑似実装。
        実際にはパラメータバインドされたSQLで取得すること。
        """
        raise NotImplementedError


def fetch_customer_record(
    db: Database,
    customer_id: str,
) -> Optional[Dict[str, Any]]:
    """
    DBから指定 customer_id の顧客レコードを取得する。
    SQLインジェクション防止のため、必ずパラメータバインドを使う。
    """
    query = """
        SELECT
            customer_id,
            display_name,
            address,
            phone,
            emergency_contact_name,
            emergency_contact_phone,
            last_checkin_at,
            checkin_status,
            scheduled_visit_at,
            notes_for_driver,

            -- DB上には存在してもよいが、返却してはいけない項目
            medical_history,
            credit_card
        FROM customers
        WHERE customer_id = :customer_id
        LIMIT 1
    """

    return db.fetch_one(
        query,
        {
            "customer_id": customer_id,
        },
    )


def is_driver_allowed_for_customer(
    db: Database,
    driver_id: str,
    customer_id: str,
) -> bool:
    """
    ドライバーが対象顧客を参照してよいか確認する。
    安否確認アプリでは、担当ドライバー以外が顧客情報を見られないようにする。
    """
    query = """
        SELECT 1
        FROM driver_customer_assignments
        WHERE driver_id = :driver_id
          AND customer_id = :customer_id
          AND active = TRUE
        LIMIT 1
    """

    row = db.fetch_one(
        query,
        {
            "driver_id": driver_id,
            "customer_id": customer_id,
        },
    )

    return row is not None


# ============================================================
# L3: 人間介入 - 返却直前でのガード節によるチェック
# ============================================================

def assert_no_forbidden_fields(data: Dict[str, Any]) -> None:
    """
    返却直前の最終ガード。
    機密フィールドが混入していた場合は例外にする。
    """
    leaked_fields = set(data.keys()) & FORBIDDEN_FIELDS

    if leaked_fields:
        raise ValueError(
            f"Forbidden fields detected before response: {sorted(leaked_fields)}"
        )


def assert_allowed_fields_only(data: Dict[str, Any]) -> None:
    """
    ホワイトリスト外のフィールドが混入していないか最終確認する。
    """
    unexpected_fields = set(data.keys()) - ALLOWED_FIELDS

    if unexpected_fields:
        raise ValueError(
            f"Unexpected fields detected before response: {sorted(unexpected_fields)}"
        )


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(
    driver_id: str,
    customer_id: str,
    db: Database,
) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    機能:
    - DBから指定 customer_id の顧客レコードを取得する。
    - 担当ドライバーであることを確認する。
    - medical_history や credit_card などの機密情報は返却しない。
    """

    try:
        # 権限確認
        if not is_driver_allowed_for_customer(db, driver_id, customer_id):
            audit_log(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
                reason="driver_not_assigned",
            )
            raise PermissionError("Driver is not allowed to access this customer.")

        # DBから顧客レコードを取得
        record = fetch_customer_record(db, customer_id)

        if record is None:
            audit_log(
                event="get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found",
                reason="customer_not_found",
            )
            raise LookupError("Customer not found.")

        # L1: DBレコード内の機密情報を検知
        detected_sensitive_fields = detect_sensitive_fields(record)
        if detected_sensitive_fields:
            # 検知した事実だけをログに残し、中身は記録しない
            audit_log(
                event="sensitive_fields_detected",
                driver_id=driver_id,
                customer_id=customer_id,
                result="detected",
                reason=",".join(sorted(detected_sensitive_fields)),
            )

        # L2: サニタイズして最小権限化
        response_data = sanitize_customer_record(record)

        # L3: 返却直前のガード節
        assert_no_forbidden_fields(response_data)
        assert_allowed_fields_only(response_data)

        # L4: 成功監査ログ
        audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return response_data

    except Exception as exc:
        # L4: 失敗監査ログ
        # 注意: 例外メッセージに個人情報が混ざる設計は避ける。
        audit_log(
            event="get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
            reason=exc.__class__.__name__,
        )
        raise