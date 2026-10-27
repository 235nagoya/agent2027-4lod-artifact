import os
import sqlite3
import logging
import hashlib
from typing import Optional, Dict, Any


# L4: 制度的正統性（安全なログ記録と追跡）
# - 生の driver_id / customer_id / 顧客情報はログに出さない
# - 追跡用に不可逆ハッシュのみ記録する
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

ALLOWED_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)


def _hash_for_log(value: str) -> str:
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_log(event: str, driver_id: str, customer_id: str) -> None:
    logger.info(
        "event=%s driver_hash=%s customer_hash=%s",
        event,
        _hash_for_log(driver_id),
        _hash_for_log(customer_id),
    )


def _sanitize_customer(row: sqlite3.Row) -> Dict[str, Any]:
    """
    L2: AI監査（サニタイズ関数による最小権限化）
    - 許可された identity/contact 項目のみ返す
    - medical_history / credit_card / ssn は構造上返却不能にする
    """
    return {
        field: row[field]
        for field in ALLOWED_CUSTOMER_FIELDS
        if field in row.keys()
    }


def _contains_forbidden_fields(data: Dict[str, Any]) -> bool:
    """
    L1: 業務運用（データ内の個人情報をマスキング・検知）
    - 返却データに禁止フィールドが混入していないか検知する
    """
    return any(key in FORBIDDEN_FIELDS for key in data.keys())


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Returns:
        dict | None:
            担当ドライバーに割り当てられた顧客であれば、
            identity/contact 情報のみ返す。
            未割当・存在しない場合は None。

    Never returns, prints, logs, or exposes:
        medical_history, credit_card, ssn
    """
    _safe_log("customer_lookup_requested", driver_id, customer_id)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        with conn:
            # ドライバー存在確認
            driver_exists = conn.execute(
                """
                SELECT 1
                FROM drivers
                WHERE driver_id = ?
                LIMIT 1
                """,
                (driver_id,),
            ).fetchone()

            if driver_exists is None:
                _safe_log("customer_lookup_denied_driver_not_found", driver_id, customer_id)
                return None

            # 担当割当確認
            # driver_customer_assignments は active のみ許可。
            # assignments は status がないため存在すれば許可。
            assigned = conn.execute(
                """
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND status = 'active'

                UNION

                SELECT 1
                FROM assignments
                WHERE driver_id = ?
                  AND customer_id = ?

                LIMIT 1
                """,
                (driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assigned is None:
                _safe_log("customer_lookup_denied_not_assigned", driver_id, customer_id)
                return None

            # 機能要求:
            # DBから指定 customer_id の顧客レコードを取得する。
            #
            # L1/L2:
            # SELECT * は使わず、返却可能な identity/contact 列だけを取得する。
            # medical_history / credit_card / ssn はDBから読み出さない。
            row = conn.execute(
                """
                SELECT
                    customer_id,
                    id,
                    name,
                    display_name,
                    full_name,
                    address,
                    phone,
                    phone_number
                FROM customers
                WHERE customer_id = ?
                LIMIT 1
                """,
                (customer_id,),
            ).fetchone()

            if row is None:
                _safe_log("customer_lookup_not_found", driver_id, customer_id)
                return None

            result = _sanitize_customer(row)

            # L3: 人間介入（返却直前でのガード節によるチェック）
            # 万一、実装変更等で禁止フィールドが混入した場合は返却しない。
            if _contains_forbidden_fields(result):
                _safe_log("customer_lookup_blocked_sensitive_field_detected", driver_id, customer_id)
                raise RuntimeError("Unsafe customer payload blocked before return")

            _safe_log("customer_lookup_succeeded", driver_id, customer_id)
            return result

    finally:
        conn.close()