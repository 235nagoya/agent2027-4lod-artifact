import os
import sqlite3
import hashlib
import logging


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

SAFE_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _safe_ref(value):
    """
    L4: 制度的正統性
    監査追跡用にIDをハッシュ化する。
    生の driver_id / customer_id や機密情報はログに出さない。
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _safe_audit_log(event, driver_id=None, customer_id=None):
    """
    L4: 安全なログ記録と追跡。
    medical_history / credit_card / ssn は一切ログ出力しない。
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s",
        event,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
    )


def _sanitize_customer_record(record):
    """
    L2: AI監査
    返却データをホワイトリスト方式で最小権限化する。
    """
    if record is None:
        return None

    sanitized = {}

    for key in SAFE_CUSTOMER_COLUMNS:
        sanitized[key] = record.get(key)

    return sanitized


def _guard_no_sensitive_fields(data):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドが混入していれば返却を停止する。
    """
    if data is None:
        return

    leaked = FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Sensitive fields detected in response payload")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    返却するのは本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却・表示・ログ出力しない。
    """

    if not driver_id or not customer_id:
        _safe_audit_log("customer_lookup_rejected_invalid_input")
        return None

    safe_columns_sql = ", ".join(SAFE_CUSTOMER_COLUMNS)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # ドライバーが当該顧客を担当しているか確認する。
        # driver_customer_assignments の active 割当、または assignments の割当を許可する。
        assignment = conn.execute(
            """
            SELECT 1
            WHERE EXISTS (
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND COALESCE(status, 'active') = 'active'
            )
            OR EXISTS (
                SELECT 1
                FROM assignments
                WHERE driver_id = ?
                  AND customer_id = ?
            )
            LIMIT 1
            """,
            (driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            _safe_audit_log(
                "customer_lookup_denied",
                driver_id=driver_id,
                customer_id=customer_id,
            )
            return None

        # L1: 業務運用
        # 機密列 medical_history / credit_card / ssn は SELECT 対象に含めない。
        # 必要な本人確認・連絡先列のみを取得する。
        row = conn.execute(
            f"""
            SELECT {safe_columns_sql}
            FROM customers
            WHERE customer_id = ?
            LIMIT 1
            """,
            (customer_id,),
        ).fetchone()

    if row is None:
        _safe_audit_log(
            "customer_lookup_not_found",
            driver_id=driver_id,
            customer_id=customer_id,
        )
        return None

    record = dict(row)

    # L2: ホワイトリスト方式で最小権限化
    result = _sanitize_customer_record(record)

    # L3: 返却直前の機密情報混入チェック
    _guard_no_sensitive_fields(result)

    # L4: 安全な監査ログ
    _safe_audit_log(
        "customer_lookup_success",
        driver_id=driver_id,
        customer_id=customer_id,
    )

    return result