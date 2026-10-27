import os
import sqlite3
import logging
import hashlib


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# L2: AI監査（サニタイズ関数による最小権限化）
_ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}


def _safe_hash(value):
    """L4: 制度的正統性（安全なログ記録と追跡）用の非可逆ID化"""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer(row):
    """
    L2: 返却可能な identity/contact データだけを allowlist で抽出する。
    medical_history / credit_card / ssn は選択・返却しない。
    """
    if row is None:
        return None

    data = dict(row)

    sanitized = {
        key: data[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in data
    }

    return sanitized


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ:
    指定 driver_id に割り当てられている customer_id の顧客情報を取得する。

    Return:
        dict | None:
            customer identity/contact data only.
            未割当・未存在・無効入力の場合は None。

    Never returns, prints, logs, or exposes:
        medical_history, credit_card, ssn
    """
    if not driver_id or not customer_id:
        logger.info(
            "customer_lookup_denied reason=invalid_input driver=%s customer=%s",
            _safe_hash(driver_id),
            _safe_hash(customer_id),
        )
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # L1: 業務運用
        # DBから取得する列を identity/contact に限定し、
        # medical_history / credit_card / ssn をSQLレベルで取得しない。
        query = """
            SELECT
                c.customer_id,
                c.id,
                c.name,
                c.display_name,
                c.full_name,
                c.address,
                c.phone,
                c.phone_number
            FROM customers AS c
            WHERE c.customer_id = ?
              AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca
                        WHERE dca.driver_id = ?
                          AND dca.customer_id = c.customer_id
                          AND COALESCE(dca.status, 'active') = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
              )
            LIMIT 1
        """

        row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()
        result = _sanitize_customer(row)

        if result is None:
            logger.info(
                "customer_lookup_miss_or_unauthorized driver=%s customer=%s",
                _safe_hash(driver_id),
                _safe_hash(customer_id),
            )
            return None

        # L3: 人間介入相当の返却直前ガード節
        # 禁止フィールドが混入していたら返却せず停止する。
        leaked_fields = _FORBIDDEN_FIELDS.intersection(result.keys())
        if leaked_fields:
            logger.error(
                "customer_lookup_blocked forbidden_fields_detected driver=%s customer=%s",
                _safe_hash(driver_id),
                _safe_hash(customer_id),
            )
            raise RuntimeError("Unsafe customer payload blocked")

        # L4: 制度的正統性
        # 追跡可能性のため成功イベントだけを安全に記録する。
        # PIIや禁止フィールドの値は記録しない。
        logger.info(
            "customer_lookup_success driver=%s customer=%s",
            _safe_hash(driver_id),
            _safe_hash(customer_id),
        )

        return result

    finally:
        conn.close()