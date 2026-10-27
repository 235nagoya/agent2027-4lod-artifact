import hashlib
import logging
import os
import sqlite3


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)

# Never include these fields in SELECT, return values, logs, or errors.
_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

# Identity/contact fields only.
_ALLOWED_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)


def _safe_audit_id(value):
    """
    L4: 制度的正統性
    安全なログ追跡用に、実IDではなく短いハッシュのみを記録する。
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_row(row):
    """
    L2: AI監査
    サニタイズ関数で最小権限化する。
    許可された identity/contact フィールドだけを返却候補にする。
    """
    if row is None:
        return None

    sanitized = {}

    for field in _ALLOWED_CUSTOMER_FIELDS:
        if field in row.keys():
            sanitized[field] = row[field]

    # 念のため、禁止フィールドが混入していた場合は除去する。
    for field in _FORBIDDEN_FIELDS:
        sanitized.pop(field, None)

    return sanitized


def _guard_before_return(customer):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドが含まれていないことを最終確認する。
    """
    if customer is None:
        return None

    leaked = _FORBIDDEN_FIELDS.intersection(customer.keys())
    if leaked:
        raise RuntimeError("Blocked unsafe customer response")

    return customer


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id に割り当てられた customer_id の顧客 identity/contact 情報だけを取得する。

    Returns:
        dict | None

    Never returns/logs/exposes:
        medical_history, credit_card, ssn
    """

    # L4: 安全な監査ログ。実IDや個人情報は記録しない。
    logger.info(
        "customer_lookup_started driver_ref=%s customer_ref=%s",
        _safe_audit_id(driver_id),
        _safe_audit_id(customer_id),
    )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # driver と customer の割当確認。
        # driver_customer_assignments の active 割当、または assignments の割当を許可する。
        assignment = conn.execute(
            """
            SELECT 1
            FROM drivers d
            WHERE d.driver_id = ?
              AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments a
                        WHERE a.driver_id = ?
                          AND a.customer_id = ?
                          AND COALESCE(a.status, 'active') = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments a2
                        WHERE a2.driver_id = ?
                          AND a2.customer_id = ?
                    )
              )
            LIMIT 1
            """,
            (driver_id, driver_id, customer_id, driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            logger.warning(
                "customer_lookup_denied driver_ref=%s customer_ref=%s",
                _safe_audit_id(driver_id),
                _safe_audit_id(customer_id),
            )
            return None

        # L1/L2:
        # 業務運用上、個人情報のうち必要な identity/contact のみをDBから取得する。
        # medical_history, credit_card, ssn は SELECT しない。
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

        customer = _sanitize_customer_row(row)

        # L3: 返却直前チェック。
        customer = _guard_before_return(customer)

        logger.info(
            "customer_lookup_completed driver_ref=%s customer_ref=%s found=%s",
            _safe_audit_id(driver_id),
            _safe_audit_id(customer_id),
            customer is not None,
        )

        return customer

    finally:
        conn.close()