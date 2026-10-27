import os
import sqlite3
import logging
import hashlib


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_ALLOWED_RETURN_KEYS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_FORBIDDEN_KEYS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def _safe_audit_id(value):
    """Log追跡用の不可逆ID。生の個人情報・機密情報はログに出さない。"""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer(row):
    """
    L2: AI監査 / 最小権限化
    DBから取得した行を返却許可された identity/contact 項目だけに限定する。
    """
    if row is None:
        return None

    data = dict(row)

    sanitized = {
        key: data.get(key)
        for key in _ALLOWED_RETURN_KEYS
        if key in data
    }

    return sanitized


def _guard_no_sensitive_fields(data):
    """
    L3: 人間介入相当の返却直前ガード
    禁止フィールドが混入していないことを最終確認する。
    """
    if data is None:
        return None

    keys = set(data.keys())

    if keys & _FORBIDDEN_KEYS:
        raise RuntimeError("Sensitive fields detected in response payload.")

    if not keys <= _ALLOWED_RETURN_KEYS:
        raise RuntimeError("Unexpected fields detected in response payload.")

    return data


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定ドライバーに割り当てられた顧客の identity/contact 情報のみを返す。

    Never returns, prints, logs, or exposes:
    medical_history, credit_card, ssn
    """

    # L4: 制度的正統性 / 安全なログ記録と追跡
    # 生の driver_id/customer_id はログに出さず、不可逆ハッシュのみ記録する。
    audit_driver = _safe_audit_id(driver_id)
    audit_customer = _safe_audit_id(customer_id)
    _logger.info(
        "get_customer_for_driver requested driver_ref=%s customer_ref=%s",
        audit_driver,
        audit_customer,
    )

    if driver_id is None or customer_id is None:
        _logger.warning(
            "get_customer_for_driver rejected missing parameter driver_ref=%s customer_ref=%s",
            audit_driver,
            audit_customer,
        )
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # L1: 業務運用 / データ内の個人情報をマスキング・検知
        # SELECT * は使わず、業務上必要な identity/contact 項目だけを明示取得する。
        # medical_history, credit_card, ssn はSQL上も取得しない。
        row = conn.execute(
            """
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
            WHERE
                c.customer_id = ?
                AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca
                        WHERE
                            dca.driver_id = ?
                            AND dca.customer_id = c.customer_id
                            AND COALESCE(dca.status, 'active') = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE
                            a.driver_id = ?
                            AND a.customer_id = c.customer_id
                    )
                )
            LIMIT 1
            """,
            (customer_id, driver_id, driver_id),
        ).fetchone()

        sanitized = _sanitize_customer(row)
        guarded = _guard_no_sensitive_fields(sanitized)

        _logger.info(
            "get_customer_for_driver completed driver_ref=%s customer_ref=%s found=%s",
            audit_driver,
            audit_customer,
            guarded is not None,
        )

        return guarded

    finally:
        conn.close()