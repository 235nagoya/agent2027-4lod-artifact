import os
import sqlite3
import logging
import hashlib


DB_PATH = (
    os.environ.get("ELDERCARE_DB_PATH")
    or os.environ.get("CUSTOMER_DB_PATH")
    or os.environ.get("DB_PATH")
    or "app.db"
)

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

_SENSITIVE_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_logger = logging.getLogger(__name__)


def _safe_trace_id(value):
    """L4: ログ追跡用。実IDは記録しない。"""
    if value is None:
        return "none"
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _sanitize_customer(row_dict):
    """
    L2: AI監査/最小権限化。
    allowlist方式で、返却可能な本人確認・連絡先情報だけを残す。
    """
    return {
        key: row_dict[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in row_dict
    }


def _contains_sensitive_field(data):
    """L1: データ内の機密項目混入を検知する。"""
    if not isinstance(data, dict):
        return False
    return any(key in _SENSITIVE_FIELDS for key in data.keys())


def get_customer_for_driver(driver_id, customer_id):
    """
    指定ドライバーに割り当てられた顧客の本人確認・連絡先情報のみを返す。
    未割当、存在しない、または安全確認に失敗した場合は None を返す。
    """

    trace_driver = _safe_trace_id(driver_id)
    trace_customer = _safe_trace_id(customer_id)

    _logger.info(
        "customer_lookup_started driver_ref=%s customer_ref=%s",
        trace_driver,
        trace_customer,
    )

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

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            _logger.info(
                "customer_lookup_not_found_or_unassigned driver_ref=%s customer_ref=%s",
                trace_driver,
                trace_customer,
            )
            return None

        raw_customer = dict(row)

        # L1: 取得データに機密項目が混入していないか検知
        if _contains_sensitive_field(raw_customer):
            _logger.error(
                "customer_lookup_blocked_raw_sensitive_fields driver_ref=%s customer_ref=%s",
                trace_driver,
                trace_customer,
            )
            return None

        # L2: allowlistで最小権限化
        sanitized = _sanitize_customer(raw_customer)

        # L3: 返却直前の人間介入相当ガード節
        if _contains_sensitive_field(sanitized):
            _logger.error(
                "customer_lookup_blocked_sanitized_sensitive_fields driver_ref=%s customer_ref=%s",
                trace_driver,
                trace_customer,
            )
            return None

        disallowed_keys = set(sanitized.keys()) - _ALLOWED_CUSTOMER_FIELDS
        if disallowed_keys:
            _logger.error(
                "customer_lookup_blocked_disallowed_fields driver_ref=%s customer_ref=%s",
                trace_driver,
                trace_customer,
            )
            return None

        # L4: 安全な監査ログ。個人情報・機密情報は記録しない。
        _logger.info(
            "customer_lookup_succeeded driver_ref=%s customer_ref=%s",
            trace_driver,
            trace_customer,
        )

        return sanitized

    except sqlite3.Error:
        _logger.error(
            "customer_lookup_database_error driver_ref=%s customer_ref=%s",
            trace_driver,
            trace_customer,
        )
        return None