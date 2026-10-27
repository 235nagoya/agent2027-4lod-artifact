import hashlib
import hmac
import logging
import os
import sqlite3
from datetime import datetime, timezone


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")

_ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _audit_token(value):
    """安全な追跡用トークン。元のIDやPIIはログに出さない。"""
    key = os.environ.get("AUDIT_HASH_KEY", "local-audit-key").encode("utf-8")
    raw = "" if value is None else str(value)
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _safe_audit(event, *, driver_id=None, customer_id=None, result=None):
    """L4: 制度的正統性 - 安全なログ記録と追跡。"""
    _AUDIT_LOGGER.info(
        "event=%s driver_ref=%s customer_ref=%s result=%s at=%s",
        event,
        _audit_token(driver_id),
        _audit_token(customer_id),
        result,
        datetime.now(timezone.utc).isoformat(),
    )


def _sanitize_customer_record(record):
    """
    L2: AI監査 - サニタイズ関数による最小権限化。
    許可された本人確認・連絡先情報のみを返却候補にする。
    """
    sanitized = {
        key: record[key]
        for key in _ALLOWED_RETURN_FIELDS
        if key in record.keys()
    }
    return sanitized


def _detect_forbidden_fields(record):
    """
    L1: 業務運用 - データ内の機微情報フィールドを検知。
    値は一切ログに出さない。
    """
    present = set(record.keys())
    return bool(present & _FORBIDDEN_FIELDS)


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された driver_id に割り当てられた customer_id の顧客情報を取得する。

    返却するのは本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """
    if driver_id is None or customer_id is None:
        _safe_audit(
            "customer_access_denied",
            driver_id=driver_id,
            customer_id=customer_id,
            result="invalid_request",
        )
        return None

    sql = """
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
            row = conn.execute(sql, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            _safe_audit(
                "customer_access_denied",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_unassigned",
            )
            return None

        # L1: 禁止フィールドが混入していないことを検知
        if _detect_forbidden_fields(row):
            _safe_audit(
                "customer_access_blocked",
                driver_id=driver_id,
                customer_id=customer_id,
                result="forbidden_field_detected",
            )
            return None

        # L2: 最小権限化
        result = _sanitize_customer_record(row)

        # L3: 人間介入相当の返却直前ガード節
        if set(result.keys()) - _ALLOWED_RETURN_FIELDS:
            _safe_audit(
                "customer_access_blocked",
                driver_id=driver_id,
                customer_id=customer_id,
                result="unexpected_field_detected",
            )
            return None

        if any(field in result for field in _FORBIDDEN_FIELDS):
            _safe_audit(
                "customer_access_blocked",
                driver_id=driver_id,
                customer_id=customer_id,
                result="sensitive_field_detected",
            )
            return None

        _safe_audit(
            "customer_access_granted",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )
        return result

    except sqlite3.Error:
        _safe_audit(
            "customer_access_error",
            driver_id=driver_id,
            customer_id=customer_id,
            result="database_error",
        )
        raise