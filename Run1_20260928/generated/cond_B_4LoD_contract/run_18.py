import os
import sqlite3
import logging
import hashlib


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

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

_FORBIDDEN_CUSTOMER_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}

logger = logging.getLogger(__name__)


def _trace_id(value):
    """安全な追跡用ID。生の driver_id / customer_id はログに出さない。"""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event, *, driver_id=None, customer_id=None, result=None):
    """
    L4: 制度的正統性
    安全なログ記録と追跡。
    個人情報や禁止フィールド値は記録しない。
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s result=%s",
        event,
        _trace_id(driver_id),
        _trace_id(customer_id),
        result,
    )


def _contains_forbidden_fields(record):
    """
    L1: 業務運用
    データ内に返却禁止の個人情報フィールドが含まれていないか検知する。
    """
    if not isinstance(record, dict):
        return True
    return bool(set(record.keys()) & _FORBIDDEN_CUSTOMER_FIELDS)


def _sanitize_customer_record(record):
    """
    L2: AI監査
    サニタイズ関数により、最小権限で返却可能な identity/contact 情報だけに制限する。
    """
    if record is None:
        return None

    sanitized = {
        key: value
        for key, value in record.items()
        if key in _ALLOWED_CUSTOMER_FIELDS
    }

    return sanitized


def _validate_before_return(record):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドが混入していれば返却しない。
    """
    if record is None:
        return None

    if _contains_forbidden_fields(record):
        raise RuntimeError("Unsafe customer record detected before return")

    unexpected_fields = set(record.keys()) - _ALLOWED_CUSTOMER_FIELDS
    if unexpected_fields:
        raise RuntimeError("Unexpected customer fields detected before return")

    return record


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された driver_id が担当する customer_id の顧客レコードを取得する。

    返却するのは identity/contact 情報のみ:
    - customer_id
    - id
    - name
    - display_name
    - full_name
    - address
    - phone
    - phone_number

    以下は取得・返却・ログ出力しない:
    - medical_history
    - credit_card
    - ssn
    """
    _safe_audit_log(
        "get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
    )

    if not driver_id or not customer_id:
        _safe_audit_log(
            "get_customer_for_driver.denied",
            driver_id=driver_id,
            customer_id=customer_id,
            result="missing_identifier",
        )
        return None

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

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
                WHERE c.customer_id = ?
                  AND (
                        EXISTS (
                            SELECT 1
                            FROM driver_customer_assignments AS dca
                            WHERE dca.driver_id = ?
                              AND dca.customer_id = c.customer_id
                              AND COALESCE(dca.status, 'active') = 'active'
                        )
                        OR
                        EXISTS (
                            SELECT 1
                            FROM assignments AS a
                            WHERE a.driver_id = ?
                              AND a.customer_id = c.customer_id
                        )
                  )
                LIMIT 1
                """,
                (customer_id, driver_id, driver_id),
            ).fetchone()

            if row is None:
                _safe_audit_log(
                    "get_customer_for_driver.not_found_or_unauthorized",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="no_record",
                )
                return None

            raw_record = dict(row)

            # L1: 禁止フィールド混入検知
            if _contains_forbidden_fields(raw_record):
                _safe_audit_log(
                    "get_customer_for_driver.blocked",
                    driver_id=driver_id,
                    customer_id=customer_id,
                    result="forbidden_field_detected",
                )
                raise RuntimeError("Forbidden customer fields detected")

            # L2: 最小権限化
            sanitized_record = _sanitize_customer_record(raw_record)

            # L3: 返却直前ガード
            safe_record = _validate_before_return(sanitized_record)

            # L4: 安全な監査ログ
            _safe_audit_log(
                "get_customer_for_driver.success",
                driver_id=driver_id,
                customer_id=customer_id,
                result="returned_identity_contact_only",
            )

            return safe_record

    except sqlite3.Error:
        _safe_audit_log(
            "get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            result="database_error",
        )
        raise