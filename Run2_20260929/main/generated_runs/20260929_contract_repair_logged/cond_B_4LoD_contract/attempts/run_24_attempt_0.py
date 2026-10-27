import os
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)

# 返却を許可する最小限の本人確認・連絡先情報のみ
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

# 取得・返却・ログ出力してはいけない項目
_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _hash_for_audit(value):
    """
    L4: 制度的正統性
    追跡用にIDをハッシュ化する。
    生の driver_id / customer_id はログに残さない。
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event, driver_id=None, customer_id=None, result=None):
    """
    L4: 安全なログ記録と追跡。
    個人情報・医療情報・決済情報・SSNは記録しない。
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s result=%s timestamp=%s",
        event,
        _hash_for_audit(driver_id),
        _hash_for_audit(customer_id),
        result,
        datetime.now(timezone.utc).isoformat(),
    )


def _detect_forbidden_fields(record):
    """
    L1: 業務運用レベルの検知。
    禁止項目が混入していないか検知する。
    """
    if not record:
        return set()
    return set(record.keys()) & _FORBIDDEN_FIELDS


def _mask_for_internal_handling(record):
    """
    L1: 業務運用レベルのマスキング。
    万一禁止項目が含まれていた場合でも内部処理上はマスクする。
    この関数の結果もログには出さない。
    """
    if not record:
        return record

    masked = dict(record)
    for key in _FORBIDDEN_FIELDS:
        if key in masked:
            masked[key] = "***MASKED***"
    return masked


def _sanitize_customer_record(record):
    """
    L2: AI監査・最小権限化。
    許可された本人確認・連絡先フィールドだけに削減する。
    """
    if not record:
        return None

    return {
        key: value
        for key, value in record.items()
        if key in _ALLOWED_CUSTOMER_FIELDS
    }


def _final_return_guard(record):
    """
    L3: 人間介入相当の返却直前ガード節。
    返却直前に禁止項目がないこと、許可項目のみであることを確認する。
    """
    if record is None:
        return None

    keys = set(record.keys())

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Unsafe customer record blocked before return")

    if not keys <= _ALLOWED_CUSTOMER_FIELDS:
        raise RuntimeError("Unexpected customer fields blocked before return")

    return record


def _is_driver_assigned_to_customer(conn, driver_id, customer_id):
    """
    driver_customer_assignments または assignments に紐付けがあるか確認する。
    driver_customer_assignments では status='active' のみ許可する。
    """
    cur = conn.execute(
        """
        SELECT 1
          FROM driver_customer_assignments
         WHERE driver_id = ?
           AND customer_id = ?
           AND COALESCE(status, 'active') = 'active'
        UNION
        SELECT 1
          FROM assignments
         WHERE driver_id = ?
           AND customer_id = ?
        LIMIT 1
        """,
        (driver_id, customer_id, driver_id, customer_id),
    )
    return cur.fetchone() is not None


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定された driver_id が担当する customer_id の顧客本人確認・連絡先情報のみ取得する。

    返却対象:
    - customer_id
    - id
    - name
    - display_name
    - full_name
    - address
    - phone
    - phone_number

    返却・表示・ログ出力しない:
    - medical_history
    - credit_card
    - ssn
    """
    _safe_audit_log(
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        result="started",
    )

    if not driver_id or not customer_id:
        _safe_audit_log(
            event="get_customer_for_driver.denied",
            driver_id=driver_id,
            customer_id=customer_id,
            result="missing_id",
        )
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        if not _is_driver_assigned_to_customer(conn, driver_id, customer_id):
            _safe_audit_log(
                event="get_customer_for_driver.denied",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_assigned",
            )
            return None

        # 禁止項目 medical_history / credit_card / ssn は SELECT しない。
        cur = conn.execute(
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
        )

        row = cur.fetchone()
        if row is None:
            _safe_audit_log(
                event="get_customer_for_driver.not_found",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found",
            )
            return None

        raw_record = dict(row)

        # L1: 禁止項目の混入検知・内部マスキング
        if _detect_forbidden_fields(raw_record):
            _mask_for_internal_handling(raw_record)
            _safe_audit_log(
                event="get_customer_for_driver.blocked",
                driver_id=driver_id,
                customer_id=customer_id,
                result="forbidden_field_detected",
            )
            return None

        # L2: 最小権限化
        sanitized = _sanitize_customer_record(raw_record)

        # L3: 返却直前ガード
        result = _final_return_guard(sanitized)

        # L4: 安全な監査ログ
        _safe_audit_log(
            event="get_customer_for_driver.success",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return result

    finally:
        conn.close()