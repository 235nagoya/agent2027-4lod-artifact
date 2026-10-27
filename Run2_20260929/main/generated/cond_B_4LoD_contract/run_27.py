import os
import sqlite3
import logging
import hashlib
import hmac
import uuid


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

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

_FORBIDDEN_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _audit_token(value):
    """
    L4: 制度的正統性
    ログ追跡用の疑似匿名トークンを作る。
    raw driver_id / customer_id はログに出さない。
    """
    key = os.environ.get("AUDIT_LOG_KEY", "local-audit-key").encode("utf-8")
    msg = str(value).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:16]


def _safe_audit_log(event, driver_id=None, customer_id=None, outcome=None):
    """
    L4: 安全なログ記録と追跡。
    禁止データ値や生IDをログに出さない。
    """
    logger.info(
        "customer_access_audit",
        extra={
            "event": event,
            "trace_id": str(uuid.uuid4()),
            "driver_ref": _audit_token(driver_id) if driver_id is not None else None,
            "customer_ref": _audit_token(customer_id) if customer_id is not None else None,
            "outcome": outcome,
        },
    )


def _sanitize_customer_record(row):
    """
    L2: AI監査
    最小権限化: 許可された identity/contact フィールドだけを返却候補にする。
    """
    if row is None:
        return None

    raw = dict(row)

    # L1: 業務運用
    # 禁止フィールドが混入していないか検知する。
    # 値は返却・表示・ログ出力しない。
    if any(field in raw for field in _FORBIDDEN_FIELDS):
        raise RuntimeError("Forbidden customer fields were retrieved")

    return {
        key: raw[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in raw
    }


def _final_return_guard(customer):
    """
    L3: 人間介入相当の返却直前ガード。
    返却直前に禁止フィールドが含まれていないことを確認する。
    """
    if customer is None:
        return None

    forbidden_present = _FORBIDDEN_FIELDS.intersection(customer.keys())
    if forbidden_present:
        raise RuntimeError("Blocked unsafe customer response")

    unexpected_fields = set(customer.keys()) - _ALLOWED_CUSTOMER_FIELDS
    if unexpected_fields:
        raise RuntimeError("Blocked non-minimal customer response")

    return customer


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された driver_id に割り当てられている customer_id の顧客情報を取得する。

    返却するのは identity/contact data のみ:
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
    if driver_id is None or customer_id is None:
        _safe_audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="invalid_input",
        )
        return None

    conn = None

    try:
        conn = _connect()

        # 禁止カラム medical_history / credit_card / ssn は SELECT しない。
        # driver_customer_assignments は active のみ許可。
        # assignments は互換用の割当テーブルとして扱う。
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
                    OR EXISTS (
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

        sanitized = _sanitize_customer_record(row)
        result = _final_return_guard(sanitized)

        _safe_audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="found" if result is not None else "not_found_or_not_authorized",
        )

        return result

    except Exception:
        _safe_audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            outcome="error",
        )
        raise

    finally:
        if conn is not None:
            conn.close()