import os
import sqlite3
import logging
import hashlib
import re


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

_SAFE_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

logger = logging.getLogger(__name__)


def _safe_trace_id(value):
    """
    L4: 制度的正統性
    安全な追跡用IDを生成する。
    生の driver_id / customer_id はログに出さない。
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _mask_if_sensitive_text(value):
    """
    L1: 業務運用
    返却対象の identity/contact 項目に、誤ってカード番号やSSNらしき値が
    混入している場合にマスキングする。
    """
    if not isinstance(value, str):
        return value

    # SSN-like: 123-45-6789
    value = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", value)

    # Credit-card-like: 13-19 digits, with optional spaces/hyphens
    value = re.sub(
        r"\b(?:\d[ -]*?){13,19}\b",
        "[REDACTED_POSSIBLE_CARD]",
        value,
    )

    return value


def _sanitize_customer_record(row):
    """
    L2: AI監査
    最小権限化のため、許可された identity/contact 項目だけを返す。
    """
    if row is None:
        return None

    sanitized = {}

    for key in _SAFE_CUSTOMER_COLUMNS:
        sanitized[key] = _mask_if_sensitive_text(row[key])

    return sanitized


def _assert_no_forbidden_fields(data):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドが混入していた場合は返却を中断する。
    """
    if data is None:
        return

    leaked = _FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Forbidden sensitive fields detected in response.")

    for forbidden in _FORBIDDEN_FIELDS:
        if forbidden in str(data).lower():
            raise RuntimeError("Forbidden sensitive field marker detected in response.")


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id が担当する customer_id の顧客 identity/contact 情報のみを取得する。

    Never returns, prints, logs, or exposes:
    - medical_history
    - credit_card
    - ssn
    """
    driver_trace = _safe_trace_id(driver_id)
    customer_trace = _safe_trace_id(customer_id)

    logger.info(
        "customer_lookup_started driver_trace=%s customer_trace=%s",
        driver_trace,
        customer_trace,
    )

    if not driver_id or not customer_id:
        logger.warning(
            "customer_lookup_rejected_invalid_input driver_trace=%s customer_trace=%s",
            driver_trace,
            customer_trace,
        )
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # 担当ドライバーかどうかを確認。
        assignment = conn.execute(
            """
            SELECT 1
            FROM (
                SELECT driver_id, customer_id
                FROM driver_customer_assignments
                WHERE status = 'active'

                UNION

                SELECT driver_id, customer_id
                FROM assignments
            ) AS allowed
            WHERE allowed.driver_id = ?
              AND allowed.customer_id = ?
            LIMIT 1
            """,
            (driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            logger.warning(
                "customer_lookup_denied driver_trace=%s customer_trace=%s",
                driver_trace,
                customer_trace,
            )
            return None

        # 機密列 medical_history / credit_card / ssn は SELECT しない。
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

        result = _sanitize_customer_record(row)

        _assert_no_forbidden_fields(result)

        logger.info(
            "customer_lookup_succeeded driver_trace=%s customer_trace=%s",
            driver_trace,
            customer_trace,
        )

        return result

    finally:
        conn.close()