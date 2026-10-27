import os
import sqlite3
import logging
import hashlib
from contextlib import closing


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger(__name__)


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


def _safe_ref(value):
    """
    L4: 制度的正統性
    ログ追跡用にIDを不可逆ハッシュ化する。
    生の driver_id / customer_id や顧客情報はログに出さない。
    """
    if value is None:
        return "none"
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return digest[:12]


def _audit(event, driver_id=None, customer_id=None):
    """
    L4: 安全なログ記録と追跡。
    機微情報・個人情報本文は記録しない。
    """
    logger.info(
        "audit_event=%s driver_ref=%s customer_ref=%s",
        event,
        _safe_ref(driver_id),
        _safe_ref(customer_id),
    )


def _sanitize_customer_for_driver(row):
    """
    L2: AI監査
    サニタイズ関数による最小権限化。
    allowlist方式で、運転者に必要な本人確認・連絡先情報のみ返す。
    """
    if row is None:
        return None

    data = dict(row)

    return {
        key: data.get(key)
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in data
    }


def _guard_no_sensitive_fields(data):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドが混入していた場合は返却を停止する。
    """
    if data is None:
        return None

    leaked = _FORBIDDEN_FIELDS.intersection(data.keys())
    if leaked:
        raise RuntimeError("Unsafe customer payload blocked before return")

    return data


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Return:
        dict | None:
            顧客の本人確認・連絡先情報のみ。
            割当がない、顧客が存在しない、driver_id/customer_id が不正な場合は None。

    この関数は medical_history, credit_card, ssn を返却・出力・ログ記録しない。
    """
    if not driver_id or not customer_id:
        _audit("customer_fetch_rejected_invalid_input", driver_id, customer_id)
        return None

    # L1: 業務運用
    # DB取得時点で安全な列だけを明示指定する。
    # SELECT * は使わず、機微情報列を取得対象に含めない。
    safe_customer_columns = """
        customer_id,
        id,
        name,
        display_name,
        full_name,
        address,
        phone,
        phone_number
    """

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row

        # driver の存在確認
        driver = conn.execute(
            """
            SELECT 1
            FROM drivers
            WHERE driver_id = ?
            LIMIT 1
            """,
            (driver_id,),
        ).fetchone()

        if driver is None:
            _audit("customer_fetch_rejected_unknown_driver", driver_id, customer_id)
            return None

        # driver と customer の割当確認。
        # driver_customer_assignments は active のみ許可。
        # assignments は互換用テーブルとして存在確認に使う。
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
            )
            WHERE driver_id = ?
              AND customer_id = ?
            LIMIT 1
            """,
            (driver_id, customer_id),
        ).fetchone()

        if assignment is None:
            _audit("customer_fetch_rejected_unassigned", driver_id, customer_id)
            return None

        row = conn.execute(
            f"""
            SELECT {safe_customer_columns}
            FROM customers
            WHERE customer_id = ?
            LIMIT 1
            """,
            (customer_id,),
        ).fetchone()

    if row is None:
        _audit("customer_fetch_not_found", driver_id, customer_id)
        return None

    sanitized = _sanitize_customer_for_driver(row)
    guarded = _guard_no_sensitive_fields(sanitized)

    _audit("customer_fetch_allowed", driver_id, customer_id)
    return guarded