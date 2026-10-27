import os
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone

DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

logger = logging.getLogger("customer_access_audit")
logger.addHandler(logging.NullHandler())

_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}
_ALLOWED_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}


def _audit_token(value):
    """
    L4: 制度的正統性
    監査追跡用に、driver_id / customer_id を直接ログへ出さずハッシュ化する。
    """
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_audit_log(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録と追跡。
    個人情報や禁止情報をログに含めない。
    """
    logger.info(
        "event=%s driver_ref=%s customer_ref=%s outcome=%s at=%s",
        event,
        _audit_token(driver_id),
        _audit_token(customer_id),
        outcome,
        datetime.now(timezone.utc).isoformat(),
    )


def _sanitize_customer(row):
    """
    L2: AI監査
    allowlist方式で返却データを最小権限化する。
    medical_history / credit_card / ssn は構造上返さない。
    """
    if row is None:
        return None

    sanitized = {}

    for key in _ALLOWED_FIELDS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _detect_forbidden_exposure(data):
    """
    L1: 業務運用
    返却予定データ内に禁止フィールドが混入していないか検知する。
    """
    if not isinstance(data, dict):
        return True

    return bool(_FORBIDDEN_FIELDS.intersection(data.keys()))


def _final_return_guard(data):
    """
    L3: 人間介入相当の返却直前ガード節。
    許可された identity/contact data のみ返す。
    """
    if data is None:
        return None

    if not isinstance(data, dict):
        raise RuntimeError("Unsafe return type detected.")

    if _detect_forbidden_exposure(data):
        raise RuntimeError("Forbidden customer fields detected.")

    unexpected = set(data.keys()) - _ALLOWED_FIELDS
    if unexpected:
        raise RuntimeError("Unexpected customer fields detected.")

    return data


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Return:
        dict | None:
            許可された顧客の identity/contact data のみ。
            未割当・未存在・無効入力の場合は None。

    Never returns/logs/exposes:
        medical_history, credit_card, ssn
    """
    if not driver_id or not customer_id:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "invalid_input")
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
                FROM customers c
                WHERE c.customer_id = ?
                  AND (
                        EXISTS (
                            SELECT 1
                            FROM driver_customer_assignments dca
                            WHERE dca.driver_id = ?
                              AND dca.customer_id = c.customer_id
                              AND COALESCE(dca.status, 'active') = 'active'
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM assignments a
                            WHERE a.driver_id = ?
                              AND a.customer_id = c.customer_id
                        )
                  )
                LIMIT 1
                """,
                (customer_id, driver_id, driver_id),
            ).fetchone()

            sanitized = _sanitize_customer(row)
            guarded = _final_return_guard(sanitized)

            _safe_audit_log(
                "get_customer_for_driver",
                driver_id,
                customer_id,
                "success" if guarded is not None else "not_found_or_unauthorized",
            )

            return guarded

    except Exception:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "error")
        raise