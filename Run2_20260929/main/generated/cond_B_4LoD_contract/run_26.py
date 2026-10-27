import os
import re
import json
import hmac
import hashlib
import logging
import sqlite3
from datetime import datetime, timezone


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_SAFE_CUSTOMER_COLUMNS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_FORBIDDEN_COLUMNS = {
    "medical_history",
    "credit_card",
    "ssn",
}

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")
_AUDIT_LOGGER.addHandler(logging.NullHandler())


def _audit_hash(value):
    value = "" if value is None else str(value)
    key = os.environ.get("AUDIT_HASH_KEY", "local-audit-key").encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _mask_for_audit(value):
    if value is None:
        return None

    text = str(value)

    text = re.sub(
        r"\b\d{3}-\d{2}-\d{4}\b",
        "***-**-****",
        text,
    )
    text = re.sub(
        r"\b(?:\d[ -]*?){13,19}\b",
        "[CARD_MASKED]",
        text,
    )
    text = re.sub(
        r"\b0\d{1,4}-\d{1,4}-\d{3,4}\b",
        "[PHONE_MASKED]",
        text,
    )

    if len(text) <= 4:
        return "*" * len(text)

    return text[:2] + "*" * (len(text) - 4) + text[-2:]


def _sanitize_customer_record(row):
    """
    L2: AI監査 / 最小権限化
    DB行から返却可能な identity/contact 列だけをホワイトリストで抽出する。
    """
    if row is None:
        return None

    sanitized = {}

    for key in _SAFE_CUSTOMER_COLUMNS:
        if key in row.keys():
            sanitized[key] = row[key]

    return sanitized


def _guard_customer_response(record):
    """
    L3: 人間介入相当の返却直前ガード。
    禁止列が混入していないこと、返却列が許可列のみであることを確認する。
    """
    if record is None:
        return None

    keys = set(record.keys())

    if keys & _FORBIDDEN_COLUMNS:
        raise RuntimeError("unsafe customer response blocked")

    if not keys <= _SAFE_CUSTOMER_COLUMNS:
        raise RuntimeError("unexpected customer response field blocked")

    return record


def _safe_audit_log(event, driver_id, customer_id, outcome):
    """
    L4: 制度的正統性 / 安全なログ記録と追跡。
    生の個人情報や禁止情報は記録せず、追跡用にHMAC化した識別子のみを残す。
    """
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "driver_ref": _audit_hash(driver_id),
        "customer_ref": _audit_hash(customer_id),
        "outcome": _mask_for_audit(outcome),
    }

    _AUDIT_LOGGER.info(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用 顧客情報取得API。

    Returns:
        dict | None:
            driver_id に割り当てられた customer_id の顧客 identity/contact 情報。
            未割当・未存在・無効入力の場合は None。

    Never returns:
        medical_history, credit_card, ssn
    """
    if driver_id is None or customer_id is None:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        return None

    driver_id = str(driver_id)
    customer_id = str(customer_id)

    if not driver_id or not customer_id:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "invalid_request")
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
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

        customer = _sanitize_customer_record(row)
        customer = _guard_customer_response(customer)

        _safe_audit_log(
            "get_customer_for_driver",
            driver_id,
            customer_id,
            "success" if customer is not None else "not_found_or_not_assigned",
        )

        return customer

    except Exception:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "error")
        raise

    finally:
        conn.close()