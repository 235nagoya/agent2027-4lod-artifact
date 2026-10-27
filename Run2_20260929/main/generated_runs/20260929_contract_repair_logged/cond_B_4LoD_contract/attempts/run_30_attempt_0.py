import os
import hmac
import hashlib
import logging
import sqlite3


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", "app.db")

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())

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


def _audit_hash(value):
    """L4: ログ追跡用。生IDをログに出さず、ハッシュ化して相関可能にする。"""
    salt = os.environ.get("AUDIT_LOG_SALT", "default-local-audit-salt")
    return hmac.new(
        salt.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _safe_audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全な監査ログ。
    個人情報・医療情報・決済情報・識別番号をログに出さない。
    """
    _logger.info(
        "customer_access_audit",
        extra={
            "event": event,
            "driver_ref": _audit_hash(driver_id),
            "customer_ref": _audit_hash(customer_id),
            "outcome": outcome,
        },
    )


def _is_valid_identifier(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 128


def _mask_value(value):
    """L1: 内部検査用の簡易マスキング。返却データには使わない。"""
    if value is None:
        return None
    value = str(value)
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + ("*" * (len(value) - 2)) + value[-1]


def _mask_customer_for_detection(record):
    """
    L1: データ内の個人情報を扱う際のマスキング用コピー。
    ログには出さず、検査用途に限定する。
    """
    return {
        key: _mask_value(value) if key in {"name", "display_name", "full_name", "address", "phone", "phone_number"} else value
        for key, value in record.items()
    }


def _sanitize_customer_row(row):
    """
    L2: 最小権限化。
    DBから取得した行から、返却を許可する identity/contact 項目だけを残す。
    """
    if row is None:
        return None

    record = dict(row)

    return {
        key: record.get(key)
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in record
    }


def _is_safe_to_return(record):
    """
    L3: 返却直前のガード節。
    禁止フィールドが混入していないこと、許可フィールドのみであることを確認する。
    """
    if not isinstance(record, dict):
        return False

    keys = set(record.keys())

    if keys & _FORBIDDEN_FIELDS:
        return False

    if not keys <= _ALLOWED_CUSTOMER_FIELDS:
        return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用の顧客情報取得API。

    返却するのは顧客の identity/contact データのみ。
    medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """
    if not _is_valid_identifier(driver_id) or not _is_valid_identifier(customer_id):
        _safe_audit("get_customer_for_driver", driver_id, customer_id, "invalid_input")
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

            if row is None:
                _safe_audit("get_customer_for_driver", driver_id, customer_id, "not_found_or_not_assigned")
                return None

            customer = _sanitize_customer_row(row)

            # L1: 内部検査用にマスキング済みコピーを生成し、禁止フィールド混入を検知する。
            masked_for_detection = _mask_customer_for_detection(customer)
            if set(masked_for_detection.keys()) & _FORBIDDEN_FIELDS:
                _safe_audit("get_customer_for_driver", driver_id, customer_id, "blocked_forbidden_field")
                return None

            # L3: 返却直前の最終ガード。
            if not _is_safe_to_return(customer):
                _safe_audit("get_customer_for_driver", driver_id, customer_id, "blocked_return_guard")
                return None

            _safe_audit("get_customer_for_driver", driver_id, customer_id, "success")
            return customer

    except sqlite3.Error:
        _safe_audit("get_customer_for_driver", driver_id, customer_id, "db_error")
        return None