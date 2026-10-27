import hashlib
import hmac
import logging
import os
import sqlite3


DATABASE_PATH = None  # 必要に応じて呼び出し側で上書き可能

_ALLOWED_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_CUSTOMER_COLUMNS = frozenset(("medical_history", "credit_card", "ssn"))

_AUDIT_LOGGER = logging.getLogger("customer_access_audit")
_AUDIT_LOGGER.addHandler(logging.NullHandler())


def _database_path():
    return (
        DATABASE_PATH
        or os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


def _normalize_identifier(value, field_name):
    if value is None:
        raise ValueError(f"{field_name} is required")

    value = str(value).strip()
    if not value:
        raise ValueError(f"{field_name} is required")

    if len(value) > 256:
        raise ValueError(f"{field_name} is too long")

    return value


def _audit_ref(value):
    """
    L4: 制度的正統性
    監査ログでは実IDを記録せず、HMAC化した参照値のみを記録する。
    """
    secret = os.environ.get("AUDIT_LOG_SECRET", "default-local-audit-secret").encode("utf-8")
    message = str(value).encode("utf-8", errors="replace")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()[:20]


def _safe_audit_log(event, driver_id, customer_id, result):
    """
    L4: 安全なログ記録と追跡。
    個人情報・医療情報・決済情報・公的識別子は出力しない。
    """
    _AUDIT_LOGGER.info(
        "event=%s driver_ref=%s customer_ref=%s result=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
        result,
    )


def _clean_text(value):
    if value is None:
        return None

    value = str(value)

    # 制御文字を除去して返却データの安全性を高める
    return "".join(ch for ch in value if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def _sanitize_customer_record(row):
    """
    L2: AI監査
    DB取得後も許可カラムだけに絞り、最小権限の返却形にサニタイズする。
    """
    row_keys = set(row.keys())

    return {
        column: _clean_text(row[column])
        for column in _ALLOWED_CUSTOMER_COLUMNS
        if column in row_keys
    }


def _guard_before_return(record):
    """
    L3: 人間介入
    返却直前のガード節。
    許可されていないカラムが混入した場合は返却しない。
    """
    if not isinstance(record, dict):
        return False

    keys = set(record.keys())

    if keys & _FORBIDDEN_CUSTOMER_COLUMNS:
        return False

    if not keys.issubset(set(_ALLOWED_CUSTOMER_COLUMNS)):
        return False

    return True


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定driverに割り当てられたcustomerの本人確認・連絡先情報のみを取得する。

    Return:
        dict | None

    返却する情報:
        customer_id, id, name, display_name, full_name, address, phone, phone_number

    返却・出力・ログ記録しない情報:
        medical_history, credit_card, ssn
    """
    try:
        driver_id = _normalize_identifier(driver_id, "driver_id")
        customer_id = _normalize_identifier(customer_id, "customer_id")
    except Exception:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "invalid_input")
        raise

    try:
        with sqlite3.connect(_database_path()) as conn:
            conn.row_factory = sqlite3.Row

            # L1: 業務運用
            # 個人情報の過剰取得を避けるため、必要な本人確認・連絡先カラムのみSELECTする。
            # 機微カラムはSELECT対象に含めない。
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
                WHERE
                    c.customer_id = ?
                    AND (
                        EXISTS (
                            SELECT 1
                            FROM driver_customer_assignments AS dca
                            WHERE
                                dca.driver_id = ?
                                AND dca.customer_id = c.customer_id
                                AND COALESCE(dca.status, 'active') = 'active'
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM assignments AS a
                            WHERE
                                a.driver_id = ?
                                AND a.customer_id = c.customer_id
                        )
                    )
                LIMIT 1
                """,
                (customer_id, driver_id, driver_id),
            ).fetchone()

        if row is None:
            _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "not_found_or_not_authorized")
            return None

        sanitized = _sanitize_customer_record(row)

        if not _guard_before_return(sanitized):
            _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "blocked_by_return_guard")
            raise RuntimeError("unsafe customer record blocked")

        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "returned")
        return sanitized

    except sqlite3.Error:
        _safe_audit_log("get_customer_for_driver", driver_id, customer_id, "database_error")
        raise