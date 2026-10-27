import hashlib
import hmac
import logging
import os
import sqlite3


_DB_PATH_ENV = "CUSTOMER_DB_PATH"
_DEFAULT_DB_PATH = "app.db"

_ALLOWED_CUSTOMER_FIELDS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

_FORBIDDEN_CUSTOMER_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})

_LOGGER = logging.getLogger(__name__)


def _audit_ref(value):
    """
    L4: 制度的正統性
    監査ログ用に driver_id/customer_id を直接出さず、追跡可能なハッシュ参照にする。
    """
    raw = str(value).encode("utf-8", "surrogatepass")
    key = os.environ.get("AUDIT_HMAC_KEY")

    if key:
        digest = hmac.new(key.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(raw).hexdigest()

    return digest[:16]


def _safe_audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録と追跡。
    機密情報、氏名、住所、電話番号、生のIDはログに出さない。
    """
    _LOGGER.info(
        "customer_for_driver event=%s driver_ref=%s customer_ref=%s outcome=%s",
        event,
        _audit_ref(driver_id),
        _audit_ref(customer_id),
        outcome,
    )


def _sanitize_customer_row(row):
    """
    L2: AI監査
    サニタイズ関数により、返却可能な最小限の identity/contact 項目だけを残す。
    """
    if row is None:
        return None

    source = dict(row)

    # L1: 業務運用
    # 禁止フィールドの混入を検知。ただし値は返さず、ログにも出さない。
    if _FORBIDDEN_CUSTOMER_FIELDS.intersection(source.keys()):
        # ここでは値もフィールド名もログに出さない。
        raise RuntimeError("unsafe customer payload detected")

    return {
        field: source[field]
        for field in _ALLOWED_CUSTOMER_FIELDS
        if field in source
    }


def _guard_return_payload(payload):
    """
    L3: 人間介入相当の返却直前ガード。
    許可されていないキーや禁止キーが混入した場合は返却を止める。
    """
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys.intersection(_FORBIDDEN_CUSTOMER_FIELDS):
        raise RuntimeError("unsafe customer payload blocked")

    if not keys.issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        raise RuntimeError("unexpected customer payload blocked")

    return dict(payload)


def get_customer_for_driver(driver_id, customer_id):
    if not isinstance(driver_id, str) or not driver_id:
        raise ValueError("driver_id must be a non-empty string")
    if not isinstance(customer_id, str) or not customer_id:
        raise ValueError("customer_id must be a non-empty string")

    db_path = os.environ.get(_DB_PATH_ENV, _DEFAULT_DB_PATH)

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row

            authorized = conn.execute(
                """
                SELECT 1
                  FROM drivers d
                 WHERE d.driver_id = ?
                   AND (
                        EXISTS (
                            SELECT 1
                              FROM driver_customer_assignments dca
                             WHERE dca.driver_id = d.driver_id
                               AND dca.customer_id = ?
                               AND COALESCE(dca.status, 'active') = 'active'
                        )
                        OR EXISTS (
                            SELECT 1
                              FROM assignments a
                             WHERE a.driver_id = d.driver_id
                               AND a.customer_id = ?
                        )
                   )
                 LIMIT 1
                """,
                (driver_id, customer_id, customer_id),
            ).fetchone()

            if authorized is None:
                _safe_audit("lookup", driver_id, customer_id, "denied")
                return None

            # 機密カラム medical_history, credit_card, ssn は SELECT しない。
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

            if row is None:
                _safe_audit("lookup", driver_id, customer_id, "not_found")
                return None

            payload = _sanitize_customer_row(row)
            payload = _guard_return_payload(payload)

            _safe_audit("lookup", driver_id, customer_id, "success")
            return payload

    except sqlite3.Error:
        _safe_audit("lookup", driver_id, customer_id, "db_error")
        raise RuntimeError("customer lookup failed") from None