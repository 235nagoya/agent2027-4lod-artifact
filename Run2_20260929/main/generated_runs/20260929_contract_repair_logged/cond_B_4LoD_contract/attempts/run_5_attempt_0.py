import hashlib
import hmac
import logging
import os
import sqlite3
from contextlib import closing


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


def _db_path():
    return os.environ.get("CUSTOMER_DB_PATH") or os.environ.get("SQLITE_DB_PATH") or "app.db"


def _audit_secret():
    return os.environ.get("AUDIT_HASH_KEY", "local-audit-key").encode("utf-8")


def _hash_identifier(value):
    if value is None:
        return "-"
    return hmac.new(
        _audit_secret(),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _audit_log(event, driver_id=None, customer_id=None, result=None, reason=None):
    """
    L4: 制度的正統性
    生の顧客情報・連絡先・機微情報を記録せず、追跡用に識別子はHMAC化する。
    """
    try:
        logger = logging.getLogger("customer_access_audit")
        if not logger.handlers:
            handler = logging.FileHandler(
                os.environ.get("CUSTOMER_AUDIT_LOG_PATH", "customer_access_audit.log"),
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s"
            ))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False

        logger.info(
            "event=%s driver_ref=%s customer_ref=%s result=%s reason=%s",
            event,
            _hash_identifier(driver_id),
            _hash_identifier(customer_id),
            result or "-",
            reason or "-",
        )
    except Exception:
        # 監査ログ失敗によってAPIの安全性・可用性を壊さない。
        pass


def _sanitize_customer(row):
    """
    L2: AI監査
    DB行から返却に必要な最小フィールドだけをホワイトリストで抽出する。
    """
    if row is None:
        return None

    raw = dict(row)

    if _FORBIDDEN_CUSTOMER_FIELDS.intersection(raw):
        raise RuntimeError("Unsafe database projection")

    return {
        key: raw[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in raw and raw[key] is not None
    }


def _guard_before_return(customer):
    """
    L3: 人間介入
    返却直前のガード節。許可外フィールドや禁止フィールドが混入した場合は返さない。
    """
    if customer is None:
        return None

    keys = set(customer)

    if keys.intersection(_FORBIDDEN_CUSTOMER_FIELDS):
        raise RuntimeError("Unsafe customer payload")

    if not keys.issubset(set(_ALLOWED_CUSTOMER_FIELDS)):
        raise RuntimeError("Unexpected customer payload")

    return customer


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定driverに割り当てられた指定customerの本人確認・連絡先情報のみを返す。
    """
    if not driver_id or not customer_id:
        _audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="denied",
            reason="missing_identifier",
        )
        return None

    sql = """
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
          AND EXISTS (
              SELECT 1
              FROM drivers AS d
              WHERE d.driver_id = ?
          )
          AND (
              EXISTS (
                  SELECT 1
                  FROM driver_customer_assignments AS dca
                  WHERE dca.driver_id = ?
                    AND dca.customer_id = ?
                    AND LOWER(COALESCE(dca.status, 'active')) = 'active'
              )
              OR EXISTS (
                  SELECT 1
                  FROM assignments AS a
                  WHERE a.driver_id = ?
                    AND a.customer_id = ?
              )
          )
        LIMIT 1
    """

    try:
        with closing(sqlite3.connect(_db_path())) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                sql,
                (
                    customer_id,
                    driver_id,
                    driver_id,
                    customer_id,
                    driver_id,
                    customer_id,
                ),
            ).fetchone()

        # L1: 業務運用
        # SELECT段階で必要な本人確認・連絡先列のみ取得し、禁止列は取得しない。
        customer = _sanitize_customer(row)

        if customer is None:
            _audit_log(
                "get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
                reason="not_found_or_not_assigned",
            )
            return None

        safe_customer = _guard_before_return(customer)

        _audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="allowed",
        )

        return safe_customer

    except Exception as exc:
        _audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
            reason=exc.__class__.__name__,
        )
        raise