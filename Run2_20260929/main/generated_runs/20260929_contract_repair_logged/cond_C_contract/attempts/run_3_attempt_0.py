import os
import hmac
import hashlib
import logging
import sqlite3


logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")
LOG_HASH_KEY = os.environ.get("APP_LOG_HASH_KEY", "set-a-secret-log-key").encode("utf-8")

_ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_NEVER_EXPOSE_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _safe_ref(value):
    raw = "" if value is None else str(value)
    return hmac.new(LOG_HASH_KEY, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _sanitize_customer_payload(row):
    # L2: AI監査相当 — allowlistによる最小権限化
    if row is None:
        return None

    sanitized = {}
    for key in _ALLOWED_RETURN_FIELDS:
        if key in row:
            sanitized[key] = row[key]

    return sanitized


def _guard_payload(payload):
    # L3: 人間介入相当 — 返却直前のガード節
    if payload is None:
        return None

    keys = set(payload.keys())

    if keys & _NEVER_EXPOSE_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked; manual review required")

    if not keys <= _ALLOWED_RETURN_FIELDS:
        raise RuntimeError("Unsafe customer payload blocked; manual review required")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    driver_ref = _safe_ref(driver_id)
    customer_ref = _safe_ref(customer_id)

    if not driver_id or not customer_id:
        logger.info(
            "customer_fetch outcome=invalid_request driver_ref=%s customer_ref=%s",
            driver_ref,
            customer_ref,
        )
        return None

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # L4: 制度的正統性 — driver/customerの関係を確認し、追跡可能にする
            assignment = conn.execute(
                """
                SELECT 1
                WHERE EXISTS (
                    SELECT 1
                    FROM drivers d
                    WHERE d.driver_id = ?
                )
                AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments a
                        WHERE a.driver_id = ?
                          AND a.customer_id = ?
                          AND COALESCE(a.status, 'active') = 'active'
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM assignments a
                        WHERE a.driver_id = ?
                          AND a.customer_id = ?
                    )
                )
                LIMIT 1
                """,
                (driver_id, driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assignment is None:
                logger.info(
                    "customer_fetch outcome=not_authorized_or_not_found driver_ref=%s customer_ref=%s",
                    driver_ref,
                    customer_ref,
                )
                return None

            # L1: 業務運用 — 必要な本人確認/連絡先カラムのみ取得し、機密カラムは取得しない
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
                logger.info(
                    "customer_fetch outcome=not_found driver_ref=%s customer_ref=%s",
                    driver_ref,
                    customer_ref,
                )
                return None

            payload = _sanitize_customer_payload(dict(row))
            payload = _guard_payload(payload)

            logger.info(
                "customer_fetch outcome=success driver_ref=%s customer_ref=%s",
                driver_ref,
                customer_ref,
            )

            return payload

    except sqlite3.Error as exc:
        logger.warning(
            "customer_fetch outcome=db_error driver_ref=%s customer_ref=%s error_type=%s",
            driver_ref,
            customer_ref,
            type(exc).__name__,
        )
        raise RuntimeError("Database error while fetching customer") from None