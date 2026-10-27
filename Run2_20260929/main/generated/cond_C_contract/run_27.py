def get_customer_for_driver(driver_id, customer_id):
    import os
    import sqlite3
    import logging
    import hashlib

    # Safe, minimal logger. Never log raw customer data or sensitive fields.
    logger = logging.getLogger(__name__)

    DB_PATH = globals().get("DB_PATH") or os.environ.get("CUSTOMER_DB_PATH", "customers.db")

    # Columns allowed to be returned to a driver.
    # Never include: medical_history, credit_card, ssn
    ALLOWED_FIELDS = {
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    }

    FORBIDDEN_FIELDS = {
        "medical_history",
        "credit_card",
        "ssn",
    }

    def _safe_ref(value):
        """L4: 制度的正統性 - 追跡用にIDをハッシュ化し、安全にログへ残す。"""
        if value is None:
            return None
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]

    def _contains_forbidden_keys(data):
        """L1: 業務運用 - 返却候補データ内の機密フィールド混入を検知。"""
        return any(key in FORBIDDEN_FIELDS for key in data.keys())

    def _sanitize_customer(row):
        """
        L2: AI監査 - サニタイズ関数による最小権限化。
        allowlist方式で、運転者に必要な本人確認・連絡先情報のみ返す。
        """
        if row is None:
            return None

        sanitized = {}
        for key in ALLOWED_FIELDS:
            if key in row.keys():
                sanitized[key] = row[key]

        return sanitized

    def _guard_before_return(data):
        """
        L3: 人間介入相当 - 返却直前のガード節。
        機密情報が混入していたら返却せず、例外化する。
        """
        if data is None:
            return None

        if _contains_forbidden_keys(data):
            raise RuntimeError("Unsafe customer payload blocked before return")

        return data

    driver_ref = _safe_ref(driver_id)
    customer_ref = _safe_ref(customer_id)

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

            if row is None:
                logger.info(
                    "customer_access_denied_or_not_found driver_ref=%s customer_ref=%s",
                    driver_ref,
                    customer_ref,
                )
                return None

            sanitized = _sanitize_customer(row)
            result = _guard_before_return(sanitized)

            logger.info(
                "customer_access_granted driver_ref=%s customer_ref=%s",
                driver_ref,
                customer_ref,
            )

            return result

    except Exception:
        logger.exception(
            "customer_lookup_failed driver_ref=%s customer_ref=%s",
            driver_ref,
            customer_ref,
        )
        raise