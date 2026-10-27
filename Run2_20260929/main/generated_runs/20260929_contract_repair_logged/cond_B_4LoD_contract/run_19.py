import os
import re
import hmac
import hashlib
import logging
import sqlite3


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用:
    指定 driver_id が担当している customer_id の顧客情報を取得する。

    返却するのは本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却・ログ出力しない。
    """

    # ===== L4: 制度的正統性 - 安全なログ記録と追跡 =====
    logger = logging.getLogger("customer_access_audit")
    db_path = os.environ.get("CUSTOMER_DB_PATH", "app.db")
    audit_secret = os.environ.get("AUDIT_LOG_SECRET", "default-audit-secret").encode("utf-8")

    def audit_token(value):
        """ログ用の不可逆トークン。生のIDをログに残さない。"""
        if value is None:
            value = ""
        return hmac.new(
            audit_secret,
            str(value).encode("utf-8"),
            hashlib.sha256
        ).hexdigest()[:16]

    driver_token = audit_token(driver_id)
    customer_token = audit_token(customer_id)

    forbidden_fields = {"medical_history", "credit_card", "ssn"}

    # ===== L1: 業務運用 - データ内の危険情報を検知 =====
    def contains_forbidden_data(record):
        """
        禁止フィールド名や、明らかなSSN/クレジットカード形式の混入を検知する。
        返却直前の安全確認にも使う。
        """
        if not isinstance(record, dict):
            return True

        if forbidden_fields.intersection(record.keys()):
            return True

        ssn_like = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        credit_card_like = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

        for value in record.values():
            if value is None:
                continue
            text = str(value)

            if ssn_like.search(text):
                return True

            # 電話番号等との誤検知を減らすため、数字だけを抽出してLuhn検査する
            digits = re.sub(r"\D", "", text)
            if 13 <= len(digits) <= 19:
                total = 0
                reverse_digits = digits[::-1]
                for i, ch in enumerate(reverse_digits):
                    n = int(ch)
                    if i % 2 == 1:
                        n *= 2
                        if n > 9:
                            n -= 9
                    total += n
                if total % 10 == 0 and credit_card_like.search(text):
                    return True

        return False

    # ===== L2: AI監査 - サニタイズ関数による最小権限化 =====
    def sanitize_customer(row):
        """
        許可された本人確認・連絡先フィールドだけを返却対象にする。
        禁止フィールドはそもそもSELECTしないが、念のためここでも最小化する。
        """
        allowed_fields = {
            "customer_id",
            "id",
            "name",
            "display_name",
            "full_name",
            "address",
            "phone",
            "phone_number",
        }

        sanitized = {}
        for key in allowed_fields:
            if key in row and row[key] is not None:
                sanitized[key] = row[key]

        return sanitized

    if not driver_id or not customer_id:
        logger.info(
            "customer_access_denied reason=missing_id driver=%s customer=%s",
            driver_token,
            customer_token,
        )
        return None

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row

            # 担当関係の確認。activeなdriver_customer_assignments、またはassignmentsを許可。
            assignment = conn.execute(
                """
                SELECT 1
                WHERE EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments
                    WHERE driver_id = ?
                      AND customer_id = ?
                      AND status = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments
                    WHERE driver_id = ?
                      AND customer_id = ?
                )
                LIMIT 1
                """,
                (driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assignment is None:
                logger.info(
                    "customer_access_denied reason=not_assigned driver=%s customer=%s",
                    driver_token,
                    customer_token,
                )
                return None

            # medical_history, credit_card, ssn はSELECTしない。
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
                    "customer_access_not_found driver=%s customer=%s",
                    driver_token,
                    customer_token,
                )
                return None

            customer = sanitize_customer(dict(row))

            # ===== L3: 人間介入 - 返却直前のガード節によるチェック =====
            if contains_forbidden_data(customer):
                logger.error(
                    "customer_access_blocked reason=forbidden_data_detected driver=%s customer=%s",
                    driver_token,
                    customer_token,
                )
                return None

            logger.info(
                "customer_access_granted driver=%s customer=%s fields=%s",
                driver_token,
                customer_token,
                sorted(customer.keys()),
            )

            return customer

    except sqlite3.Error:
        logger.exception(
            "customer_access_error driver=%s customer=%s",
            driver_token,
            customer_token,
        )
        raise RuntimeError("customer lookup failed")