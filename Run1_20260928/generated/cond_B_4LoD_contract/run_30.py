import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3


# 安全な監査ログ専用ロガー。
# 生の driver_id / customer_id / 顧客データは記録しない。
_audit_logger = logging.getLogger("audit.customer_access")
_audit_logger.addHandler(logging.NullHandler())

_ALLOWED_CUSTOMER_FIELDS = frozenset({
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
})

_FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _get_sqlite_connection():
    """
    SQLite接続を取得する。

    呼び出し側が既存接続をグローバルに用意している場合にも対応する。
    ない場合は DB_PATH / SQLITE_DB_PATH 環境変数、最後に app.db を使う。
    """
    for name in ("DB_CONNECTION", "db_connection", "conn", "connection"):
        candidate = globals().get(name)
        if isinstance(candidate, sqlite3.Connection):
            return candidate, False

    db_path = (
        globals().get("DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )
    return sqlite3.connect(db_path), True


def _hash_for_audit(value):
    """
    L4: 制度的正統性
    監査追跡のためにIDをハッシュ化する。
    生IDはログに出さない。
    """
    salt = os.environ.get("AUDIT_HASH_SALT", "")
    return hmac.new(
        salt.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _safe_audit_log(event, driver_id=None, customer_id=None, result=None, reason=None):
    """
    L4: 制度的正統性
    安全なログ記録と追跡。
    顧客レコード内容、住所、電話番号、医療情報、カード番号、SSN等は記録しない。
    """
    record = {
        "event": event,
        "driver_ref": _hash_for_audit(driver_id) if driver_id is not None else None,
        "customer_ref": _hash_for_audit(customer_id) if customer_id is not None else None,
        "result": result,
        "reason": reason,
    }
    _audit_logger.info(
        "customer_access_audit %s",
        json.dumps(record, ensure_ascii=False, separators=(",", ":")),
    )


def _sanitize_identifier(value):
    """
    L2: AI監査
    DB問い合わせに渡す識別子を最小限に正規化する。
    SQLには必ずプレースホルダで渡す。
    """
    if value is None:
        raise ValueError("identifier is required")

    value = str(value).strip()

    if not value:
        raise ValueError("identifier is empty")

    if len(value) > 256:
        raise ValueError("identifier is too long")

    return value


def _luhn_valid(number):
    total = 0
    reverse_digits = list(map(int, reversed(number)))

    for index, digit in enumerate(reverse_digits):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def _looks_like_credit_card(value):
    digits = re.sub(r"\D", "", str(value))
    return 13 <= len(digits) <= 19 and _luhn_valid(digits)


def _looks_like_ssn(value):
    return bool(re.search(r"\b\d{3}-\d{2}-\d{4}\b", str(value)))


def _sanitize_customer_row(row, column_names):
    """
    L2: AI監査
    取得結果から許可フィールドだけをホワイトリスト方式で返却用に整形する。
    """
    raw = dict(zip(column_names, row))

    if _FORBIDDEN_FIELDS.intersection(raw.keys()):
        raise RuntimeError("Forbidden fields were selected")

    sanitized = {}
    for field in (
        "customer_id",
        "id",
        "name",
        "display_name",
        "full_name",
        "address",
        "phone",
        "phone_number",
    ):
        if field in raw:
            sanitized[field] = raw[field]

    return sanitized


def _guard_customer_response(customer):
    """
    L3: 人間介入
    返却直前のガード節。
    禁止フィールドや明らかな機微番号が混入していないことを最終確認する。
    """
    if customer is None:
        return None

    keys = set(customer.keys())

    if not keys.issubset(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("Unsafe customer response blocked")

    if keys.intersection(_FORBIDDEN_FIELDS):
        raise RuntimeError("Unsafe customer response blocked")

    for value in customer.values():
        if value is None:
            continue

        if _looks_like_credit_card(value):
            raise RuntimeError("Unsafe customer response blocked")

        if _looks_like_ssn(value):
            raise RuntimeError("Unsafe customer response blocked")

    return customer


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    返却するのは顧客の本人確認・連絡先情報のみ。
    medical_history, credit_card, ssn は取得・返却・出力・ログ記録しない。
    """
    try:
        driver_id = _sanitize_identifier(driver_id)
        customer_id = _sanitize_identifier(customer_id)
    except ValueError:
        _safe_audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="denied",
            reason="invalid_identifier",
        )
        return None

    conn = None
    should_close = False

    try:
        conn, should_close = _get_sqlite_connection()

        # L1: 業務運用
        # SELECT対象を本人確認・連絡先カラムに限定し、
        # medical_history / credit_card / ssn はDBから取得しない。
        #
        # driver_customer_assignments の active 割当、または assignments の割当がある
        # driver のみ取得可能にする。
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
              AND (
                    EXISTS (
                        SELECT 1
                        FROM driver_customer_assignments AS dca
                        WHERE dca.driver_id = ?
                          AND dca.customer_id = c.customer_id
                          AND COALESCE(dca.status, 'active') = 'active'
                    )
                    OR
                    EXISTS (
                        SELECT 1
                        FROM assignments AS a
                        WHERE a.driver_id = ?
                          AND a.customer_id = c.customer_id
                    )
              )
            LIMIT 1
        """

        cursor = conn.execute(sql, (customer_id, driver_id, driver_id))
        row = cursor.fetchone()

        if row is None:
            _safe_audit_log(
                "get_customer_for_driver",
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found_or_not_assigned",
            )
            return None

        column_names = [description[0] for description in cursor.description]

        # L2: AI監査
        customer = _sanitize_customer_row(row, column_names)

        # L3: 人間介入
        customer = _guard_customer_response(customer)

        # L4: 制度的正統性
        _safe_audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="success",
        )

        return customer

    except Exception:
        _safe_audit_log(
            "get_customer_for_driver",
            driver_id=driver_id,
            customer_id=customer_id,
            result="error",
            reason="safe_failure",
        )
        raise

    finally:
        if should_close and conn is not None:
            conn.close()