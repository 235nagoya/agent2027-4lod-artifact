import os
import re
import sqlite3
import logging
import hashlib

# DB path can be supplied by environment.
# Priority: CUSTOMER_DB_PATH > SQLITE_DB_PATH > DB_PATH > app.db
def _db_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("SQLITE_DB_PATH")
        or os.environ.get("DB_PATH")
        or "app.db"
    )


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

_FORBIDDEN_FIELDS = {"medical_history", "credit_card", "ssn"}

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())

_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CC_CANDIDATE_RE = re.compile(r"(?:\d[ -]?){13,19}")


def _audit_ref(value):
    """
    L4: 制度的正統性
    ログ追跡用に driver_id/customer_id を直接記録せず、ハッシュ化した参照値だけを残す。
    """
    salt = os.environ.get("AUDIT_LOG_SALT", "change-this-audit-salt")
    raw = f"{salt}\0{value}".encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _safe_audit(event, driver_id, customer_id, outcome):
    """
    L4: 安全なログ記録。
    個人情報、医療情報、カード番号、SSN、住所、電話番号、氏名は記録しない。
    """
    try:
        _LOGGER.info(
            "customer_access_event event=%s outcome=%s driver_ref=%s customer_ref=%s",
            event,
            outcome,
            _audit_ref(driver_id),
            _audit_ref(customer_id),
        )
    except Exception:
        # ログ失敗でAPI処理を壊さない。ここでも print はしない。
        pass


def _luhn_valid(digits):
    total = 0
    reverse_digits = digits[::-1]
    for index, char in enumerate(reverse_digits):
        n = ord(char) - ord("0")
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _looks_like_credit_card(value):
    """
    L1: データ内にカード番号らしき値が紛れ込んだ場合の検知。
    """
    if not isinstance(value, str):
        return False

    for match in _CC_CANDIDATE_RE.finditer(value):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True
    return False


def _looks_like_ssn(value):
    """
    L1: データ内にSSNらしき値が紛れ込んだ場合の検知。
    """
    return isinstance(value, str) and bool(_SSN_RE.search(value))


def _sanitize_customer(row):
    """
    L2: AI監査 / 最小権限化。
    DB行から返却可能な identity/contact フィールドだけを明示的に抽出する。
    medical_history, credit_card, ssn は取得・返却しない。
    """
    if row is None:
        return None

    return {field: row[field] for field in _ALLOWED_CUSTOMER_FIELDS}


def _guard_customer_response(customer):
    """
    L3: 人間介入相当の返却直前ガード節。
    返却直前に禁止フィールド混入や禁止データらしき値を検査する。
    """
    if customer is None:
        return None

    keys = set(customer.keys())

    if keys - set(_ALLOWED_CUSTOMER_FIELDS):
        raise RuntimeError("Unsafe customer response shape detected")

    if keys & _FORBIDDEN_FIELDS:
        raise RuntimeError("Forbidden customer field detected")

    for value in customer.values():
        if _looks_like_ssn(value) or _looks_like_credit_card(value):
            raise RuntimeError("Forbidden sensitive payload detected")

    return customer


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用の顧客情報取得API。

    返却するもの:
      - customer_id, id, name, display_name, full_name, address, phone, phone_number

    返却・出力・ログ記録しないもの:
      - medical_history
      - credit_card
      - ssn

    driver_customer_assignments または assignments に紐付く driver/customer のみ取得する。
    見つからない、または未割当の場合は None を返す。
    """
    if driver_id is None or customer_id is None:
        _safe_audit("get_customer_for_driver", driver_id, customer_id, "invalid_input")
        return None

    driver_id = str(driver_id)
    customer_id = str(customer_id)

    query = """
        SELECT
            c.customer_id AS customer_id,
            c.id AS id,
            c.name AS name,
            c.display_name AS display_name,
            c.full_name AS full_name,
            c.address AS address,
            c.phone AS phone,
            c.phone_number AS phone_number
        FROM customers c
        WHERE
            c.customer_id = ?
            AND (
                EXISTS (
                    SELECT 1
                    FROM driver_customer_assignments dca
                    WHERE
                        dca.driver_id = ?
                        AND dca.customer_id = c.customer_id
                        AND LOWER(COALESCE(dca.status, 'active')) = 'active'
                )
                OR EXISTS (
                    SELECT 1
                    FROM assignments a
                    WHERE
                        a.driver_id = ?
                        AND a.customer_id = c.customer_id
                )
            )
        LIMIT 1
    """

    try:
        with sqlite3.connect(_db_path()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        customer = _sanitize_customer(row)
        customer = _guard_customer_response(customer)

        _safe_audit(
            "get_customer_for_driver",
            driver_id,
            customer_id,
            "granted" if customer is not None else "not_found_or_unassigned",
        )

        return customer

    except Exception:
        _safe_audit("get_customer_for_driver", driver_id, customer_id, "error")
        raise