import os
import re
import uuid
import hashlib
import logging
import sqlite3
from contextlib import closing


logger = logging.getLogger(__name__)

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

_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_CANDIDATE_PATTERN = re.compile(r"(?:\d[ -]?){13,19}")


def _database_path():
    return (
        os.environ.get("CUSTOMER_DB_PATH")
        or os.environ.get("DATABASE_PATH")
        or "app.db"
    )


def _safe_hash(value):
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _contains_credit_card_like_value(value):
    if value is None:
        return False

    text = str(value)
    for match in _CC_CANDIDATE_PATTERN.findall(text):
        digits = re.sub(r"\D", "", match)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True
    return False


def _luhn_valid(digits):
    total = 0
    reverse_digits = digits[::-1]

    for index, char in enumerate(reverse_digits):
        number = int(char)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number

    return total % 10 == 0


def _sanitize_customer_record(record):
    """
    L2: AI監査
    allowlist方式で返却可能な identity/contact data のみに最小化する。
    """
    if record is None:
        return None

    sanitized = {}

    for key in _ALLOWED_CUSTOMER_FIELDS:
        sanitized[key] = record.get(key)

    return sanitized


def _guard_before_return(payload, trace_id):
    """
    L3: 人間介入
    返却直前に、禁止フィールドや明らかな秘匿値が混入していないか確認する。
    """
    if payload is None:
        return None

    forbidden_present = _FORBIDDEN_FIELDS.intersection(payload.keys())
    if forbidden_present:
        logger.critical(
            "blocked_unsafe_customer_payload trace_id=%s reason=forbidden_fields",
            trace_id,
        )
        raise RuntimeError("unsafe customer payload blocked")

    for key, value in payload.items():
        if key not in _ALLOWED_CUSTOMER_FIELDS:
            logger.critical(
                "blocked_unsafe_customer_payload trace_id=%s reason=unexpected_field",
                trace_id,
            )
            raise RuntimeError("unsafe customer payload blocked")

        if isinstance(value, str):
            if _SSN_PATTERN.search(value) or _contains_credit_card_like_value(value):
                logger.critical(
                    "blocked_unsafe_customer_payload trace_id=%s reason=sensitive_value_detected",
                    trace_id,
                )
                raise RuntimeError("unsafe customer payload blocked")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリ用の顧客情報取得API。

    Return:
        dict | None:
            customer_id, id, name, display_name, full_name,
            address, phone, phone_number のみ返す。
            未割当・未存在の場合は None。

    Never returns/logs/exposes:
        medical_history, credit_card, ssn
    """
    trace_id = str(uuid.uuid4())

    # L4: 制度的正統性
    # ログには生の driver_id/customer_id や個人情報を出さず、追跡用のハッシュのみ記録する。
    logger.info(
        "customer_lookup_started trace_id=%s driver_hash=%s customer_hash=%s",
        trace_id,
        _safe_hash(driver_id),
        _safe_hash(customer_id),
    )

    query = """
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
    """

    try:
        with closing(sqlite3.connect(_database_path())) as conn:
            conn.row_factory = sqlite3.Row

            # L1: 業務運用
            # 禁止カラム medical_history, credit_card, ssn は SELECT しない。
            # パラメータ化クエリで取得対象を限定する。
            row = conn.execute(query, (customer_id, driver_id, driver_id)).fetchone()

        if row is None:
            logger.info(
                "customer_lookup_not_found_or_not_assigned trace_id=%s driver_hash=%s customer_hash=%s",
                trace_id,
                _safe_hash(driver_id),
                _safe_hash(customer_id),
            )
            return None

        record = dict(row)

        sanitized = _sanitize_customer_record(record)
        safe_payload = _guard_before_return(sanitized, trace_id)

        logger.info(
            "customer_lookup_completed trace_id=%s driver_hash=%s customer_hash=%s",
            trace_id,
            _safe_hash(driver_id),
            _safe_hash(customer_id),
        )

        return safe_payload

    except sqlite3.DatabaseError as exc:
        logger.error(
            "customer_lookup_database_error trace_id=%s error_type=%s",
            trace_id,
            type(exc).__name__,
        )
        raise RuntimeError("customer lookup failed") from exc