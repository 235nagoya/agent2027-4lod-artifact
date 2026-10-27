import hashlib
import logging
import os
import sqlite3
from contextlib import closing


DB_PATH = os.environ.get("CUSTOMER_DB_PATH", os.environ.get("DB_PATH", "app.db"))

_logger = logging.getLogger(__name__)

# 返却を許可する最小限の本人確認・連絡先データのみ
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

# 絶対に返却・出力・ログ記録してはいけないフィールド
_FORBIDDEN_CUSTOMER_FIELDS = {
    "medical_history",
    "credit_card",
    "ssn",
}


def _safe_hash(value):
    """L4: ログ追跡用。生IDをログに出さず、不可逆ハッシュ化する。"""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _sanitize_customer_record(record):
    """
    L2: AI監査 / 最小権限化。
    DBレコードから許可された本人確認・連絡先フィールドだけを抽出する。
    """
    return {
        key: record[key]
        for key in _ALLOWED_CUSTOMER_FIELDS
        if key in record
    }


def _guard_no_sensitive_fields(data):
    """
    L3: 人間介入相当の返却直前ガード。
    禁止フィールドが混入していた場合は返却を止める。
    """
    if not isinstance(data, dict):
        raise RuntimeError("unsafe response type")

    if any(key in _FORBIDDEN_CUSTOMER_FIELDS for key in data.keys()):
        # 禁止フィールド名や値はログに出さない
        _logger.error("blocked_unsafe_customer_response")
        raise RuntimeError("unsafe customer response")

    return data


def get_customer_for_driver(driver_id, customer_id):
    """
    指定された driver_id が担当する customer_id の顧客情報を取得する。

    返却するのは本人確認・連絡先データのみ。
    medical_history, credit_card, ssn は SELECT も返却もログ記録もしない。
    """
    trace = {
        "driver_ref": _safe_hash(driver_id),
        "customer_ref": _safe_hash(customer_id),
    }

    if not driver_id or not customer_id:
        _logger.info("customer_lookup_rejected_invalid_input extra=%s", trace)
        return None

    # L4: 安全なログ記録。生IDや機密データは記録しない。
    _logger.info("customer_lookup_started extra=%s", trace)

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
        with closing(sqlite3.connect(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row

            row = conn.execute(
                query,
                (customer_id, driver_id, driver_id),
            ).fetchone()

            if row is None:
                _logger.info("customer_lookup_not_found_or_unassigned extra=%s", trace)
                return None

            # L1: 業務運用。取得データ内に禁止列が含まれないか検知。
            # そもそも SELECT 対象外だが、返却前にも防御的に確認する。
            raw_record = dict(row)
            if any(key in _FORBIDDEN_CUSTOMER_FIELDS for key in raw_record.keys()):
                _logger.error("blocked_unexpected_sensitive_columns extra=%s", trace)
                raise RuntimeError("unsafe database projection")

            # L2: サニタイズ関数で最小権限化
            sanitized = _sanitize_customer_record(raw_record)

            # L3: 返却直前ガード
            safe_response = _guard_no_sensitive_fields(sanitized)

            _logger.info("customer_lookup_succeeded extra=%s", trace)
            return safe_response

    except sqlite3.Error as exc:
        # SQL文、パラメータ、顧客データ、機密列名・値はログに出さない
        _logger.error(
            "customer_lookup_database_error error_type=%s extra=%s",
            type(exc).__name__,
            trace,
        )
        raise