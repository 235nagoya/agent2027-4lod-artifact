import hashlib
import logging
import os
import re
import sqlite3
import uuid


DB_PATH = os.environ.get("SQLITE_DB_PATH", "app.db")

logger = logging.getLogger(__name__)

_ALLOWED_RETURN_KEYS = {
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
}

_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


def _sanitize_id(value, field_name):
    """
    L2: AI監査 / 最小権限化
    - IDとして扱える文字列のみ許可
    - SQLは必ずプレースホルダを使用する
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    value = value.strip()

    if not value or not _ID_RE.fullmatch(value):
        raise ValueError(f"invalid {field_name}")

    return value


def _safe_audit_id(value):
    """
    L4: 制度的正統性 / 安全なログ記録と追跡
    - 生の customer_id / driver_id はログに出さない
    - 追跡可能なハッシュのみ記録
    """
    salt = os.environ.get("AUDIT_LOG_SALT", "default-local-audit-salt")
    digest = hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()
    return digest[:16]


def _mask_for_log(value):
    """
    L1: 業務運用 / 個人情報のマスキング
    ログ用。返却データには使わない。
    """
    if value is None:
        return None

    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)

    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _validate_response_payload(payload):
    """
    L3: 人間介入 / 返却直前のガード節
    - 返却キーを allow-list で固定
    - 顧客の医療・決済・識別番号系など、許可外フィールドを返さない
    """
    if not isinstance(payload, dict):
        raise RuntimeError("invalid response payload")

    keys = set(payload.keys())

    if not keys.issubset(_ALLOWED_RETURN_KEYS):
        raise RuntimeError("response contains non-allowed fields")

    return payload


def get_customer_for_driver(driver_id, customer_id):
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    Returns:
        dict:
            {
                "customer_id": ...,
                "id": ...,
                "name": ...,
                "display_name": ...,
                "full_name": ...,
                "address": ...,
                "phone": ...,
                "phone_number": ...
            }

    Notes:
        - 標準ライブラリのみ使用
        - SQLインジェクション対策としてプレースホルダを使用
        - 返却対象は identity/contact data のみ
        - 医療情報・決済情報・公的識別番号系の値は取得も返却もしない
        - driver_customer_assignments の active 割当、または assignments の割当を確認する
    """
    trace_id = uuid.uuid4().hex

    driver_id = _sanitize_id(driver_id, "driver_id")
    customer_id = _sanitize_id(customer_id, "customer_id")

    safe_driver_ref = _safe_audit_id(driver_id)
    safe_customer_ref = _safe_audit_id(customer_id)

    logger.info(
        "customer_lookup_started trace_id=%s driver_ref=%s customer_ref=%s",
        trace_id,
        safe_driver_ref,
        safe_customer_ref,
    )

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            assignment = conn.execute(
                """
                SELECT 1
                FROM driver_customer_assignments
                WHERE driver_id = ?
                  AND customer_id = ?
                  AND status = 'active'

                UNION

                SELECT 1
                FROM assignments
                WHERE driver_id = ?
                  AND customer_id = ?

                LIMIT 1
                """,
                (driver_id, customer_id, driver_id, customer_id),
            ).fetchone()

            if assignment is None:
                logger.warning(
                    "customer_lookup_denied trace_id=%s driver_ref=%s customer_ref=%s",
                    trace_id,
                    safe_driver_ref,
                    safe_customer_ref,
                )
                raise PermissionError("driver is not assigned to this customer")

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
                    "customer_lookup_not_found trace_id=%s driver_ref=%s customer_ref=%s",
                    trace_id,
                    safe_driver_ref,
                    safe_customer_ref,
                )
                raise LookupError("customer not found")

            payload = {
                "customer_id": row["customer_id"],
                "id": row["id"],
                "name": row["name"],
                "display_name": row["display_name"],
                "full_name": row["full_name"],
                "address": row["address"],
                "phone": row["phone"],
                "phone_number": row["phone_number"],
            }

            payload = _validate_response_payload(payload)

            logger.info(
                "customer_lookup_succeeded trace_id=%s driver_ref=%s customer_ref=%s returned_fields=%s masked_customer_ref=%s",
                trace_id,
                safe_driver_ref,
                safe_customer_ref,
                sorted(payload.keys()),
                _mask_for_log(customer_id),
            )

            return payload

    except Exception:
        logger.exception(
            "customer_lookup_failed trace_id=%s driver_ref=%s customer_ref=%s",
            trace_id,
            safe_driver_ref,
            safe_customer_ref,
        )
        raise