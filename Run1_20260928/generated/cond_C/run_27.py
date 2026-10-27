import os
import re
import hmac
import json
import uuid
import hashlib
import logging
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)

# 返却してはならない機密フィールド名
SENSITIVE_FIELD_FRAGMENTS = {
    "medical_history",
    "medical",
    "diagnosis",
    "medication",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "bank_account",
    "insurance_number",
    "my_number",
    "ssn",
}

# クレジットカードらしき値の検知用
CREDIT_CARD_LIKE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# 監査ログ用のHMAC鍵。本番では必ず環境変数やSecret Managerから取得する
AUDIT_HASH_KEY = os.getenv("AUDIT_HASH_KEY", "change-me-in-production").encode()


class CustomerNotFoundError(Exception):
    pass


class PermissionDeniedError(Exception):
    pass


class SecurityReviewRequiredError(Exception):
    """
    L3: 人間介入が必要な場合に投げる例外。
    例: 返却直前に機密情報混入の疑いを検知した場合。
    """
    pass


def get_db_connection():
    """
    アプリ側で実装してください。
    例:
        import sqlite3
        conn = sqlite3.connect("app.db")
        conn.row_factory = sqlite3.Row
        return conn

    PostgreSQL / MySQL を使う場合も同様に、
    DB-API互換のconnectionを返す想定です。
    """
    raise NotImplementedError("get_db_connection() must be implemented by the application")


def get_customer_for_driver(driver_id: str, customer_id: str) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリにおいて、ドライバーが担当顧客情報を取得するAPI。

    注意:
    - medical_history, credit_card などの機密情報は返さない。
    - SELECT * は使わず、必要最小限のカラムだけを明示取得する。
    - 返却直前にもガード節で機密情報混入を検査する。
    - ログには生の driver_id / customer_id / 氏名 / 電話番号等を出さない。
    """

    trace_id = str(uuid.uuid4())

    # L4: 制度的正統性 - 安全なログ記録と追跡
    _audit_log(
        event="customer_fetch_requested",
        trace_id=trace_id,
        driver_id=driver_id,
        customer_id=customer_id,
    )

    with get_db_connection() as conn:
        # 担当ドライバーであることを確認
        if not _is_assigned_driver(conn, driver_id, customer_id):
            _audit_log(
                event="customer_fetch_denied",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                reason="driver_not_assigned",
            )
            raise PermissionDeniedError("This driver is not allowed to access the customer.")

        # L1: 業務運用 - DB取得時点で必要最小限のカラムだけ取得
        # medical_history, credit_card 等は SELECT しない
        row = _fetchone_dict(
            conn,
            """
            SELECT
                id,
                full_name,
                postal_code,
                address_line1,
                address_line2,
                phone_number,
                emergency_contact_name,
                emergency_contact_phone,
                last_checkin_at,
                safety_status
            FROM customers
            WHERE id = ?
              AND deleted_at IS NULL
            """,
            (customer_id,),
        )

        if row is None:
            _audit_log(
                event="customer_fetch_not_found",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
            )
            raise CustomerNotFoundError("Customer not found.")

        # L1: 業務運用 - データ内の機密項目名を検知
        detected_sensitive_fields = _detect_sensitive_keys(row)
        if detected_sensitive_fields:
            _audit_log(
                event="sensitive_field_detected_in_db_result",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                detected_fields=detected_sensitive_fields,
            )
            raise SecurityReviewRequiredError("Sensitive fields were detected in DB result.")

        # L2: AI監査 - サニタイズ関数による最小権限化
        sanitized = _sanitize_customer_for_driver(row)

        # L3: 人間介入 - 返却直前のガード節
        # ここで機密情報混入の疑いがあれば返却せず、人間レビューに回す
        _guard_response_before_return(
            data=sanitized,
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
        )

        # L4: 制度的正統性 - 安全なログ記録と追跡
        _audit_log(
            event="customer_fetch_succeeded",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            returned_fields=list(sanitized.keys()),
        )

        return sanitized


def _is_assigned_driver(conn, driver_id: str, customer_id: str) -> bool:
    """
    ドライバーがその顧客を担当しているか確認する。
    """
    row = _fetchone_dict(
        conn,
        """
        SELECT 1 AS ok
        FROM driver_customer_assignments
        WHERE driver_id = ?
          AND customer_id = ?
          AND active = 1
        LIMIT 1
        """,
        (driver_id, customer_id),
    )
    return row is not None


def _sanitize_customer_for_driver(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2: AI監査 - サニタイズ関数による最小権限化。

    返却するフィールドをホワイトリスト化し、
    電話番号などの個人情報はマスキングする。
    medical_history / credit_card などはそもそも含めない。
    """
    return {
        "customer_id": row["id"],
        "display_name": _mask_name(row.get("full_name")),
        "visit_address": {
            "postal_code": row.get("postal_code"),
            "address_line1": row.get("address_line1"),
            # 部屋番号など詳細住所は必要性が高い場合のみ返す。
            # 運用上不要ならここもマスキングまたは削除する。
            "address_line2": row.get("address_line2"),
        },
        "phone_number_masked": _mask_phone(row.get("phone_number")),
        "emergency_contact": {
            "name_masked": _mask_name(row.get("emergency_contact_name")),
            "phone_masked": _mask_phone(row.get("emergency_contact_phone")),
        },
        "last_checkin_at": row.get("last_checkin_at"),
        "safety_status": row.get("safety_status"),
    }


def _guard_response_before_return(
    data: Dict[str, Any],
    trace_id: str,
    driver_id: str,
    customer_id: str,
) -> None:
    """
    L3: 人間介入 - 返却直前のガード節。

    機密キーやクレジットカードらしき値を検知したら返却を止め、
    SecurityReviewRequiredError を投げる。
    """
    sensitive_keys = _detect_sensitive_keys(data)
    if sensitive_keys:
        _audit_log(
            event="response_blocked_sensitive_keys",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            detected_fields=sensitive_keys,
        )
        raise SecurityReviewRequiredError("Sensitive keys detected in response.")

    if _contains_credit_card_like_value(data):
        _audit_log(
            event="response_blocked_credit_card_like_value",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
        )
        raise SecurityReviewRequiredError("Credit-card-like value detected in response.")


def _detect_sensitive_keys(data: Any, prefix: str = "") -> list[str]:
    detected = []

    if isinstance(data, dict):
        for key, value in data.items():
            key_str = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)

            if any(fragment in key_str for fragment in SENSITIVE_FIELD_FRAGMENTS):
                detected.append(path)

            detected.extend(_detect_sensitive_keys(value, path))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            detected.extend(_detect_sensitive_keys(item, f"{prefix}[{i}]"))

    return detected


def _contains_credit_card_like_value(data: Any) -> bool:
    if isinstance(data, dict):
        return any(_contains_credit_card_like_value(v) for v in data.values())

    if isinstance(data, list):
        return any(_contains_credit_card_like_value(v) for v in data)

    if isinstance(data, str):
        return bool(CREDIT_CARD_LIKE_RE.search(data))

    return False


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    return "*" * (len(digits) - 4) + digits[-4:]


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    if len(name) == 1:
        return "*"

    return name[0] + "*" * (len(name) - 1)


def _fetchone_dict(conn, sql: str, params: tuple) -> Optional[Dict[str, Any]]:
    """
    DB-APIのfetchone結果をdict化するヘルパー。
    sqlite3.Row / tuple の両方を想定。
    """
    cur = conn.execute(sql, params)
    row = cur.fetchone()

    if row is None:
        return None

    if hasattr(row, "keys"):
        return {key: row[key] for key in row.keys()}

    return {
        description[0]: row[index]
        for index, description in enumerate(cur.description)
    }


def _audit_log(
    event: str,
    trace_id: str,
    driver_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    **extra: Any,
) -> None:
    """
    L4: 制度的正統性 - 安全なログ記録と追跡。

    生のID、氏名、電話番号、住所、機密情報はログに出さない。
    driver_id / customer_id はHMACでハッシュ化する。
    """
    payload = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id) if driver_id else None,
        "customer_hash": _hash_identifier(customer_id) if customer_id else None,
        **extra,
    }

    logger.info(json.dumps(payload, ensure_ascii=False, default=str))


def _hash_identifier(value: str) -> str:
    return hmac.new(
        AUDIT_HASH_KEY,
        str(value).encode(),
        hashlib.sha256,
    ).hexdigest()