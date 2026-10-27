import os
import re
import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)

DB_PATH = os.getenv("APP_DB_PATH", "app.db")


class SecurityError(Exception):
    pass


# =========================
# L1: 業務運用
# データ内の個人情報・機密情報を検知し、ログ用にはマスキングする
# =========================

FORBIDDEN_FIELD_NAMES = {
    "medical_history",
    "medical_record",
    "diagnosis",
    "disease",
    "medication",
    "allergy",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "bank_account",
    "insurance_number",
    "my_number",
}

FORBIDDEN_KEY_PATTERN = re.compile(
    r"(medical|history|diagnosis|disease|medication|allergy|credit|card|cvv|cvc|bank|insurance|my_number)",
    re.IGNORECASE,
)

# クレジットカードらしき13〜19桁の連続数字を検知
CREDIT_CARD_LIKE_PATTERN = re.compile(r"\b\d{13,19}\b")


def mask_value(value: Any) -> Any:
    """
    ログ出力用のマスキング。
    返却データ用ではなく、監査ログ・アプリログに使う。
    """
    if value is None:
        return None

    s = str(value)

    # 長い数字列はマスク
    if CREDIT_CARD_LIKE_PATTERN.search(s):
        return CREDIT_CARD_LIKE_PATTERN.sub("[MASKED_NUMBER]", s)

    # 電話番号っぽいものを軽くマスク
    if re.search(r"\d{2,4}-?\d{2,4}-?\d{3,4}", s):
        return re.sub(r"\d", "*", s)

    if len(s) > 100:
        return s[:100] + "...[TRUNCATED]"

    return value


def mask_dict_for_log(data: Dict[str, Any]) -> Dict[str, Any]:
    masked = {}

    for key, value in data.items():
        if key.lower() in FORBIDDEN_FIELD_NAMES or FORBIDDEN_KEY_PATTERN.search(key):
            masked[key] = "[REDACTED]"
        else:
            masked[key] = mask_value(value)

    return masked


def detect_sensitive_data(data: Any, path: str = "") -> list[str]:
    """
    返却予定データ内に禁止フィールドやカード番号らしき値がないか検知する。
    """
    violations = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            if key.lower() in FORBIDDEN_FIELD_NAMES or FORBIDDEN_KEY_PATTERN.search(key):
                violations.append(f"forbidden_key:{current_path}")

            violations.extend(detect_sensitive_data(value, current_path))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            violations.extend(detect_sensitive_data(item, f"{path}[{i}]"))

    elif isinstance(data, str):
        if CREDIT_CARD_LIKE_PATTERN.search(data):
            violations.append(f"credit_card_like_value:{path}")

    return violations


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

ALLOWED_CUSTOMER_FIELDS = {
    "customer_id",
    "full_name",
    "phone",
    "address",
    "emergency_contact_name",
    "emergency_contact_phone",
    "last_checkin_at",
    "safety_status",
}


def sanitize_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    DBから取得した顧客レコードを、ドライバーに必要な最小項目のみに制限する。
    medical_history, credit_card 等はここで確実に落とす。
    """
    sanitized = {
        key: record.get(key)
        for key in ALLOWED_CUSTOMER_FIELDS
        if key in record
    }

    return sanitized


# =========================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# =========================

def guard_before_return(payload: Dict[str, Any]) -> None:
    """
    返却直前の最終防衛線。
    禁止フィールドやカード番号らしき値が混入していたら返却を中断する。
    """
    violations = detect_sensitive_data(payload)

    if violations:
        raise SecurityError(
            "Sensitive data detected before response: "
            + ", ".join(violations)
        )


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def write_audit_log(
    conn: sqlite3.Connection,
    *,
    actor_driver_id: str,
    customer_id: str,
    action: str,
    outcome: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    監査ログ。
    機密情報は記録しない。
    必要最小限のID、操作、結果、時刻のみを保存する。
    """
    safe_metadata = mask_dict_for_log(metadata or {})

    conn.execute(
        """
        INSERT INTO audit_logs (
            actor_driver_id,
            customer_id,
            action,
            outcome,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor_driver_id,
            customer_id,
            action,
            outcome,
            json.dumps(safe_metadata, ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def get_customer_for_driver(driver_id: str, customer_id: str) -> Optional[Dict[str, Any]]:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    機能:
      - DBから指定 customer_id の顧客情報を取得する。
      - 指定 driver_id に割り当てられている顧客のみ取得可能。
      - medical_history, credit_card などの機密情報は返却しない。

    戻り値:
      - 顧客が存在し、かつ担当ドライバーなら、サニタイズ済みdict
      - 存在しない、または担当外なら None
    """
    conn = get_connection()

    try:
        # 許可されたカラムのみSELECTする。
        # medical_history, credit_card 等はSQLレベルで取得しない。
        row = conn.execute(
            """
            SELECT
                id AS customer_id,
                full_name,
                phone,
                address,
                emergency_contact_name,
                emergency_contact_phone,
                last_checkin_at,
                safety_status
            FROM customers
            WHERE id = ?
              AND assigned_driver_id = ?
            LIMIT 1
            """,
            (customer_id, driver_id),
        ).fetchone()

        if row is None:
            write_audit_log(
                conn,
                actor_driver_id=driver_id,
                customer_id=customer_id,
                action="get_customer_for_driver",
                outcome="not_found_or_not_assigned",
                metadata={"reason": "no accessible customer record"},
            )
            return None

        raw_record = dict(row)

        # L2: サニタイズ
        sanitized = sanitize_customer_record(raw_record)

        # L3: 返却直前チェック
        guard_before_return(sanitized)

        # L4: 安全な監査ログ
        write_audit_log(
            conn,
            actor_driver_id=driver_id,
            customer_id=customer_id,
            action="get_customer_for_driver",
            outcome="success",
            metadata={
                "returned_fields": list(sanitized.keys())
            },
        )

        return sanitized

    except SecurityError as e:
        write_audit_log(
            conn,
            actor_driver_id=driver_id,
            customer_id=customer_id,
            action="get_customer_for_driver",
            outcome="blocked_by_security_guard",
            metadata={"error": str(e)},
        )
        logger.warning(
            "Blocked sensitive customer response. driver_id=%s customer_id=%s",
            driver_id,
            customer_id,
        )
        raise

    finally:
        conn.close()