import os
import re
import json
import hmac
import uuid
import hashlib
import logging
import sqlite3
from typing import Any, Dict, List, Mapping, Optional


# ============================================================
# 設定
# ============================================================

DB_PATH = os.environ.get("DB_PATH", "app.db")

# 監査ログ用。実運用では必ず環境変数やKMS等から取得してください。
AUDIT_HASH_SECRET = os.environ.get("AUDIT_HASH_SECRET", "CHANGE_ME_IN_PRODUCTION").encode()

logger = logging.getLogger("audit.customer_access")


# ============================================================
# 例外
# ============================================================

class NotFoundOrForbiddenError(Exception):
    """顧客が存在しない、または driver に参照権限がない場合。"""


class DataLeakPreventionError(Exception):
    """返却直前の安全確認で機密情報混入が検知された場合。"""


# ============================================================
# L4: 制度的正統性
# 安全なログ記録と追跡
# - 生の driver_id / customer_id / 個人情報はログに出さない
# - HMACで疑似匿名化して監査可能性を確保
# ============================================================

def _hash_identifier(value: Any) -> str:
    raw = str(value).encode()
    return hmac.new(AUDIT_HASH_SECRET, raw, hashlib.sha256).hexdigest()


def _audit_log(
    *,
    event: str,
    driver_id: Any,
    customer_id: Any,
    trace_id: str,
    result: str,
    reason: Optional[str] = None,
) -> None:
    payload = {
        "event": event,
        "trace_id": trace_id,
        "driver_hash": _hash_identifier(driver_id),
        "customer_hash": _hash_identifier(customer_id),
        "result": result,
    }

    if reason:
        payload["reason"] = reason

    # 個人情報や機密情報は含めない
    logger.info("customer_access_audit=%s", json.dumps(payload, ensure_ascii=False))


# ============================================================
# DB接続
# ============================================================

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# L1: 業務運用
# データ内の個人情報をマスキング・検知
# ============================================================

CREDIT_CARD_PATTERN = re.compile(r"(?:\d[ -]*?){13,19}")

SENSITIVE_KEYWORDS = {
    "medical_history",
    "credit_card",
    "credit_card_number",
    "card_number",
    "card_no",
    "cvv",
    "cvc",
    "diagnosis",
    "disease",
    "medication",
    "insurance_number",
    "my_number",
    "マイナンバー",
    "病歴",
    "既往歴",
    "診断",
    "服薬",
    "薬",
    "クレジットカード",
}


def _mask_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    name = name.strip()
    if len(name) <= 1:
        return "*"

    # 例: 山田太郎 -> 山**
    return name[0] + "*" * (len(name) - 1)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "***"

    return f"***-****-{digits[-4:]}"


def _mask_address(address: Optional[str]) -> Optional[str]:
    """
    住所は詳細番地を返さず、市区町村程度までに抑える。
    例: 東京都新宿区西新宿2-8-1 -> 東京都新宿区以降非表示
    """
    if not address:
        return None

    match = re.match(r"^(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "以降非表示"

    # パターンに合わない住所は荒くマスク
    return address[:6] + "..." if len(address) > 6 else "***"


def _redact_free_text(text: Optional[str]) -> Optional[str]:
    """
    自由記述欄は漏えいリスクが高いため、カード番号らしき値などを伏せる。
    医療情報らしきキーワードを含む場合は全文を返さない。
    """
    if not text:
        return None

    lower_text = text.lower()

    for keyword in SENSITIVE_KEYWORDS:
        if keyword.lower() in lower_text:
            return "[REDACTED]"

    text = CREDIT_CARD_PATTERN.sub("[REDACTED_CARD]", text)

    return text


def _contains_luhn_valid_number(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def _detect_sensitive_issues(obj: Any, path: str = "") -> List[str]:
    """
    キー名・値の両方から機密情報混入を検知する。
    """
    issues: List[str] = []

    if isinstance(obj, Mapping):
        for key, value in obj.items():
            key_str = str(key)
            current_path = f"{path}.{key_str}" if path else key_str

            if key_str.lower() in {k.lower() for k in SENSITIVE_KEYWORDS}:
                issues.append(f"sensitive_key:{current_path}")

            issues.extend(_detect_sensitive_issues(value, current_path))

    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            issues.extend(_detect_sensitive_issues(value, f"{path}[{i}]"))

    elif isinstance(obj, str):
        # クレジットカード番号らしき値
        for match in CREDIT_CARD_PATTERN.findall(obj):
            if _contains_luhn_valid_number(match):
                issues.append(f"possible_credit_card:{path}")

        lower_value = obj.lower()
        for keyword in SENSITIVE_KEYWORDS:
            if keyword.lower() in lower_value:
                issues.append(f"sensitive_keyword:{path}:{keyword}")

    return issues


# ============================================================
# L2: AI監査
# サニタイズ関数による最小権限化
# - allowlist方式
# - medical_history / credit_card 等は構造上返却不能にする
# ============================================================

ALLOWED_RETURN_FIELDS = {
    "customer_id",
    "display_name",
    "phone_masked",
    "address_area",
    "emergency_contact_name_masked",
    "emergency_contact_phone_masked",
    "last_checkin_at",
    "status",
    "driver_note",
}


def _sanitize_customer_for_driver(row: sqlite3.Row) -> Dict[str, Any]:
    """
    DBレコードを driver 向けの最小限レスポンスに変換する。

    注意:
    - medical_history
    - credit_card
    - insurance_number
    - my_number

    などは絶対に返却しない。
    """
    sanitized = {
        "customer_id": row["customer_id"],
        "display_name": _mask_name(row["name"]),
        "phone_masked": _mask_phone(row["phone"]),
        "address_area": _mask_address(row["address"]),
        "emergency_contact_name_masked": _mask_name(row["emergency_contact_name"]),
        "emergency_contact_phone_masked": _mask_phone(row["emergency_contact_phone"]),
        "last_checkin_at": row["last_checkin_at"],
        "status": row["status"],
        "driver_note": _redact_free_text(row["driver_note"]),
    }

    # allowlist以外のフィールドを混入させない
    extra_fields = set(sanitized.keys()) - ALLOWED_RETURN_FIELDS
    if extra_fields:
        raise DataLeakPreventionError(f"Unexpected fields: {extra_fields}")

    return sanitized


# ============================================================
# L3: 人間介入
# 返却直前でのガード節によるチェック
# - 万一、実装ミスで機密情報が混入した場合は返却を止める
# ============================================================

def _guard_before_return(response: Dict[str, Any]) -> None:
    issues = _detect_sensitive_issues(response)

    if issues:
        # ここでは「検知した内容そのもの」をログに出しすぎない。
        # 必要なら件数や種別程度に限定する。
        raise DataLeakPreventionError(
            f"Sensitive data detected before return. issue_count={len(issues)}"
        )


# ============================================================
# API本体
# ============================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> Dict[str, Any]:
    """
    高齢者向け安否確認アプリのドライバー用顧客情報取得API。

    機能:
    - 指定 customer_id の顧客レコードをDBから取得する。
    - driver_id に割り当てられた顧客のみ取得可能。
    - medical_history / credit_card 等の機密情報は返却しない。

    前提テーブル例:
    - customers
        - id
        - name
        - phone
        - address
        - emergency_contact_name
        - emergency_contact_phone
        - last_checkin_at
        - status
        - driver_note
        - medical_history
        - credit_card
    - driver_customer_assignments
        - driver_id
        - customer_id
        - active
    """
    trace_id = str(uuid.uuid4())

    _audit_log(
        event="get_customer_for_driver.start",
        driver_id=driver_id,
        customer_id=customer_id,
        trace_id=trace_id,
        result="started",
    )

    try:
        with _get_connection() as conn:
            # 重要:
            # SELECT * は使わない。
            # medical_history / credit_card などの機密カラムをDB取得時点で除外する。
            row = conn.execute(
                """
                SELECT
                    c.id AS customer_id,
                    c.name,
                    c.phone,
                    c.address,
                    c.emergency_contact_name,
                    c.emergency_contact_phone,
                    c.last_checkin_at,
                    c.status,
                    c.driver_note
                FROM customers c
                INNER JOIN driver_customer_assignments a
                    ON a.customer_id = c.id
                WHERE
                    c.id = ?
                    AND a.driver_id = ?
                    AND a.active = 1
                LIMIT 1
                """,
                (customer_id, driver_id),
            ).fetchone()

        if row is None:
            _audit_log(
                event="get_customer_for_driver.denied",
                driver_id=driver_id,
                customer_id=customer_id,
                trace_id=trace_id,
                result="denied",
                reason="not_found_or_forbidden",
            )
            raise NotFoundOrForbiddenError("Customer not found or access forbidden.")

        # L2: 最小権限化されたレスポンスへ変換
        response = _sanitize_customer_for_driver(row)

        # L3: 返却直前の漏えい防止ガード
        _guard_before_return(response)

        _audit_log(
            event="get_customer_for_driver.success",
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            result="success",
        )

        return response

    except DataLeakPreventionError:
        _audit_log(
            event="get_customer_for_driver.blocked",
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            result="blocked",
            reason="sensitive_data_detected",
        )
        raise

    except Exception:
        _audit_log(
            event="get_customer_for_driver.error",
            driver_id=driver_id,
            customer_id=customer_id,
            trace_id=trace_id,
            result="error",
            reason="unexpected_error",
        )
        raise