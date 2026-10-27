import os
import re
import hmac
import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Optional


logger = logging.getLogger(__name__)


# =========================
# 例外
# =========================

class NotFoundError(Exception):
    pass


class ForbiddenError(Exception):
    pass


class DataLeakageError(Exception):
    pass


# =========================
# 設定
# =========================

AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", "replace-this-in-production").encode()

# 返却を絶対に禁止するキー
FORBIDDEN_KEYS = {
    "medical_history",
    "medical_records",
    "diagnosis",
    "disease",
    "medication",
    "allergy",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "my_number",
    "bank_account",
}

# APIレスポンスとして許可するキーのみ定義する
ALLOWED_RESPONSE_KEYS = {
    "trace_id",
    "customer_id",
    "display_name",
    "address",
    "phone_masked",
    "checkin_status",
    "last_seen_at",
}

CREDIT_CARD_CANDIDATE_RE = re.compile(r"(?:\d[ -]*?){13,19}")


# =========================
# DB接続取得
# =========================

def get_db_connection():
    """
    実環境ではアプリケーション側のDB接続取得処理に置き換えてください。

    例:
        import sqlite3
        conn = sqlite3.connect("app.db")
        conn.row_factory = sqlite3.Row
        return conn
    """
    raise NotImplementedError("get_db_connection() を実装してください")


# =========================
# L4: 制度的正統性
# 安全なログ記録と追跡
# =========================

def _hash_ref(value: Any) -> str:
    """
    driver_id / customer_id をそのままログに出さず、HMACで追跡可能な形にする。
    """
    raw = str(value).encode()
    return hmac.new(AUDIT_HMAC_KEY, raw, hashlib.sha256).hexdigest()


def _audit_event(
    conn,
    *,
    event: str,
    trace_id: str,
    driver_id: Any,
    customer_id: Any,
    result: str,
    reason: Optional[str] = None,
) -> None:
    """
    安全な監査ログ。
    - 生の氏名、電話番号、住所、医療情報、カード情報は記録しない。
    - driver_id / customer_id はHMAC化して記録する。
    """

    audit_record = {
        "event": event,
        "trace_id": trace_id,
        "driver_ref": _hash_ref(driver_id),
        "customer_ref": _hash_ref(customer_id),
        "result": result,
        "reason": reason,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # アプリログ・SIEM向け
    logger.info("audit_event=%s", json.dumps(audit_record, ensure_ascii=False))

    # DB監査テーブルへの保存はベストエフォート
    try:
        conn.execute(
            """
            INSERT INTO security_audit_logs
                (
                    event,
                    trace_id,
                    driver_ref,
                    customer_ref,
                    result,
                    reason,
                    created_at
                )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_record["event"],
                audit_record["trace_id"],
                audit_record["driver_ref"],
                audit_record["customer_ref"],
                audit_record["result"],
                audit_record["reason"],
                audit_record["created_at"],
            ),
        )
        conn.commit()
    except Exception:
        # 監査ログ保存失敗時にも個人情報は出さない
        logger.exception("failed_to_write_security_audit_log trace_id=%s", trace_id)


# =========================
# 共通ユーティリティ
# =========================

def _row_to_dict(row: Any) -> dict:
    if row is None:
        return {}

    if isinstance(row, Mapping):
        return dict(row)

    if hasattr(row, "keys"):
        return {key: row[key] for key in row.keys()}

    return dict(row)


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    """
    L1: 業務運用
    電話番号は完全返却せず、下4桁のみ表示する。
    """
    if not phone:
        return None

    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"

    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def _mask_name(name: Optional[str]) -> Optional[str]:
    """
    L1: 業務運用
    氏名を部分マスクする。
    """
    if not name:
        return None

    name = str(name).strip()
    if len(name) <= 1:
        return "*"

    return name[0] + "*" * (len(name) - 1)


def _luhn_check(number: str) -> bool:
    """
    クレジットカード番号らしき値の検知用。
    """
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    checksum = 0
    parity = len(digits) % 2

    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def _contains_credit_card_like_value(value: str) -> bool:
    for match in CREDIT_CARD_CANDIDATE_RE.findall(value):
        digits = re.sub(r"\D", "", match)
        if _luhn_check(digits):
            return True
    return False


# =========================
# L2: AI監査
# サニタイズ関数による最小権限化
# =========================

def _sanitize_customer_for_driver(record: dict, trace_id: str) -> dict:
    """
    ドライバー向けに必要最小限の情報だけを返す。

    重要:
    - medical_history / credit_card などはここで返却しない。
    - whitelist方式でレスポンスを構築する。
    - DBから余分な列を取っていなくても、二重防御としてここでも絞る。
    """

    return {
        "trace_id": trace_id,
        "customer_id": record["customer_id"],
        "display_name": _mask_name(record.get("full_name")),
        "address": record.get("address"),
        "phone_masked": _mask_phone(record.get("phone_number")),
        "checkin_status": record.get("checkin_status"),
        "last_seen_at": record.get("last_seen_at"),
    }


# =========================
# L3: 人間介入
# 返却直前でのガード節
# =========================

def _collect_forbidden_paths(obj: Any, path: str = "") -> list[str]:
    violations = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()
            current_path = f"{path}.{key}" if path else str(key)

            if key_lower in FORBIDDEN_KEYS:
                violations.append(current_path)

            violations.extend(_collect_forbidden_paths(value, current_path))

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            violations.extend(_collect_forbidden_paths(item, f"{path}[{i}]"))

    elif isinstance(obj, str):
        if _contains_credit_card_like_value(obj):
            violations.append(path or "<value>")

    return violations


def _request_human_review(*, trace_id: str, reason: str) -> None:
    """
    実環境ではチケット起票、Slack通知、PagerDuty連携などに置き換える。
    ここでも個人情報やレスポンス本文は出さない。
    """
    logger.critical(
        "human_review_required trace_id=%s reason=%s",
        trace_id,
        reason,
    )


def _guard_response_before_return(payload: dict, trace_id: str) -> None:
    """
    返却直前の最終チェック。
    """
    unexpected_keys = set(payload.keys()) - ALLOWED_RESPONSE_KEYS
    forbidden_paths = _collect_forbidden_paths(payload)

    if unexpected_keys or forbidden_paths:
        reason = {
            "unexpected_keys": sorted(unexpected_keys),
            "forbidden_paths": forbidden_paths,
        }

        _request_human_review(
            trace_id=trace_id,
            reason=json.dumps(reason, ensure_ascii=False),
        )

        raise DataLeakageError(
            f"返却データに許可されていない情報が含まれる可能性があります。trace_id={trace_id}"
        )


# =========================
# 認可チェック
# =========================

def _is_driver_allowed_for_customer(conn, driver_id: Any, customer_id: Any) -> bool:
    """
    driver_id が customer_id にアクセスできるか確認する。
    get_customer_for_driver なので、担当外顧客の取得を防ぐ。
    """
    row = conn.execute(
        """
        SELECT 1
        FROM driver_customer_assignments
        WHERE driver_id = ?
          AND customer_id = ?
          AND active = 1
        LIMIT 1
        """,
        (driver_id, customer_id),
    ).fetchone()

    return row is not None


# =========================
# API本体
# =========================

def get_customer_for_driver(driver_id: Any, customer_id: Any) -> Optional[dict]:
    """
    高齢者向け安否確認アプリ用:
    指定された customer_id の顧客情報を、ドライバー向けに安全化して取得する。

    機能要求:
    - DBから指定 customer_id の顧客レコードを取得する。

    ネガティブ制約:
    - medical_history や credit_card などの機密情報を返却しない。

    4LoD:
    - L1: 氏名・電話番号などの個人情報をマスキング
    - L2: whitelist方式のサニタイズで最小権限化
    - L3: 返却直前にガード節で機密情報混入を検知し、人間レビューへ
    - L4: 生PIIを含まない安全な監査ログを記録
    """

    if driver_id is None or customer_id is None:
        raise ValueError("driver_id and customer_id are required")

    trace_id = str(uuid.uuid4())

    conn = get_db_connection()

    try:
        # 認可
        if not _is_driver_allowed_for_customer(conn, driver_id, customer_id):
            _audit_event(
                conn,
                event="customer.read",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                result="denied",
                reason="driver_not_assigned_to_customer",
            )
            raise ForbiddenError("この顧客情報へのアクセス権がありません")

        # DB取得
        # 重要:
        # SELECT * は使わない。
        # medical_history, credit_card 等の列は最初から取得しない。
        row = conn.execute(
            """
            SELECT
                id AS customer_id,
                full_name,
                address,
                phone_number,
                checkin_status,
                last_seen_at
            FROM customers
            WHERE id = ?
              AND deleted_at IS NULL
            LIMIT 1
            """,
            (customer_id,),
        ).fetchone()

        if row is None:
            _audit_event(
                conn,
                event="customer.read",
                trace_id=trace_id,
                driver_id=driver_id,
                customer_id=customer_id,
                result="not_found",
                reason="customer_not_found",
            )
            return None

        record = _row_to_dict(row)

        # L2: サニタイズ
        payload = _sanitize_customer_for_driver(record, trace_id)

        # L3: 返却直前ガード
        _guard_response_before_return(payload, trace_id)

        # L4: 監査ログ
        _audit_event(
            conn,
            event="customer.read",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="allowed",
            reason=None,
        )

        return payload

    except DataLeakageError:
        _audit_event(
            conn,
            event="customer.read",
            trace_id=trace_id,
            driver_id=driver_id,
            customer_id=customer_id,
            result="blocked",
            reason="data_leakage_guard_triggered",
        )
        raise

    finally:
        try:
            conn.close()
        except Exception:
            logger.exception("failed_to_close_db_connection trace_id=%s", trace_id)