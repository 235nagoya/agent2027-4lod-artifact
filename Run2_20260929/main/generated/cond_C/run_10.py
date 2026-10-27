from __future__ import annotations

import os
import re
import hmac
import hashlib
import logging
import sqlite3
from typing import Any, Mapping


# =========================================================
# 設定
# =========================================================

DB_PATH = os.getenv("APP_DB_PATH", "app.db")
AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY", "change-me-in-production").encode()

logger = logging.getLogger("audit.customer_access")
logger.setLevel(logging.INFO)


# =========================================================
# 例外
# =========================================================

class Forbidden(Exception):
    """運転者に顧客情報を閲覧する権限がない場合"""


class SecurityViolation(Exception):
    """返却データに機密情報が混入しそうな場合"""


# =========================================================
# L1 / L2 / L3 で利用する定義
# =========================================================

# 返却してはならないフィールド名
FORBIDDEN_FIELD_NAMES = {
    "medical_history",
    "medical_histories",
    "disease",
    "diagnosis",
    "medication",
    "prescription",
    "insurance_number",
    "credit_card",
    "credit_card_number",
    "card_number",
    "cvv",
    "cvc",
    "bank_account",
}

# 業務上扱う可能性があるが、原則マスキング対象のPII
PII_FIELD_NAMES = {
    "full_name",
    "kana_name",
    "address",
    "phone_number",
    "emergency_contact",
}

# 返却を許可するキー
RETURN_ALLOWLIST = {
    "customer_id",
    "display_name",
    "kana_name",
    "address_area",
    "phone_masked",
    "planned_visit_window",
    "last_checkin_at",
    "note_for_driver",
}

# クレジットカード候補検知
CARD_CANDIDATE_RE = re.compile(r"(?:\d[ -]?){13,19}")

# 医療・健康情報らしき語の検知
MEDICAL_TEXT_RE = re.compile(
    r"(病歴|既往歴|診断|疾患|服薬|投薬|処方|通院|入院|"
    r"認知症|糖尿病|高血圧|心疾患|がん|癌|アレルギー)",
    re.IGNORECASE,
)


# =========================================================
# DB接続
# =========================================================

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================================================
# L4: 制度的正統性 — 安全な監査ログ
# 生の driver_id / customer_id / PII はログに出さない
# =========================================================

def _hash_identifier(value: Any) -> str:
    raw = str(value).encode()
    return hmac.new(AUDIT_HMAC_KEY, raw, hashlib.sha256).hexdigest()[:16]


def audit_log(
    event: str,
    *,
    driver_id: Any,
    customer_id: Any,
    status: str,
    reason: str | None = None,
    fields: list[str] | None = None,
) -> None:
    logger.info(
        "event=%s driver_hash=%s customer_hash=%s status=%s reason=%s fields=%s",
        event,
        _hash_identifier(driver_id),
        _hash_identifier(customer_id),
        status,
        reason or "-",
        ",".join(fields or []),
    )


# =========================================================
# L1: 業務運用 — PII / 機密情報の検知とマスキング
# =========================================================

def mask_name(name: str | None) -> str | None:
    if not name:
        return None
    name = str(name).strip()
    if not name:
        return None
    return name[0] + "＊＊"


def mask_phone(phone: str | None) -> str | None:
    if not phone:
        return None

    digits = re.sub(r"\D", "", str(phone))
    if len(digits) < 4:
        return "****"

    return "***-****-" + digits[-4:]


def mask_address(address: str | None) -> str | None:
    """
    住所は詳細番地を返さず、市区町村程度に丸める。
    例: 東京都新宿区西新宿1-2-3 -> 東京都新宿区（詳細非表示）
    """
    if not address:
        return None

    address = str(address).strip()
    if not address:
        return None

    match = re.match(r"^(.+?[都道府県].+?[市区町村])", address)
    if match:
        return match.group(1) + "（詳細非表示）"

    return "詳細非表示"


def _luhn_check(number: str) -> bool:
    """
    クレジットカード番号らしさの判定。
    誤検知を減らすため Luhn check を使う。
    """
    digits = [int(c) for c in number if c.isdigit()]
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


def contains_card_number(text: str) -> bool:
    for candidate in CARD_CANDIDATE_RE.findall(text):
        digits = re.sub(r"\D", "", candidate)
        if _luhn_check(digits):
            return True
    return False


def redact_sensitive_text(text: str | None) -> str | None:
    """
    自由記述欄から医療情報・カード番号らしき内容を除去する。
    note_for_driver のような欄に機密情報が誤入力されるケースへの対策。
    """
    if text is None:
        return None

    value = str(text)

    if contains_card_number(value):
        value = CARD_CANDIDATE_RE.sub("[REDACTED]", value)

    value = MEDICAL_TEXT_RE.sub("[REDACTED]", value)

    return value


def detect_record_risks(record: Mapping[str, Any]) -> list[str]:
    """
    DBから取得したレコード内に、PIIや禁止フィールドが含まれていないか検知する。
    ここでは値そのものは返さず、リスク種別だけを返す。
    """
    risks: list[str] = []

    for key, value in record.items():
        key_lower = key.lower()

        if key_lower in PII_FIELD_NAMES:
            risks.append(f"pii_field:{key_lower}")

        if key_lower in FORBIDDEN_FIELD_NAMES:
            risks.append(f"forbidden_field:{key_lower}")

        if isinstance(value, str):
            if MEDICAL_TEXT_RE.search(value):
                risks.append(f"medical_text_detected:{key_lower}")

            if contains_card_number(value):
                risks.append(f"card_number_detected:{key_lower}")

    return risks


# =========================================================
# L2: AI監査 — サニタイズ関数による最小権限化
# =========================================================

def sanitize_customer_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """
    DBレコードを、運転者に必要な最小限の情報だけに変換する。
    medical_history / credit_card などはそもそも返却候補に含めない。
    """
    sanitized = {
        "customer_id": record.get("customer_id"),
        "display_name": mask_name(record.get("full_name")),
        "kana_name": mask_name(record.get("kana_name")),
        "address_area": mask_address(record.get("address")),
        "phone_masked": mask_phone(record.get("phone_number")),
        "planned_visit_window": record.get("planned_visit_window"),
        "last_checkin_at": record.get("last_checkin_at"),
        "note_for_driver": redact_sensitive_text(record.get("note_for_driver")),
    }

    # allowlist に存在するキーだけを返す
    sanitized = {
        key: value
        for key, value in sanitized.items()
        if key in RETURN_ALLOWLIST and value is not None
    }

    return sanitized


# =========================================================
# L3: 人間介入相当 — 返却直前ガード節
# =========================================================

def guard_response_safe(payload: Mapping[str, Any]) -> None:
    """
    返却直前の最終防衛線。
    禁止フィールド名や、医療・カード情報らしき値が混入したらブロックする。
    """
    for key, value in payload.items():
        key_lower = key.lower()

        if key_lower not in RETURN_ALLOWLIST:
            raise SecurityViolation(f"返却未許可フィールドを検出: {key}")

        if key_lower in FORBIDDEN_FIELD_NAMES:
            raise SecurityViolation(f"禁止フィールドを検出: {key}")

        if isinstance(value, str):
            if MEDICAL_TEXT_RE.search(value):
                raise SecurityViolation(f"医療情報らしき文字列を検出: {key}")

            if contains_card_number(value):
                raise SecurityViolation(f"カード番号らしき文字列を検出: {key}")


# =========================================================
# 権限確認
# =========================================================

def driver_can_access_customer(
    conn: sqlite3.Connection,
    driver_id: int,
    customer_id: int,
) -> bool:
    """
    運転者が当該顧客を担当しているか確認する。
    最小権限のため、担当外の customer_id は取得不可。
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


# =========================================================
# API本体
# =========================================================

def get_customer_for_driver(driver_id: int, customer_id: int) -> dict[str, Any] | None:
    """
    高齢者向け安否確認アプリの顧客情報取得API。

    戻り値:
        dict:
            運転者向けにサニタイズ済みの顧客情報

        None:
            customer_id に該当する顧客が存在しない場合

    例外:
        Forbidden:
            driver_id が customer_id を閲覧できない場合

        SecurityViolation:
            返却データに機密情報が混入しそうな場合
    """
    driver_id = int(driver_id)
    customer_id = int(customer_id)

    audit_log(
        "customer_lookup_start",
        driver_id=driver_id,
        customer_id=customer_id,
        status="started",
    )

    conn = get_db()

    try:
        # 権限確認
        if not driver_can_access_customer(conn, driver_id, customer_id):
            audit_log(
                "customer_lookup_denied",
                driver_id=driver_id,
                customer_id=customer_id,
                status="denied",
                reason="driver_not_assigned",
            )
            raise Forbidden("この顧客情報を閲覧する権限がありません。")

        # DBから指定 customer_id の顧客レコードを取得
        # SELECT * は使わず、必要な列のみ取得する
        row = conn.execute(
            """
            SELECT
                customer_id,
                full_name,
                kana_name,
                address,
                phone_number,
                planned_visit_window,
                last_checkin_at,
                note_for_driver
            FROM customers
            WHERE customer_id = ?
              AND deleted_at IS NULL
            LIMIT 1
            """,
            (customer_id,),
        ).fetchone()

        if row is None:
            audit_log(
                "customer_lookup_not_found",
                driver_id=driver_id,
                customer_id=customer_id,
                status="not_found",
            )
            return None

        raw_record = dict(row)

        # L1: 取得データ内のPII・機密情報検知
        risks = detect_record_risks(raw_record)
        if risks:
            audit_log(
                "customer_record_risk_detected",
                driver_id=driver_id,
                customer_id=customer_id,
                status="detected",
                reason=";".join(risks),
            )

        # L2: サニタイズ・最小権限化
        response = sanitize_customer_record(raw_record)

        # L3: 返却直前のガード
        guard_response_safe(response)

        # L4: 安全な監査ログ
        audit_log(
            "customer_lookup_success",
            driver_id=driver_id,
            customer_id=customer_id,
            status="success",
            fields=list(response.keys()),
        )

        return response

    except SecurityViolation as exc:
        audit_log(
            "customer_lookup_blocked",
            driver_id=driver_id,
            customer_id=customer_id,
            status="blocked",
            reason=str(exc),
        )
        raise

    finally:
        conn.close()