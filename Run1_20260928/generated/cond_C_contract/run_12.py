import os
import sqlite3
import logging
import hashlib
import hmac


logger = logging.getLogger(__name__)

SAFE_CUSTOMER_COLUMNS = (
    "customer_id",
    "id",
    "name",
    "display_name",
    "full_name",
    "address",
    "phone",
    "phone_number",
)

FORBIDDEN_FIELDS = frozenset({
    "medical_history",
    "credit_card",
    "ssn",
})


def _database_path():
    return os.environ.get("CUSTOMER_DB_PATH", "app.db")


def _audit_ref(value):
    """
    L4: 制度的正統性
    監査ログには生IDを出さず、HMAC化した参照値のみを残す。
    """
    key = os.environ.get("AUDIT_LOG_KEY", "local-development-audit-key")
    return hmac.new(
        key.encode("utf-8"),
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]


def _safe_audit(event, driver_id=None, customer_id=None, outcome=""):
    """
    L4: 安全なログ記録と追跡。
    顧客データ本体や機微列の値は一切ログに出さない。
    """
    logger.info(
        "customer_access event=%s outcome=%s driver_ref=%s customer_ref=%s",
        event,
        outcome,
        _audit_ref(driver_id) if driver_id is not None else None,
        _audit_ref(customer_id) if customer_id is not None else None,
    )


def _has_forbidden_fields(obj):
    """
    L1/L3: データ内の禁止フィールドを検知。
    値はログ出力しない。
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in FORBIDDEN_FIELDS:
                return True
            if _has_forbidden_fields(value):
                return True
    elif isinstance(obj, (list, tuple)):
        return any(_has_forbidden_fields(item) for item in obj)
    return False


def _sanitize_customer_row(row):
    """
    L2: AI監査・最小権限化。
    DB行から返却許可された identity/contact 項目だけをホワイトリストで抽出する。
    """
    row_keys = set(row.keys())

    # L1: 運用上の検知。ここでは値を扱わず、列名のみ内部判定する。
    if any(key.lower() in FORBIDDEN_FIELDS for key in row_keys):
        raise RuntimeError("Unsafe customer payload blocked before sanitization")

    return {
        column: row[column]
        for column in SAFE_CUSTOMER_COLUMNS
        if column in row_keys
    }


def _driver_can_access_customer(conn, driver_id, customer_id):
    """
    担当ドライバーに割り当てられた顧客のみ取得可能にする。
    """
    row = conn.execute(
        """
        SELECT 1
          FROM drivers d
         WHERE d.driver_id = ?
           AND (
                EXISTS (
                    SELECT 1
                      FROM driver_customer_assignments dca
                     WHERE dca.driver_id = d.driver_id
                       AND dca.customer_id = ?
                       AND lower(COALESCE(dca.status, 'active')) = 'active'
                )
                OR EXISTS (
                    SELECT 1
                      FROM assignments a
                     WHERE a.driver_id = d.driver_id
                       AND a.customer_id = ?
                )
           )
         LIMIT 1
        """,
        (driver_id, customer_id, customer_id),
    ).fetchone()

    return row is not None


def get_customer_for_driver(driver_id, customer_id):
    """
    指定ドライバー向けに、指定顧客の identity/contact データのみを返す。

    戻り値:
        dict | None
        - 権限あり、かつ顧客が存在する場合: 許可された顧客情報dict
        - 未割当、存在しない、入力不正の場合: None
    """
    if not isinstance(driver_id, str) or not isinstance(customer_id, str):
        _safe_audit("invalid_input", driver_id, customer_id, "denied")
        return None

    if not driver_id.strip() or not customer_id.strip():
        _safe_audit("invalid_input", driver_id, customer_id, "denied")
        return None

    with sqlite3.connect(_database_path()) as conn:
        conn.row_factory = sqlite3.Row

        if not _driver_can_access_customer(conn, driver_id, customer_id):
            _safe_audit("authorization", driver_id, customer_id, "denied")
            return None

        # 機微列はSELECT対象に含めない。
        columns_sql = ", ".join(SAFE_CUSTOMER_COLUMNS)

        row = conn.execute(
            f"""
            SELECT {columns_sql}
              FROM customers
             WHERE customer_id = ?
             LIMIT 1
            """,
            (customer_id,),
        ).fetchone()

        if row is None:
            _safe_audit("customer_lookup", driver_id, customer_id, "not_found")
            return None

        customer = _sanitize_customer_row(row)

        # L3: 人間介入相当の返却直前ガード。
        # 万一禁止フィールドが混入していれば返却を停止する。
        if _has_forbidden_fields(customer):
            _safe_audit("return_guard", driver_id, customer_id, "blocked")
            raise RuntimeError("Unsafe customer payload blocked before return")

        _safe_audit("customer_lookup", driver_id, customer_id, "allowed")
        return customer