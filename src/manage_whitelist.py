from pathlib import Path
import argparse
import ipaddress
import json
import re
import socket
import sqlite3
import sys
import ipaddress
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "app_state" / "trust_store.db"

ALLOWED_KINDS = {"host", "ip", "ip_port", "cidr"}
ALLOWED_SOURCES = {"user", "system", "api"}
ALLOWED_CATEGORIES = {
    "general",
    "dns",
    "cdn",
    "cloud",
    "os_update",
    "browser",
    "custom",
    "public_dns",
    "china_mainland_routes",
    "china_telecom_dns",
    "china_unicom_dns",
    "china_mobile_dns",
}
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS whitelist_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL,
                value TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'user',
                category TEXT NOT NULL DEFAULT 'general',
                confidence REAL NOT NULL DEFAULT 1.0,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_seen_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_whitelist_rules_unique
            ON whitelist_rules(rule_type, value)
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_rule_type_value ON whitelist_rules(rule_type, value)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_source_enabled ON whitelist_rules(source, is_enabled)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_category_enabled ON whitelist_rules(category, is_enabled)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_updated_at ON whitelist_rules(updated_at DESC)")

        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(whitelist_rules)").fetchall()
        }
        migrations = [
            ("category", "ALTER TABLE whitelist_rules ADD COLUMN category TEXT NOT NULL DEFAULT 'general'"),
            ("confidence", "ALTER TABLE whitelist_rules ADD COLUMN confidence REAL NOT NULL DEFAULT 1.0"),
            ("last_seen_at", "ALTER TABLE whitelist_rules ADD COLUMN last_seen_at TEXT"),
        ]
        for column_name, ddl in migrations:
            if column_name not in existing_columns:
                conn.execute(ddl)

        conn.commit()


def validate_ip(value: str) -> str:
    value = value.strip()
    ipaddress.ip_address(value)
    return value
def validate_cidr(value: str) -> str:
    value = value.strip()
    network = ipaddress.ip_network(value, strict=False)
    return str(network)

def validate_host(value: str) -> str:
    value = value.strip().lower()
    if not value:
        raise ValueError("Host cannot be empty")
    return value


def validate_ip_port(value: str) -> str:
    value = value.strip().lower()
    if not re.match(r"^[^:]+:\d+$", value):
        raise ValueError("ip_port must look like ip:port")
    host_part, port_part = value.rsplit(":", 1)
    validate_ip(host_part)
    port = int(port_part)
    if not (1 <= port <= 65535):
        raise ValueError("Port out of range")
    return f"{host_part}:{port}"


def normalize_value(kind: str, value: str) -> str:
    if kind == "host":
        return validate_host(value)
    if kind == "ip":
        return validate_ip(value)
    if kind == "ip_port":
        return validate_ip_port(value)
    if kind == "cidr":
        return validate_cidr(value)
    raise ValueError(f"Unknown kind: {kind}")


def normalize_source(source: str) -> str:
    source = (source or "user").strip().lower()
    if source not in ALLOWED_SOURCES:
        raise ValueError(f"Unsupported source: {source}")
    return source


def normalize_category(category: str) -> str:
    category = (category or "general").strip().lower()
    if category not in ALLOWED_CATEGORIES:
        raise ValueError(f"Unsupported category: {category}")
    return category


def normalize_enabled(value: str | int | bool) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return 1 if value else 0

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return 1
    if text in {"0", "false", "no", "off"}:
        return 0
    raise ValueError("enabled must be true/false or 1/0")


def resolve_host_ips(host: str) -> list[str]:
    host = host.strip().lower()
    if not host:
        return []

    results: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for item in infos:
            sockaddr = item[4]
            if sockaddr and len(sockaddr) >= 1:
                ip_value = str(sockaddr[0]).strip()
                if ip_value:
                    results.add(ip_value)
    except Exception:
        return []

    return sorted(results)


def enrich_item_with_resolution(item: dict) -> dict:
    enriched = dict(item)
    if enriched.get("rule_type") == "host":
        enriched["resolved_ips"] = resolve_host_ips(enriched.get("value", ""))
    else:
        enriched["resolved_ips"] = []
    return enriched


def add_item(
    kind: str,
    value: str,
    note: str = "",
    source: str = "user",
    category: str = "general",
    confidence: float = 1.0,
    is_enabled: int = 1,
) -> str:
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"Unknown kind: {kind}")

    ensure_db()
    normalized = normalize_value(kind, value)
    source = normalize_source(source)
    category = normalize_category(category)
    is_enabled = normalize_enabled(is_enabled)
    confidence = float(confidence)
    now = utc_now_iso()
    note = note.strip()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        columns = {row[1] for row in conn.execute("PRAGMA table_info(whitelist_rules)").fetchall()}
        existing = conn.execute(
            """
            SELECT *
            FROM whitelist_rules
            WHERE rule_type = ? AND value = ?
            """,
            (kind, normalized),
        ).fetchone()

        if existing is None:
            if {"category", "confidence", "last_seen_at"}.issubset(columns):
                conn.execute(
                    """
                    INSERT INTO whitelist_rules(
                        rule_type, value, note, source, category, confidence,
                        is_enabled, created_at, updated_at, last_seen_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        kind,
                        normalized,
                        note,
                        source,
                        category,
                        confidence,
                        is_enabled,
                        now,
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO whitelist_rules(
                        rule_type, value, note, source,
                        is_enabled, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        kind,
                        normalized,
                        note,
                        source,
                        is_enabled,
                        now,
                        now,
                    ),
                )
            conn.commit()
            return normalized

        existing_source = str(existing["source"] or "user").strip().lower()

        # Do not allow system/api sync to overwrite a user-managed entry.
        if existing_source == "user" and source in {"system", "api"}:
            if {"category", "confidence"}.issubset(columns):
                conn.execute(
                    """
                    UPDATE whitelist_rules
                    SET note = ?,
                        category = ?,
                        confidence = ?,
                        is_enabled = ?,
                        updated_at = ?
                    WHERE rule_type = ? AND value = ?
                    """,
                    (
                        note,
                        category,
                        confidence,
                        is_enabled,
                        now,
                        kind,
                        normalized,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE whitelist_rules
                    SET note = ?,
                        is_enabled = ?,
                        updated_at = ?
                    WHERE rule_type = ? AND value = ?
                    """,
                    (
                        note,
                        is_enabled,
                        now,
                        kind,
                        normalized,
                    ),
                )
            conn.commit()
            return normalized

        if {"category", "confidence", "last_seen_at"}.issubset(columns):
            conn.execute(
                """
                UPDATE whitelist_rules
                SET note = ?,
                    source = ?,
                    category = ?,
                    confidence = ?,
                    is_enabled = ?,
                    updated_at = ?
                WHERE rule_type = ? AND value = ?
                """,
                (
                    note,
                    source,
                    category,
                    confidence,
                    is_enabled,
                    now,
                    kind,
                    normalized,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE whitelist_rules
                SET note = ?,
                    source = ?,
                    is_enabled = ?,
                    updated_at = ?
                WHERE rule_type = ? AND value = ?
                """,
                (
                    note,
                    source,
                    is_enabled,
                    now,
                    kind,
                    normalized,
                ),
            )
        conn.commit()

    return normalized


def remove_item(kind: str, value: str, force: bool = False) -> str:
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"Unknown kind: {kind}")

    ensure_db()
    normalized = normalize_value(kind, value)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT source
            FROM whitelist_rules
            WHERE rule_type = ? AND value = ?
            """,
            (kind, normalized),
        ).fetchone()

        if row is None:
            raise ValueError(f"Whitelist entry not found: {kind} {normalized}")

        source = str(row["source"] or "user").strip().lower()
        if source != "user" and not force:
            raise PermissionError(f"Only user entries can be removed. Current source: {source}")

        if force:
            conn.execute(
                "DELETE FROM whitelist_rules WHERE rule_type = ? AND value = ?",
                (kind, normalized),
            )
        else:
            conn.execute(
                "DELETE FROM whitelist_rules WHERE rule_type = ? AND value = ? AND source = 'user'",
                (kind, normalized),
            )
        conn.commit()

    return normalized


def update_item(
    kind: str,
    value: str,
    note: str | None = None,
    source: str | None = None,
    category: str | None = None,
    confidence: float | None = None,
    is_enabled: int | None = None,
) -> str:
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"Unknown kind: {kind}")

    ensure_db()
    normalized = normalize_value(kind, value)

    with sqlite3.connect(DB_PATH) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(whitelist_rules)").fetchall()}

        fields = []
        params = []

        if note is not None:
            fields.append("note = ?")
            params.append(note.strip())

        if source is not None:
            fields.append("source = ?")
            params.append(normalize_source(source))

        if category is not None and "category" in columns:
            fields.append("category = ?")
            params.append(normalize_category(category))

        if confidence is not None and "confidence" in columns:
            fields.append("confidence = ?")
            params.append(float(confidence))

        if is_enabled is not None:
            fields.append("is_enabled = ?")
            params.append(normalize_enabled(is_enabled))

        fields.append("updated_at = ?")
        params.append(utc_now_iso())

        if not fields:
            return normalized

        params.extend([kind, normalized])
        conn.execute(
            f"""
            UPDATE whitelist_rules
            SET {", ".join(fields)}
            WHERE rule_type = ? AND value = ?
            """,
            params,
        )
        conn.commit()

    return normalized


def get_item(kind: str, value: str) -> dict | None:
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"Unknown kind: {kind}")

    ensure_db()
    normalized = normalize_value(kind, value)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT *
            FROM whitelist_rules
            WHERE rule_type = ? AND value = ?
            """,
            (kind, normalized),
        ).fetchone()

    if not row:
        return None

    return enrich_item_with_resolution(dict(row))




def list_items(
    include_disabled: bool = False,
    limit: int | None = None,
    offset: int = 0,
    source: str = "",
    category: str = "",
    kind: str = "",
    keyword: str = "",
) -> list[dict]:
    ensure_db()

    sql = """
        SELECT id, rule_type, value, note, source, category, confidence, is_enabled, created_at, updated_at, last_seen_at
        FROM whitelist_rules
        WHERE 1 = 1
    """
    params: list = []

    if not include_disabled:
        sql += " AND is_enabled = 1"

    if source:
        sql += " AND source = ?"
        params.append(normalize_source(source))

    if category:
        sql += " AND category = ?"
        params.append(normalize_category(category))

    if kind:
        normalized_kind = kind.strip().lower()
        if normalized_kind not in ALLOWED_KINDS:
            raise ValueError(f"Unknown kind: {kind}")
        sql += " AND rule_type = ?"
        params.append(normalized_kind)

    if keyword:
        keyword_like = f"%{keyword.strip()}%"
        sql += " AND (value LIKE ? OR note LIKE ?)"
        params.extend([keyword_like, keyword_like])

    sql += " ORDER BY updated_at DESC, id DESC"

    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params.extend([int(limit), max(int(offset), 0)])

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()

    return [enrich_item_with_resolution(dict(row)) for row in rows]


def fetch_exact_ip_record(ip: str, include_disabled: bool = False) -> dict | None:
    ensure_db()
    normalized_ip = validate_ip(ip)
    sql = """
        SELECT id, rule_type, value, note, source, category, confidence, is_enabled, created_at, updated_at, last_seen_at
        FROM whitelist_rules
        WHERE rule_type = 'ip' AND value = ?
    """
    params: list = [normalized_ip]

    if not include_disabled:
        sql += " AND is_enabled = 1"

    sql += " ORDER BY updated_at DESC, id DESC LIMIT 1"

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(sql, params).fetchone()

    return enrich_item_with_resolution(dict(row)) if row else None


def load_cidr_records(include_disabled: bool = False) -> list[dict]:
    ensure_db()
    sql = """
        SELECT id, rule_type, value, note, source, category, confidence, is_enabled, created_at, updated_at, last_seen_at
        FROM whitelist_rules
        WHERE rule_type = 'cidr'
    """

    if not include_disabled:
        sql += " AND is_enabled = 1"

    sql += " ORDER BY updated_at DESC, id DESC"

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()

    return [enrich_item_with_resolution(dict(row)) for row in rows]


def _ip_to_bitstring(ip: str) -> str:
    ip_obj = ipaddress.ip_address(validate_ip(ip))
    if ip_obj.version != 4:
        raise ValueError("Only IPv4 is currently supported for prefix-tree matching")
    return format(int(ip_obj), "032b")


def build_cidr_prefix_tree(records: list[dict]) -> dict:
    root: dict = {"children": {}, "records": []}

    for record in records:
        network = ipaddress.ip_network(record["value"], strict=False)
        if network.version != 4:
            continue

        bits = format(int(network.network_address), "032b")[: network.prefixlen]
        node = root
        for bit in bits:
            children = node.setdefault("children", {})
            node = children.setdefault(bit, {"children": {}, "records": []})
        node.setdefault("records", []).append(record)

    return root


def search_ip_in_prefix_tree(ip: str, tree: dict) -> list[dict]:
    bits = _ip_to_bitstring(ip)
    node = tree
    matches: list[dict] = list(node.get("records", []))

    for bit in bits:
        children = node.get("children", {})
        if bit not in children:
            break
        node = children[bit]
        if node.get("records"):
            matches.extend(node["records"])

    matches.sort(
        key=lambda item: (
            ipaddress.ip_network(item["value"], strict=False).prefixlen,
            item["updated_at"],
        ),
        reverse=True,
    )
    return matches


def match_ip_rules(ip: str, include_disabled: bool = False) -> dict:
    exact = fetch_exact_ip_record(ip, include_disabled=include_disabled)
    cidr_records = load_cidr_records(include_disabled=include_disabled)
    tree = build_cidr_prefix_tree(cidr_records)
    cidr_matches = search_ip_in_prefix_tree(ip, tree)

    return {
        "query_ip": validate_ip(ip),
        "exact_ip_match": exact,
        "cidr_match_count": len(cidr_matches),
        "cidr_matches": cidr_matches,
        "best_cidr_match": cidr_matches[0] if cidr_matches else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", required=True, choices=["add", "remove", "list", "update", "get", "match"])
    parser.add_argument("--kind", choices=["host", "ip", "ip_port", "cidr"])
    parser.add_argument("--value", default="")
    parser.add_argument("--query-ip", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--source", default="user")
    parser.add_argument("--category", default="general")
    parser.add_argument("--confidence", type=float, default=1.0)
    parser.add_argument("--enabled", default=None)
    parser.add_argument("--include-disabled", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--filter-source", default="")
    parser.add_argument("--filter-category", default="")
    parser.add_argument("--filter-kind", default="")
    parser.add_argument("--keyword", default="")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        if args.action == "match":
            if not args.query_ip:
                raise ValueError("--query-ip is required for action=match")
            result = match_ip_rules(args.query_ip, include_disabled=args.include_disabled)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return
        if args.action == "list":
            items = list_items(
                include_disabled=args.include_disabled,
                limit=args.limit,
                offset=args.offset,
                source=args.filter_source,
                category=args.filter_category,
                kind=args.filter_kind,
                keyword=args.keyword,
            )
            print(json.dumps(items, ensure_ascii=False, indent=2))
            return

        if not args.kind:
            raise ValueError("--kind is required for this action")
        if args.action in {"add", "remove", "update", "get"} and not args.value.strip():
            raise ValueError("--value is required for this action")

        if args.action == "add":
            add_item(
                kind=args.kind,
                value=args.value,
                note=args.note,
                source=args.source,
                category=args.category,
                confidence=args.confidence,
                is_enabled=1 if args.enabled is None else args.enabled,
            )
            item = get_item(args.kind, args.value)
            print(json.dumps(item, ensure_ascii=False, indent=2))
            return

        if args.action == "remove":
            normalized = remove_item(args.kind, args.value, force=args.force)
            if args.force:
                print(f"Force removed {args.kind}: {normalized}")
            else:
                print(f"Removed {args.kind}: {normalized}")
            return

        if args.action == "update":
            normalized = update_item(
                kind=args.kind,
                value=args.value,
                note=None if args.note == "" else args.note,
                source=None if args.source == "user" else args.source,
                category=None if args.category == "general" else args.category,
                confidence=None if args.confidence == 1.0 else args.confidence,
                is_enabled=args.enabled,
            )
            item = get_item(args.kind, normalized)
            print(json.dumps(item, ensure_ascii=False, indent=2))
            return

        if args.action == "get":
            item = get_item(args.kind, args.value)
            print(json.dumps(item, ensure_ascii=False, indent=2))
            return

    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()