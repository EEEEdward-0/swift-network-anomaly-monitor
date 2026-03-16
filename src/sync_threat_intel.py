import argparse
import html
import re
import sqlite3
from typing import Iterable

import requests

from manage_whitelist import DB_PATH, add_item, ensure_db

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SEED_DIR = BASE_DIR / "data" / "seeds"
SEED_DIR.mkdir(parents=True, exist_ok=True)

CHNROUTES_OPTIMIZED_LOCAL = SEED_DIR / "chnroutes2.txt"
CHNROUTES_DAILY_LOCAL = SEED_DIR / "chnroutes_daily.txt"

IPCN_DNS_URL = "https://www.ip.cn/dns.html"
IPCN_DNS_CACHE = SEED_DIR / "ipcn_dns.html"

def download_to_file(url: str, file_path: Path, timeout: int = 20) -> Path:
    response = direct_get(url, timeout=timeout)
    response.raise_for_status()
    file_path.write_text(response.text, encoding="utf-8")
    return file_path


def load_local_lines(file_path: Path) -> list[str]:
    return [
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_local_text(file_path: Path) -> str:
    return file_path.read_text(encoding="utf-8")


def fetch_dns_html(url: str = IPCN_DNS_URL, cache_path: Path = IPCN_DNS_CACHE) -> tuple[str, str]:
    try:
        download_to_file(url, cache_path, timeout=30)
        return load_local_text(cache_path), "network"
    except Exception:
        if cache_path.exists():
            return load_local_text(cache_path), "cache"
        raise


def extract_text_lines(page_html: str) -> list[str]:
    text = re.sub(r"<script[\s\S]*?</script>", "\n", page_html, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "\n", text)
    text = html.unescape(text)
    return [line.strip() for line in text.splitlines() if line.strip()]




# Robust parser for locally saved view-source HTML files from ip.cn/dns.html
def parse_ipcn_dns_records(page_html: str) -> list[dict[str, str]]:
    rows = re.findall(r"<tr[^>]*>([\s\S]*?)</tr>", page_html, flags=re.IGNORECASE)
    records: list[dict[str, str]] = []
    current_name = ""
    current_category = "public_dns"

    for row_html in rows:
        cells = re.findall(r"<td[^>]*>([\s\S]*?)</td>", row_html, flags=re.IGNORECASE)
        if not cells:
            continue

        normalized_cells: list[str] = []
        for cell in cells:
            cell_text = re.sub(r"<br\s*/?>", " / ", cell, flags=re.IGNORECASE)
            cell_text = re.sub(r"<[^>]+>", "", cell_text)
            cell_text = html.unescape(cell_text).strip()
            if cell_text:
                normalized_cells.append(cell_text)

        if not normalized_cells:
            continue

        joined = " | ".join(normalized_cells)
        if "电信" in joined and "DNS" in joined:
            current_category = "china_telecom_dns"
        elif "联通" in joined and "DNS" in joined:
            current_category = "china_unicom_dns"
        elif "移动" in joined and "DNS" in joined:
            current_category = "china_mobile_dns"
        elif "公共" in joined and "DNS" in joined:
            current_category = "public_dns"

        ips: list[str] = []
        label_candidates: list[str] = []

        for cell_text in normalized_cells:
            found_ips = IPV4_RE.findall(cell_text)
            if found_ips:
                ips.extend(found_ips)
            else:
                label_candidates.append(cell_text)

        if label_candidates:
            current_name = label_candidates[0]

        if not current_name or not ips:
            continue

        for ip in ips:
            records.append(
                {
                    "ip": ip,
                    "name": current_name,
                    "category": current_category,
                }
            )

    deduplicated: dict[str, dict[str, str]] = {}
    for record in records:
        ip = record["ip"]
        existing = deduplicated.get(ip)
        if existing is None:
            deduplicated[ip] = record
            continue

        if existing.get("category") != "public_dns" and record.get("category") == "public_dns":
            deduplicated[ip] = record

    return sorted(deduplicated.values(), key=lambda item: item["ip"])


def build_combined_dns_records() -> tuple[list[dict[str, str]], str]:
    combined: dict[str, dict[str, str]] = {
        item["ip"]: dict(item) for item in DNS_SEED_RECORDS
    }
    dns_source = "embedded"

    try:
        page_html, fetched_from = fetch_dns_html()
        page_records = parse_ipcn_dns_records(page_html)
        dns_source = fetched_from

        for item in page_records:
            ip = item["ip"]
            existing = combined.get(ip)
            if existing is None:
                combined[ip] = item
            elif existing.get("category") != "public_dns" and item.get("category") == "public_dns":
                combined[ip] = item
    except Exception:
        pass

    return sorted(combined.values(), key=lambda item: item["ip"]), dns_source


def direct_get(url: str, timeout: int = 20) -> requests.Response:
    session = requests.Session()
    return session.get(url, timeout=(10, max(timeout, 60)), allow_redirects=True)


CHNROUTES_OPTIMIZED_URL = "https://raw.githubusercontent.com/ym/chnroutes2/master/chnroutes.txt"
CHNROUTES_DAILY_URL = "https://www.ip.cn/rt/chnroutes.txt"
CIDR_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s*$")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECTION_HEADER_RE = re.compile(r"^全国各地(.+?)\s+DNS\s+服务器\s+IP\s+地址$")

DNS_SEED_RECORDS = [
    {"ip": "8.8.8.8", "name": "GoogleDNS", "category": "public_dns"},
    {"ip": "8.8.4.4", "name": "GoogleDNS", "category": "public_dns"},
    {"ip": "1.1.1.1", "name": "CloudflareDNS", "category": "public_dns"},
    {"ip": "1.0.0.1", "name": "CloudflareDNS", "category": "public_dns"},
    {"ip": "223.5.5.5", "name": "阿里云DNS", "category": "public_dns"},
    {"ip": "223.6.6.6", "name": "阿里云DNS", "category": "public_dns"},
    {"ip": "119.29.29.29", "name": "DNSPod DNS+", "category": "public_dns"},
    {"ip": "114.114.114.114", "name": "114DNS", "category": "public_dns"},
    {"ip": "114.114.115.115", "name": "114DNS", "category": "public_dns"},
    {"ip": "9.9.9.9", "name": "Quad9DNS", "category": "public_dns"},
]


def get_existing_rule(kind: str, value: str) -> dict[str, str] | None:
    ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT rule_type, value, note, source, category, confidence, is_enabled
            FROM whitelist_rules
            WHERE rule_type = ? AND value = ?
            """,
            (kind, value),
        ).fetchone()

    if row is None:
        return None

    return {key: str(row[key]) if row[key] is not None else "" for key in row.keys()}


def upsert_rule_with_status(
    kind: str,
    value: str,
    note: str,
    source: str,
    category: str,
    confidence: float,
    is_enabled: int,
) -> str:
    existing = get_existing_rule(kind, value)

    normalized_confidence = f"{float(confidence):.2f}"
    normalized_enabled = str(int(is_enabled))

    if existing is None:
        add_item(
            kind=kind,
            value=value,
            note=note,
            source=source,
            category=category,
            confidence=confidence,
            is_enabled=is_enabled,
        )
        return "inserted"

    if (
        existing.get("note", "") == note
        and existing.get("source", "") == source
        and existing.get("category", "") == category
        and existing.get("confidence", "") == normalized_confidence
        and existing.get("is_enabled", "") == normalized_enabled
    ):
        return "unchanged"

    add_item(
        kind=kind,
        value=value,
        note=note,
        source=source,
        category=category,
        confidence=confidence,
        is_enabled=is_enabled,
    )
    return "updated"


def parse_cidr_records(lines: Iterable[str], source_name: str, category: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = CIDR_RE.match(line)
        if not match:
            continue

        records.append(
            {
                "value": match.group(1),
                "name": source_name,
                "category": category,
            }
        )

    deduplicated: dict[str, dict[str, str]] = {}
    for record in records:
        deduplicated[record["value"]] = record

    return sorted(deduplicated.values(), key=lambda item: item["value"])


def sync_dns_records() -> dict[str, object]:
    records, dns_source = build_combined_dns_records()
    inserted = 0
    updated = 0
    unchanged = 0

    for record in records:
        ip = record["ip"]
        name = record["name"]
        category = record["category"]
        note = f"ip.cn dns seeded | {name}" if dns_source in {"network", "cache"} else f"dns seed file | {name}"

        status = upsert_rule_with_status(
            kind="ip",
            value=ip,
            note=note,
            source="system",
            category=category,
            confidence=0.95,
            is_enabled=1,
        )

        if status == "inserted":
            inserted += 1
        elif status == "updated":
            updated += 1
        else:
            unchanged += 1

    return {
        "records": records,
        "inserted": inserted,
        "updated": updated,
        "unchanged": unchanged,
        "total": len(records),
        "dns_source": dns_source,
    }


def sync_chnroutes_records(
    list_url: str,
    local_path: Path,
    source_name: str,
    category: str,
) -> dict[str, object]:
    download_to_file(list_url, local_path, timeout=20)

    lines = load_local_lines(local_path)
    records = parse_cidr_records(lines, source_name=source_name, category=category)

    inserted = 0
    updated = 0
    unchanged = 0

    for record in records:
        value = record["value"]
        name = record["name"]
        note = f"route list seeded | {name}"

        status = upsert_rule_with_status(
            kind="cidr",
            value=value,
            note=note,
            source="system",
            category=record["category"],
            confidence=0.95,
            is_enabled=1,
        )

        if status == "inserted":
            inserted += 1
        elif status == "updated":
            updated += 1
        else:
            unchanged += 1

    return {
        "records": records,
        "inserted": inserted,
        "updated": updated,
        "unchanged": unchanged,
        "total": len(records),
        "local_path": str(local_path),
    }


def safe_sync_chnroutes_records(
    list_url: str,
    local_path: Path,
    source_name: str,
    category: str,
) -> dict[str, object]:
    try:
        return sync_chnroutes_records(
            list_url,
            local_path,
            source_name=source_name,
            category=category,
        )
    except Exception as exc:
        return {
            "records": [],
            "inserted": 0,
            "updated": 0,
            "unchanged": 0,
            "total": 0,
            "error": str(exc),
            "source_name": source_name,
            "list_url": list_url,
        }


def sync_all_sources() -> dict[str, dict[str, object]]:
    return {
        "dns": sync_dns_records(),
        "chnroutes_optimized": safe_sync_chnroutes_records(
            CHNROUTES_OPTIMIZED_URL,
            CHNROUTES_OPTIMIZED_LOCAL,
            source_name="chnroutes2 optimized",
            category="china_mainland_routes",
        ),
        "chnroutes_daily": safe_sync_chnroutes_records(
            CHNROUTES_DAILY_URL,
            CHNROUTES_DAILY_LOCAL,
            source_name="ip.cn chnroutes daily",
            category="china_mainland_routes",
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["dns", "chnroutes_optimized", "chnroutes_daily", "all"],
        default="all",
    )
    parser.add_argument("--url", default="")
    args = parser.parse_args()

    if args.mode == "dns":
        result = sync_dns_records()
        print(f"Seeded {result['total']} DNS IP entries from {result['dns_source']}")
        print(f"inserted={result['inserted']} updated={result['updated']} unchanged={result['unchanged']}")
        if int(result["inserted"]) == 0 and int(result["updated"]) == 0:
            print("当前IP库已是最新")
        for record in list(result["records"])[:20]:
            print(record)
        return

    if args.mode == "chnroutes_optimized":
        list_url = args.url or CHNROUTES_OPTIMIZED_URL
        result = safe_sync_chnroutes_records(
            list_url,
            CHNROUTES_OPTIMIZED_LOCAL,
            source_name="chnroutes2 optimized",
            category="china_mainland_routes",
        )
        if result.get("error"):
            print(f"Sync failed for {list_url}")
            print(result["error"])
            return
        print(f"Seeded {result['total']} mainland route entries from {list_url}")
        print(f"inserted={result['inserted']} updated={result['updated']} unchanged={result['unchanged']}")
        if int(result["inserted"]) == 0 and int(result["updated"]) == 0:
            print("当前IP库已是最新")
        for record in list(result["records"])[:20]:
            print(record)
        return

    if args.mode == "chnroutes_daily":
        list_url = args.url or CHNROUTES_DAILY_URL
        result = safe_sync_chnroutes_records(
            list_url,
            CHNROUTES_DAILY_LOCAL,
            source_name="ip.cn chnroutes daily",
            category="china_mainland_routes",
        )
        if result.get("error"):
            print(f"Sync failed for {list_url}")
            print(result["error"])
            return
        print(f"Seeded {result['total']} mainland route entries from {list_url}")
        print(f"inserted={result['inserted']} updated={result['updated']} unchanged={result['unchanged']}")
        if int(result["inserted"]) == 0 and int(result["updated"]) == 0:
            print("当前IP库已是最新")
        for record in list(result["records"])[:20]:
            print(record)
        return

    results = sync_all_sources()
    total_inserted = sum(int(item["inserted"]) for item in results.values())
    total_updated = sum(int(item["updated"]) for item in results.values())
    errors = {
        key: item.get("error", "")
        for key, item in results.items()
        if item.get("error", "")
    }

    print(f"Seeded {results['dns']['total']} DNS IP entries from {results['dns']['dns_source']}")
    print(
        f"DNS inserted={results['dns']['inserted']} updated={results['dns']['updated']} unchanged={results['dns']['unchanged']}"
    )
    print(f"Seeded {results['chnroutes_optimized']['total']} mainland route entries from {CHNROUTES_OPTIMIZED_URL}")
    print(
        "Optimized routes "
        f"inserted={results['chnroutes_optimized']['inserted']} "
        f"updated={results['chnroutes_optimized']['updated']} "
        f"unchanged={results['chnroutes_optimized']['unchanged']}"
    )
    print(f"Seeded {results['chnroutes_daily']['total']} mainland route entries from {CHNROUTES_DAILY_URL}")
    print(
        "Daily routes "
        f"inserted={results['chnroutes_daily']['inserted']} "
        f"updated={results['chnroutes_daily']['updated']} "
        f"unchanged={results['chnroutes_daily']['unchanged']}"
    )

    for key, message in errors.items():
        print(f"{key} sync failed: {message}")

    if total_inserted == 0 and total_updated == 0 and not errors:
        print("当前IP库已是最新")


if __name__ == "__main__":
    main()