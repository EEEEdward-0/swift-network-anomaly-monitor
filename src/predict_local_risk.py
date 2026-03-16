# predict_local_risk.py
# Combine anomaly scores and heuristic rules into final local risk results.
# Supports local subnet detection, LAN traffic filtering, and endpoint enrichment.

from pathlib import Path
import argparse
import ipaddress
import json
import re
import socket
import subprocess
from urllib import request
import numpy as np
import pandas as pd
import sqlite3

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
LOCAL_ANALYSIS_DIR = REPORTS_DIR / "local_analysis"

INPUT_CSV = LOCAL_ANALYSIS_DIR / "local_flows_with_anomaly_score.csv"
OUTPUT_CSV = LOCAL_ANALYSIS_DIR / "local_risk_results.csv"
OUTPUT_JSON = LOCAL_ANALYSIS_DIR / "local_risk_summary.json"


COMMON_PORTS = {
    53, 80, 123, 137, 138, 139, 443, 445, 5353, 853, 1900
}

COMMON_SERVICES = {
    "dns", "http", "https", "mdns", "ntp", "netbios"
}


LOCAL_DISCOVERY_SERVICES = {
    "mdns", "netbios"
}

IBM_DEFAULT_APP_PORTS = {
    51343: "Authentication",
    51346: "Authentication",
    51347: "Authentication",
    51348: "Authentication",
    21122: "Authentication",
    21140: "Authentication",
}

SENSITIVE_EXTERNAL_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate / Admin Web",
    8443: "HTTPS Alternate / Admin Web",
    9200: "Elasticsearch",
    5601: "Kibana",
    27017: "MongoDB",
}

EPHEMERAL_PORT_MIN = 49152

TRUSTED_HOST_SUFFIXES = {
    "alidns.com",
    "qq.com",
    "weixin.qq.com",
    "icloud.com",
    "apple.com",
    "mzstatic.com",
    "microsoft.com",
    "windowsupdate.com",
    "office.com",
    "live.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "amazonaws.com",
    "awsstatic.com",
}

TRUSTED_DNS_HOST_SUFFIXES = {
    "alidns.com",
    "cloudflare-dns.com",
    "dns.google",
}

TRUSTED_SERVICE_PORTS = {53, 80, 123, 443, 853}

WHITELIST_DB_PATH = PROJECT_ROOT / "data" / "app_state" / "trust_store.db"
# Optional user-maintained endpoint overrides.
# You can add trusted VPN servers or known services here.
KNOWN_ENDPOINTS = {
    "209.9.200.159": {
        "label": "Known VPN Server",
        "endpoint_type": "Trusted VPN Endpoint",
        "service_hint": "VPN / Secure Tunnel",
        "geo_label": "Known Remote Endpoint",
        "risk_cap": "Medium",
    },
}

# Simple in-memory caches to avoid repeated lookups.
_HOST_CACHE: dict[str, str] = {}
_GEO_CACHE: dict[str, str] = {}


def normalize_scores(values: pd.Series) -> pd.Series:
    # Normalize scores to 0-1 range.
    vmin = float(values.min())
    vmax = float(values.max())
    if vmax - vmin < 1e-12:
        return pd.Series(np.zeros(len(values)), index=values.index)
    return (values - vmin) / (vmax - vmin)



def build_thresholds(df: pd.DataFrame):
    # Use empirical quantiles as adaptive thresholds.
    return {
        "bytes_per_second_p95": float(df["bytes_per_second"].quantile(0.95)),
        "packets_per_second_p95": float(df["packets_per_second"].quantile(0.95)),
        "duration_p95": float(df["duration"].quantile(0.95)),
        "rst_count_p95": float(df["tcp_rst_count"].quantile(0.95)),
        "syn_count_p95": float(df["tcp_syn_count"].quantile(0.95)),
    }


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_private_local_flow(row: pd.Series) -> bool:
    src_ip = str(row.get("src_ip", ""))
    dst_ip = str(row.get("dst_ip", ""))
    return is_private_ip(src_ip) and is_private_ip(dst_ip)



def is_ephemeral_port(port: int) -> bool:
    return port >= EPHEMERAL_PORT_MIN


def load_user_whitelist() -> dict:
    if not WHITELIST_DB_PATH.exists():
        return {"hosts": [], "ips": [], "ip_ports": [], "records": []}

    result = {"hosts": [], "ips": [], "ip_ports": [], "records": []}

    try:
        with sqlite3.connect(WHITELIST_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT *
                FROM whitelist_rules
                WHERE is_enabled = 1
                ORDER BY rule_type ASC, value ASC
                """
            ).fetchall()

        for row in rows:
            item = dict(row)
            result["records"].append(item)

            if item["rule_type"] == "host":
                result["hosts"].append(item["value"])
            elif item["rule_type"] == "ip":
                result["ips"].append(item["value"])
            elif item["rule_type"] == "ip_port":
                result["ip_ports"].append(item["value"])

        return result
    except Exception:
        return {"hosts": [], "ips": [], "ip_ports": [], "records": []}


def try_reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.strip().lower()
    except Exception:
        return ""


def normalize_host(value: str) -> str:
    return str(value or "").strip().lower()


def host_matches_suffix(host: str, suffixes: set[str]) -> bool:
    host = normalize_host(host)
    if not host or host == "unresolved":
        return False
    return any(host == suffix or host.endswith("." + suffix) for suffix in suffixes)


def is_user_whitelisted(dst_ip: str, dst_port: int, resolved_host: str, whitelist: dict) -> bool:
    host = normalize_host(resolved_host)
    
def get_whitelist_match(dst_ip: str, dst_port: int, resolved_host: str, whitelist: dict) -> dict | None:
    host = normalize_host(resolved_host)
    ip_port_key = f"{dst_ip}:{dst_port}"

    for item in whitelist.get("records", []):
        rule_type = str(item.get("rule_type", ""))
        value = str(item.get("value", ""))
        if rule_type == "ip" and value == dst_ip:
            return item
        if rule_type == "ip_port" and value == ip_port_key:
            return item
        if rule_type == "host" and (host == value or host.endswith("." + value)):
            return item

    return None


def whitelist_score_delta(match: dict | None) -> float:
    if not match:
        return 0.0

    source = str(match.get("source", "user")).lower()
    confidence = float(match.get("confidence", 1.0))

    if source == "user":
        return 2.5 * confidence
    if source == "system":
        return 1.5 * confidence
    if source == "api":
        return 1.0 * confidence

    return 1.0 * confidence
    if dst_ip in set(whitelist.get("ips", [])):
        return True

    ip_port_key = f"{dst_ip}:{dst_port}"
    if ip_port_key in set(whitelist.get("ip_ports", [])):
        return True

    for item in whitelist.get("hosts", []):
        item = normalize_host(item)
        if not item:
            continue
        if host == item or host.endswith("." + item):
            return True

    return False


def is_trusted_public_infra(resolved_host: str, dst_port: int) -> bool:
    host = normalize_host(resolved_host)
    if not host or host == "unresolved":
        return False

    if host_matches_suffix(host, TRUSTED_DNS_HOST_SUFFIXES) and dst_port in {53, 853, 443}:
        return True

    if host_matches_suffix(host, TRUSTED_HOST_SUFFIXES) and dst_port in TRUSTED_SERVICE_PORTS:
        return True

    return False


def classify_network_scope(row):
    # Classify traffic direction by private/public properties.
    src_private = int(row["src_is_private"])
    dst_private = int(row["dst_is_private"])

    if src_private == 1 and dst_private == 1:
        return "private_to_private"
    if src_private == 1 and dst_private == 0:
        return "private_to_public"
    if src_private == 0 and dst_private == 1:
        return "public_to_private"
    return "public_to_public"


def is_broadcast_or_multicast(ip: str) -> bool:
    # Detect IPv4 broadcast or multicast, and IPv6 multicast.
    try:
        addr = ipaddress.ip_address(ip)

        if addr.version == 4:
            if str(addr).endswith(".255"):
                return True
            if addr.is_multicast:
                return True

        if addr.version == 6 and addr.is_multicast:
            return True

        return False
    except ValueError:
        return False


def detect_local_subnet(interface: str) -> str | None:
    # Detect the local subnet from a macOS interface using ipconfig + ifconfig.
    try:
        ip_result = subprocess.run(
            ["ipconfig", "getifaddr", interface],
            capture_output=True,
            text=True,
            check=True,
        )
        ip_addr = ip_result.stdout.strip()

        ifconfig_result = subprocess.run(
            ["ifconfig", interface],
            capture_output=True,
            text=True,
            check=True,
        )
        text = ifconfig_result.stdout

        match = re.search(r"netmask\s+0x([0-9a-fA-F]+)", text)
        if not match:
            return None

        mask_hex = match.group(1)
        mask_int = int(mask_hex, 16)
        mask_str = str(ipaddress.IPv4Address(mask_int))

        network = ipaddress.IPv4Network(f"{ip_addr}/{mask_str}", strict=False)
        return str(network)

    except Exception:
        return None


def ip_in_subnet(ip: str, subnet: str | None) -> int:
    # Check whether an IP belongs to the detected or user-provided local subnet.
    if not subnet:
        return 0

    try:
        addr = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(subnet, strict=False)
        return int(addr in net)
    except ValueError:
        return 0


def apply_rules(row: pd.Series, thresholds: dict):
    # Apply heuristic rules and return score + reasons.
    score = 0
    reasons = []

    dst_port = int(row["dst_port"])
    src_port = int(row["src_port"])
    service = str(row["service"])
    network_scope = str(row.get("network_scope", ""))
    dst_ip = str(row.get("dst_ip", ""))

    known_ibm_app = dst_port in IBM_DEFAULT_APP_PORTS
    sensitive_external_port = dst_port in SENSITIVE_EXTERNAL_PORTS
    private_local_flow = is_private_local_flow(row)
    ephemeral_src_port = is_ephemeral_port(src_port)
    ephemeral_dst_port = is_ephemeral_port(dst_port)

    # Rule 1: rare port or rare service
    # Do not flag known IBM default application ports as rare.
    # Do not flag private-network ephemeral ports as rare by themselves.
    if not known_ibm_app:
        is_generic_other = service in {"tcp_other", "udp_other"}
        is_unknown_service = service not in COMMON_SERVICES and not is_generic_other
        uncommon_ports = dst_port not in COMMON_PORTS and src_port not in COMMON_PORTS

        if uncommon_ports and is_unknown_service:
            if private_local_flow and ephemeral_dst_port:
                pass
            elif private_local_flow and ephemeral_src_port:
                pass
            else:
                score += 1
                reasons.append("Rare port/service")

    # Rule 1b: known IBM application ports
    if known_ibm_app:
        reasons.append(f"Known application port: {IBM_DEFAULT_APP_PORTS[dst_port]}")

    # Rule 1c: external access to sensitive service ports
    if sensitive_external_port and network_scope in {"private_to_public", "public_to_private", "public_to_public"}:
        score += 1
        reasons.append("External access to sensitive service port")

    # Rule 2: high throughput
    if float(row["bytes_per_second"]) > thresholds["bytes_per_second_p95"]:
        score += 2
        reasons.append("High bytes per second")

    if float(row["packets_per_second"]) > thresholds["packets_per_second_p95"]:
        score += 1
        reasons.append("High packets per second")

    # Rule 3: unusually long flow
    if float(row["duration"]) > thresholds["duration_p95"]:
        score += 1
        reasons.append("Long-lived connection")

    # Rule 4: heavily one-sided traffic
    a_ratio = float(row["a_to_b_packet_ratio"])
    b_ratio = float(row["b_to_a_packet_ratio"])
    total_packets = float(row["total_packets"])

    if total_packets >= 10 and (a_ratio >= 0.95 or b_ratio >= 0.95):
        score += 1
        reasons.append("Highly unidirectional traffic")

    # Rule 5: suspicious TCP flag pattern
    if float(row["tcp_rst_count"]) > thresholds["rst_count_p95"]:
        score += 2
        reasons.append("High TCP reset count")

    if (
        float(row["tcp_syn_count"]) > thresholds["syn_count_p95"]
        and float(row["tcp_ack_count"]) <= 1
    ):
        score += 2
        reasons.append("High SYN with low ACK")

    # Rule 6: private to public uncommon connection
    if network_scope == "private_to_public":
        if not known_ibm_app and dst_port not in COMMON_PORTS and service in {
            "tcp_other",
            "udp_other",
            "custom_tcp_6000",
            "custom_tcp_6001",
            "custom_tcp_6010",
            "custom_tcp_6011",
            "custom_tcp_7826",
        }:
            score += 2
            reasons.append("Uncommon private-to-public connection")

    return score, reasons


def apply_local_context_downweighting(row: pd.Series, score: float, reasons: list[str]):
    # Reduce false positives for benign LAN discovery / broadcast / multicast traffic.
    dst_ip = str(row["dst_ip"])
    service = str(row["service"])
    network_scope = str(row["network_scope"])
    both_in_local_subnet = int(row.get("both_in_local_subnet", 0))
    dst_port = int(row["dst_port"])
    src_port = int(row["src_port"])
    private_local_flow = is_private_local_flow(row)

    downweight_reasons = []

    if is_broadcast_or_multicast(dst_ip):
        score -= 1.0
        downweight_reasons.append("Broadcast/multicast destination")

    if both_in_local_subnet == 1 and service in LOCAL_DISCOVERY_SERVICES:
        score -= 1.0
        downweight_reasons.append("Local discovery service")

    if both_in_local_subnet == 1 and dst_port in {5353, 137, 138, 139, 1900}:
        score -= 1.0
        downweight_reasons.append("Typical LAN discovery port")

    if network_scope == "private_to_private" and both_in_local_subnet == 1 and service in {"tcp_other", "udp_other"}:
        score -= 0.5
        downweight_reasons.append("Local subnet internal traffic")

    if private_local_flow and dst_port in IBM_DEFAULT_APP_PORTS:
        score -= 1.0
        downweight_reasons.append("Known private-network application port")

    if private_local_flow and is_ephemeral_port(dst_port):
        score -= 1.0
        downweight_reasons.append("Private-network ephemeral destination port")

    if private_local_flow and is_ephemeral_port(src_port):
        score -= 0.5
        downweight_reasons.append("Private-network ephemeral source port")

    score = max(score, 0.0)

    if downweight_reasons:
        reasons.extend(downweight_reasons)

    return score, reasons


def determine_risk_level(final_score: float):
    # Map score to risk label.
    if final_score >= 2.4:
        return "High"
    if final_score >= 1.2:
        return "Medium"
    return "Low"


def filter_by_scope(df: pd.DataFrame, scope: str):
    # Filter traffic according to user-selected scope.
    if scope == "all":
        return df.copy()

    if scope == "exclude_lan":
        return df[df["both_in_local_subnet"] == 0].copy()

    if scope == "lan_only":
        return df[df["both_in_local_subnet"] == 1].copy()

    if scope == "external_only":
        return df[df["network_scope"].isin(["private_to_public", "public_to_private"])].copy()

    raise ValueError(f"Unsupported scope: {scope}")


def resolve_host(ip: str) -> str:
    # Try reverse DNS lookup with a small cache.
    if ip in _HOST_CACHE:
        return _HOST_CACHE[ip]

    fallback = try_reverse_dns(ip)
    if fallback:
        _HOST_CACHE[ip] = fallback
        return fallback

    _HOST_CACHE[ip] = "unresolved"
    return "unresolved"


def is_local_or_private_ip(ip: str) -> bool:
    # Detect private, loopback, link-local, multicast and reserved IPs.
    try:
        addr = ipaddress.ip_address(ip)
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


def resolve_geo_label(ip: str) -> str:
    # Resolve a coarse geographic label for public IPs.
    # China IPs are shown as country / city when available.
    # Non-China IPs are shown as country only.
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    if is_broadcast_or_multicast(ip):
        _GEO_CACHE[ip] = "Broadcast / Multicast"
        return _GEO_CACHE[ip]

    if is_local_or_private_ip(ip):
        _GEO_CACHE[ip] = "Local / Private Network"
        return _GEO_CACHE[ip]

    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            },
        )
        with request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        country = str(payload.get("country_name", "")).strip()
        country_code = str(payload.get("country_code", "")).strip().upper()
        city = str(payload.get("city", "")).strip()

        if country_code == "CN":
            parts = [x for x in [country, city] if x]
            label = " / ".join(parts) if parts else "China"
        else:
            label = country if country else "Public Network"

        _GEO_CACHE[ip] = label
        return label
    except Exception:
        _GEO_CACHE[ip] = "Public Network"
        return _GEO_CACHE[ip]


def infer_service_hint(row: pd.Series, resolved_host: str) -> str:
    # Infer a human-readable service hint.
    dst_ip = str(row["dst_ip"])
    dst_port = int(row["dst_port"])
    service = str(row["service"])
    proto = str(row["proto"])
    if dst_port in IBM_DEFAULT_APP_PORTS:
        return IBM_DEFAULT_APP_PORTS[dst_port]

    if host_matches_suffix(resolved_host, TRUSTED_DNS_HOST_SUFFIXES):
        if dst_port == 53:
            return "Public DNS"
        if dst_port == 853:
            return "DNS over TLS"
        if dst_port == 443:
            return "Encrypted DNS / HTTPS"

    if dst_port in SENSITIVE_EXTERNAL_PORTS:
        return SENSITIVE_EXTERNAL_PORTS[dst_port]
    if "vpn" in resolved_host.lower() or "tunnel" in resolved_host.lower() or "wireguard" in resolved_host.lower():
        return "VPN / Tunnel Endpoint"

    if is_broadcast_or_multicast(dst_ip):
        return "Broadcast / Multicast"

    if service == "mdns" or dst_port == 5353:
        return "Local Discovery (mDNS)"
    if service == "dns" or dst_port in {53, 853}:
        return "DNS / Encrypted DNS"
    if service == "https" or dst_port == 443:
        return "HTTPS / Encrypted Web"
    if service == "http" or dst_port in {80, 8080}:
        return "HTTP / Web Service"
    if service == "netbios" or dst_port in {137, 138, 139, 445}:
        return "Windows / NetBIOS / SMB"
    if "vpn" in resolved_host.lower() or "tunnel" in resolved_host.lower() or "wireguard" in resolved_host.lower():
        return "VPN / Tunnel Endpoint"
    if service in {"custom_tcp_6000", "custom_tcp_6001", "custom_tcp_6010", "custom_tcp_6011", "custom_tcp_7826"}:
        return "Custom TCP Service"
    if proto == "udp" and service == "udp_other":
        return "UDP Service"
    if proto == "tcp" and service == "tcp_other":
        return "TCP Service"

    return "Unknown / Other"


def infer_endpoint_type(row: pd.Series, resolved_host: str, service_hint: str) -> str:
    # Infer a simplified endpoint label for the UI.
    network_scope = str(row["network_scope"])
    both_in_local_subnet = int(row.get("both_in_local_subnet", 0))
    dst_ip = str(row["dst_ip"])
    known_override = KNOWN_ENDPOINTS.get(dst_ip)

    if known_override and "endpoint_type" in known_override:
        return str(known_override["endpoint_type"])
    if is_broadcast_or_multicast(dst_ip):
        return "Local Broadcast"
    if both_in_local_subnet == 1:
        return "LAN Device"
    if service_hint == "Authentication":
        return "Authentication Service"
    if "VPN" in service_hint:
        return "VPN Endpoint"
    if "Custom TCP Service" in service_hint:
        return "Custom External Service"
    if "DNS" in service_hint:
        return "DNS Service"
    if "HTTPS" in service_hint:
        return "External HTTPS"
    if network_scope == "private_to_public":
        return "External Service"
    if network_scope == "public_to_private":
        return "Inbound Response"
    return "Other Endpoint"


def apply_known_endpoint_overrides(row: pd.Series):
    # Override labels and risk for user-known trusted endpoints.
    dst_ip = str(row["dst_ip"])

    if dst_ip not in KNOWN_ENDPOINTS:
        return row

    config = KNOWN_ENDPOINTS[dst_ip]

    row["user_label"] = config.get("label", "")
    row["endpoint_type"] = config.get("endpoint_type", row["endpoint_type"])
    row["service_hint"] = config.get("service_hint", row["service_hint"])
    row["geo_label"] = config.get("geo_label", row["geo_label"])

    risk_cap = config.get("risk_cap")
    if risk_cap == "Medium" and row["risk_level"] == "High":
        row["risk_level"] = "Medium"
        row["reason"] = str(row["reason"]) + "; Known trusted endpoint"
    elif risk_cap == "Low":
        row["risk_level"] = "Low"
        row["reason"] = str(row["reason"]) + "; Known trusted endpoint"

    return row


def enrich_endpoint_info(df: pd.DataFrame):
    # Add reverse DNS, coarse geolocation and human-readable endpoint hints.
    unique_ips = df["dst_ip"].astype(str).unique().tolist()
    resolved_map = {ip: resolve_host(ip) for ip in unique_ips}
    geo_map = {ip: resolve_geo_label(ip) for ip in unique_ips}

    df["resolved_host"] = df["dst_ip"].astype(str).map(resolved_map)
    df["geo_label"] = df["dst_ip"].astype(str).map(geo_map)
    df["service_hint"] = df.apply(lambda row: infer_service_hint(row, str(row["resolved_host"])), axis=1)
    df["endpoint_type"] = df.apply(
        lambda row: infer_endpoint_type(row, str(row["resolved_host"]), str(row["service_hint"])),
        axis=1,
    )
    return df


def parse_args():
    parser = argparse.ArgumentParser(description="Predict local network risk with rules + anomaly scores.")
    parser.add_argument(
        "--interface",
        type=str,
        default="en0",
        help="Network interface used to auto-detect local subnet, default is en0.",
    )
    parser.add_argument(
        "--local-subnet",
        type=str,
        default=None,
        help="Optional manual local subnet, e.g. 192.168.11.0/24. Overrides auto detection.",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["all", "exclude_lan", "lan_only", "external_only"],
        default="all",
        help="Traffic scope filter.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"Missing input CSV: {INPUT_CSV}")

    df = pd.read_csv(INPUT_CSV)
    if df.empty:
        raise ValueError("Input CSV is empty.")

    # Rebuild network scope if missing.
    if "network_scope" not in df.columns:
        df["network_scope"] = df.apply(classify_network_scope, axis=1)

    # Detect local subnet.
    local_subnet = args.local_subnet
    if local_subnet is None:
        local_subnet = detect_local_subnet(args.interface)

    # Add local subnet membership fields.
    df["src_in_local_subnet"] = df["src_ip"].apply(lambda x: ip_in_subnet(str(x), local_subnet))
    df["dst_in_local_subnet"] = df["dst_ip"].apply(lambda x: ip_in_subnet(str(x), local_subnet))
    df["both_in_local_subnet"] = (
        (df["src_in_local_subnet"] == 1) & (df["dst_in_local_subnet"] == 1)
    ).astype(int)


    if df.empty:
        raise ValueError("No flows remain after applying the selected scope filter.")

    thresholds = build_thresholds(df)
    whitelist = load_user_whitelist()

    # Add endpoint enrichment before whitelist matching.
    df = enrich_endpoint_info(df)

    # Normalize anomaly score.
    df["anomaly_score_norm"] = normalize_scores(df["anomaly_score"])

    rule_scores = []
    reasons_all = []
    final_scores = []
    risk_levels = []

    for _, row in df.iterrows():
        resolved_host = str(row.get("resolved_host", "")).strip()
        if not resolved_host or resolved_host == "unresolved" or resolved_host == str(row.get("dst_ip", "")):
            fallback_host = try_reverse_dns(str(row.get("dst_ip", "")))
            if fallback_host:
                resolved_host = fallback_host

        rule_score, reasons = apply_rules(row, thresholds)
        rule_score, reasons = apply_local_context_downweighting(row, float(rule_score), reasons)

        dst_ip = str(row.get("dst_ip", ""))
        dst_port = int(row["dst_port"])

        whitelist_match = get_whitelist_match(dst_ip, dst_port, resolved_host, whitelist)
        trusted_infra = is_trusted_public_infra(resolved_host, dst_port)

        if whitelist_match:
           delta = whitelist_score_delta(whitelist_match)
           rule_score = max(rule_score - delta, 0.0)
           reasons.append(
        f"Whitelisted endpoint ({whitelist_match.get('source', 'user')}, {whitelist_match.get('rule_type', 'unknown')})"
    )
        elif trusted_infra:
            rule_score = max(rule_score - 1.5, 0.0)
            reasons.append("Trusted public infrastructure host")

        anomaly_component = float(row["anomaly_score_norm"]) * 2.0
        final_score = rule_score * 0.6 + anomaly_component * 0.4
        risk_level = determine_risk_level(final_score)

        if is_private_local_flow(row) and int(row["dst_port"]) in IBM_DEFAULT_APP_PORTS and risk_level == "High":
            risk_level = "Medium"
            reasons.append("Private-network known application downgraded from High")

        if is_private_local_flow(row) and is_ephemeral_port(int(row["dst_port"])) and risk_level == "High":
            risk_level = "Medium"
            reasons.append("Private-network ephemeral port downgraded from High")

        if trusted_infra and risk_level == "High":
            risk_level = "Medium"
            reasons.append("Downgraded because destination is trusted public infrastructure")

        if whitelist_match and risk_level == "High":
            risk_level = "Medium"
            reasons.append("Downgraded because endpoint is whitelisted")

        rule_scores.append(rule_score)
        reasons_all.append("; ".join(reasons) if reasons else "No heuristic trigger")
        final_scores.append(final_score)
        risk_levels.append(risk_level)

    df["rule_score"] = rule_scores
    df["reason"] = reasons_all
    df["final_risk_score"] = final_scores
    df["risk_level"] = risk_levels

    # Apply optional user-known endpoint overrides.
    df["user_label"] = ""
    df = df.apply(apply_known_endpoint_overrides, axis=1)

    df = df.sort_values(
        by=["final_risk_score", "anomaly_score"],
        ascending=[False, False]
    ).reset_index(drop=True)

    df.to_csv(OUTPUT_CSV, index=False)

    summary = {
        "input_csv": str(INPUT_CSV),
        "output_csv": str(OUTPUT_CSV),
        "num_flows": int(len(df)),
        "interface": args.interface,
        "local_subnet": local_subnet,
        "scope": args.scope,
        "risk_level_counts": df["risk_level"].value_counts(dropna=False).to_dict(),
        "ip_version_counts": df["ip_version"].value_counts(dropna=False).to_dict(),
        "geo_label_counts": df["geo_label"].value_counts(dropna=False).head(20).to_dict(),
        "endpoint_type_counts": df["endpoint_type"].value_counts(dropna=False).to_dict(),
        "service_counts": df["service_hint"].value_counts(dropna=False).to_dict(),
        "top_10_risk_scores": [float(x) for x in df["final_risk_score"].head(10).tolist()],
        "thresholds": thresholds,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("Local risk prediction finished.")
    print("Input:", INPUT_CSV)
    print("Output CSV:", OUTPUT_CSV)
    print("Output JSON:", OUTPUT_JSON)
    print("Interface:", args.interface)
    print("Detected local subnet:", local_subnet)
    print("Scope:", args.scope)
    print()
    print("Risk level counts:")
    print(df["risk_level"].value_counts(dropna=False))
    print()
    print("Top 10 suspicious flows:")
    print(
        df[
            [
                "ip_version",
                "src_ip",
                "dst_ip",
                "resolved_host",
                "geo_label",
                "service_hint",
                "endpoint_type",
                "user_label",
                "dst_port",
                "proto",
                "service",
                "network_scope",
                "anomaly_score",
                "rule_score",
                "final_risk_score",
                "risk_level",
                "reason",
            ]
        ].head(10)
    )


if __name__ == "__main__":
    main()