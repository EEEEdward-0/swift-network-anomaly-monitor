# get_host_summary.py
# Collect local host summary for the app home screen.

from pathlib import Path
import argparse
import json
import subprocess
from urllib import request
from urllib.parse import quote
import ipaddress
import re


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
LOCAL_ANALYSIS_DIR = REPORTS_DIR / "local_analysis"
LOCAL_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_JSON = LOCAL_ANALYSIS_DIR / "host_summary.json"


def run_command(
    cmd: list[str],
    check: bool = True,
    timeout: int = 5,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
        timeout=timeout,
    )


def get_local_ip(interface: str = "en0") -> str:
    try:
        result = run_command(["ipconfig", "getifaddr", interface])
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def get_local_ipv6(interface: str = "en0") -> str:
    try:
        result = run_command(["ifconfig", interface])
        candidates = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("inet6 "):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            addr = parts[1].split("%", 1)[0].strip()
            if not addr:
                continue
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj.is_link_local or ip_obj.is_loopback or ip_obj.is_multicast:
                    continue
                candidates.append(addr)
            except Exception:
                continue

        if candidates:
            return candidates[0]
    except Exception:
        pass
    return "unknown"


def is_ipv4_address(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except Exception:
        return False


def is_ipv6_address(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except Exception:
        return False


def is_global_ipv6_candidate(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
        if not isinstance(ip_obj, ipaddress.IPv6Address):
            return False
        return not (
            ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def get_public_ip(interface: str = "en0") -> str:
    urls = [
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
    ]
    for url in urls:
        try:
            req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with request.urlopen(req, timeout=2.0) as resp:
                value = resp.read().decode("utf-8", errors="replace").strip()
                if value and is_ipv4_address(value):
                    return value
        except Exception:
            continue

    curl_urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
    ]

    curl_cmds = [
        ["curl", "-4", "-fsL", "--connect-timeout", "2", "--max-time", "4"],
        ["curl", "-4", "--interface", interface, "-fsL", "--connect-timeout", "2", "--max-time", "4"],
    ]

    for base_cmd in curl_cmds:
        for url in curl_urls:
            try:
                result = run_command(base_cmd + [url], check=True, timeout=5)
                value = result.stdout.strip()
                if value and is_ipv4_address(value):
                    return value
            except Exception:
                continue

    return "unknown"


def get_public_ipv6(interface: str = "en0") -> str:
    urls = [
        "https://api64.ipify.org",
        "https://api6.ipify.org",
        "https://v6.ident.me",
    ]
    for url in urls:
        try:
            req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with request.urlopen(req, timeout=2.0) as resp:
                value = resp.read().decode("utf-8", errors="replace").strip()
                if value and is_ipv6_address(value):
                    return value
        except Exception:
            continue

    curl_urls = [
        "https://api64.ipify.org",
        "https://api6.ipify.org",
        "https://v6.ident.me",
    ]

    curl_cmds = [
        ["curl", "-6", "-fsL", "--connect-timeout", "2", "--max-time", "4"],
        ["curl", "-6", "--interface", interface, "-fsL", "--connect-timeout", "2", "--max-time", "4"],
    ]

    for base_cmd in curl_cmds:
        for url in curl_urls:
            try:
                result = run_command(base_cmd + [url], check=True, timeout=5)
                value = result.stdout.strip()
                if value and is_ipv6_address(value):
                    return value
            except Exception:
                continue

    return "unknown"


def get_ip_location(ip: str) -> str:
    if not ip or ip == "unknown":
        return "unknown"

    api_specs = [
        {
            "url": f"https://free.freeipapi.com/api/json/{quote(ip)}",
            "ip_key": "ipAddress",
            "country_key": "countryName",
            "country_code_key": "countryCode",
            "city_key": "cityName",
            "region_key": "regionName",
        },
        {
            "url": f"https://ipwho.is/{quote(ip)}",
            "ip_key": "ip",
            "country_key": "country",
            "country_code_key": "country_code",
            "city_key": "city",
            "region_key": "region",
        },
    ]

    for spec in api_specs:
        try:
            result = run_command(
                ["curl", "-fsL", "--connect-timeout", "1", "--max-time", "2", spec["url"]],
                check=True,
                timeout=3,
            )
            payload = json.loads(result.stdout)

            returned_ip = str(payload.get(spec["ip_key"], "")).strip()
            if returned_ip and returned_ip != ip:
                continue

            country = str(payload.get(spec["country_key"], "")).strip()
            country_code = str(payload.get(spec["country_code_key"], "")).strip().upper()
            city = str(payload.get(spec["city_key"], "")).strip()
            region = str(payload.get(spec["region_key"], "")).strip()

            if country_code == "CN" or country in {"China", "中国"}:
                parts = [x for x in ["China", region, city] if x]
                return " / ".join(parts) if parts else "China"

            parts = [x for x in [country, region or city] if x]
            if parts:
                return " / ".join(parts)
        except Exception:
            continue

    return "unknown"


def parse_lsof_ports(output: str) -> list[int]:
    ports = set()
    patterns = [
        r":(\d+)\s*\(LISTEN\)",
        r":(\d+)\s*$",
        r":(\d+)->",
        r"\*:(\d+)",
        r"\]:(\d+)",
    ]

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("COMMAND"):
            continue

        for pattern in patterns:
            for match in re.finditer(pattern, line):
                try:
                    ports.add(int(match.group(1)))
                except Exception:
                    continue

    return sorted(ports)


def parse_netstat_ports(output: str, proto: str) -> list[int]:
    ports = set()
    target = proto.lower()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lower = line.lower()
        if not lower.startswith(target):
            continue
        if target == "tcp" and "listen" not in lower:
            continue

        for match in re.finditer(r"[\.:](\d+)(?:\s|$)", line):
            try:
                ports.add(int(match.group(1)))
            except Exception:
                continue

    return sorted(ports)


def get_open_tcp_ports() -> list[int]:
    candidates = []

    try:
        result = run_command(
            ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
            timeout=12,
        )
        candidates.extend(parse_lsof_ports(result.stdout))
    except Exception:
        pass

    try:
        result = run_command(
            ["netstat", "-an", "-p", "tcp"],
            check=False,
            timeout=6,
        )
        candidates.extend(parse_netstat_ports(result.stdout, "tcp"))
    except Exception:
        pass

    return sorted({p for p in candidates if isinstance(p, int) and 1 <= p <= 65535})


def get_open_udp_ports() -> list[int]:
    candidates = []

    try:
        result = run_command(
            ["lsof", "-nP", "-iUDP"],
            timeout=12,
        )
        candidates.extend(parse_lsof_ports(result.stdout))
    except Exception:
        pass

    try:
        result = run_command(
            ["netstat", "-an", "-p", "udp"],
            check=False,
            timeout=6,
        )
        candidates.extend(parse_netstat_ports(result.stdout, "udp"))
    except Exception:
        pass

    return sorted({p for p in candidates if isinstance(p, int) and 1 <= p <= 65535})


def parse_args():
    parser = argparse.ArgumentParser(description="Collect host summary.")
    parser.add_argument("--interface", type=str, default="en0", help="Network interface, default en0.")
    return parser.parse_args()


def main():
    args = parse_args()

    interface = args.interface
    local_ip = get_local_ip(interface)
    local_ipv6 = get_local_ipv6(interface)
    public_ip = get_public_ip(interface)
    public_ipv6 = get_public_ipv6(interface) if local_ipv6 != "unknown" else "unknown"
    if public_ipv6 == "unknown" and local_ipv6 != "unknown" and is_global_ipv6_candidate(local_ipv6):
        public_ipv6 = local_ipv6

    public_ip_location = get_ip_location(public_ip) if public_ip != "unknown" else "unknown"
    public_ipv6_location = get_ip_location(public_ipv6) if public_ipv6 != "unknown" else "unknown"
    open_tcp_ports = get_open_tcp_ports()
    open_udp_ports = get_open_udp_ports()

    result = {
        "interface": interface,
        "local_ip": local_ip,
        "local_ipv6": local_ipv6,
        "public_ip": public_ip,
        "public_ipv6": public_ipv6,
        "public_ip_location": public_ip_location,
        "public_ipv6_location": public_ipv6_location,
        "open_tcp_ports": open_tcp_ports,
        "open_udp_ports": open_udp_ports,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print("Host summary collected.")
    print("Output JSON:", OUTPUT_JSON)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()