# local_realtime_analyzer.py
# One-click local traffic capture and risk analysis pipeline.
# Supports one-shot analysis, manual start/stop capture, history archiving, and log export.

from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib import request
from urllib.parse import quote

import pandas as pd
import ipaddress
import re


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
LOCAL_ANALYSIS_DIR = REPORTS_DIR / "local_analysis"
LOCAL_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

PCAP_PATH = Path.home() / "Desktop" / "local_test.pcap"
FINAL_JSON = LOCAL_ANALYSIS_DIR / "realtime_result.json"
RISK_CSV = LOCAL_ANALYSIS_DIR / "local_risk_results.csv"
RISK_SUMMARY_JSON = LOCAL_ANALYSIS_DIR / "local_risk_summary.json"

CAPTURE_STATE_JSON = LOCAL_ANALYSIS_DIR / "capture_state.json"
HISTORY_DIR = LOCAL_ANALYSIS_DIR / "history"
HISTORY_INDEX_JSON = HISTORY_DIR / "history_index.json"
LOG_FILE = LOCAL_ANALYSIS_DIR / "realtime_analysis.log"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def append_log(message: str):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    line = f"[{now_iso()}] {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


# Throughput helper functions
def get_file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.exists() else 0
    except Exception:
        return 0



def append_throughput_metrics(df: pd.DataFrame, duration: int) -> dict:
    safe_duration = max(int(duration), 1)

    total_tx_bytes = 0.0
    total_rx_bytes = 0.0
    total_packets = 0.0

    if "a_to_b_bytes" in df.columns:
        try:
            total_tx_bytes = float(pd.to_numeric(df["a_to_b_bytes"], errors="coerce").fillna(0).sum())
        except Exception:
            total_tx_bytes = 0.0

    if "b_to_a_bytes" in df.columns:
        try:
            total_rx_bytes = float(pd.to_numeric(df["b_to_a_bytes"], errors="coerce").fillna(0).sum())
        except Exception:
            total_rx_bytes = 0.0

    if "total_packets" in df.columns:
        try:
            total_packets = float(pd.to_numeric(df["total_packets"], errors="coerce").fillna(0).sum())
        except Exception:
            total_packets = 0.0

    rx_bytes_per_second = total_rx_bytes / safe_duration
    tx_bytes_per_second = total_tx_bytes / safe_duration
    packets_per_second = total_packets / safe_duration

    append_log(f"rx_bytes_per_second={rx_bytes_per_second:.2f}")
    append_log(f"tx_bytes_per_second={tx_bytes_per_second:.2f}")
    append_log(f"packets_per_second={packets_per_second:.2f}")

    return {
        "rx_bytes_per_second": rx_bytes_per_second,
        "tx_bytes_per_second": tx_bytes_per_second,
        "packets_per_second": packets_per_second,
        "total_rx_bytes": total_rx_bytes,
        "total_tx_bytes": total_tx_bytes,
        "total_packets": total_packets,
        "duration": safe_duration,
    }



def get_interface_bytes(interface: str) -> tuple[float, float] | None:
    try:
        result = run_command(["netstat", "-b", "-I", interface], check=False)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) < 2:
            return None
        parts = lines[-1].split()
        if len(parts) < 10:
            return None
        ibytes = float(parts[6])
        obytes = float(parts[9])
        return ibytes, obytes
    except Exception:
        return None


def monitor_capture_throughput(poll_interval: float = 0.4):
    append_log("Capture throughput monitor started.")
    state = load_capture_state() or {}
    interface = str(state.get("interface", "en0"))

    previous_time = time.time()
    previous_counters = get_interface_bytes(interface)
    previous_size = get_file_size(PCAP_PATH)

    while True:
        state = load_capture_state()
        if not state or not state.get("active"):
            break

        time.sleep(poll_interval)

        current_time = time.time()
        elapsed = max(current_time - previous_time, 0.001)
        counters = get_interface_bytes(interface)

        if counters is not None and previous_counters is not None:
            rx_delta = max(counters[0] - previous_counters[0], 0.0)
            tx_delta = max(counters[1] - previous_counters[1], 0.0)
            append_log(f"rx_bytes_per_second={rx_delta / elapsed:.2f}")
            append_log(f"tx_bytes_per_second={tx_delta / elapsed:.2f}")
            previous_counters = counters
        else:
            current_size = get_file_size(PCAP_PATH)
            delta_bytes = max(current_size - previous_size, 0)
            fallback_rate = delta_bytes / elapsed
            append_log(f"rx_bytes_per_second={fallback_rate:.2f}")
            append_log("tx_bytes_per_second=0.00")
            previous_size = current_size

        previous_time = current_time

    append_log("Capture throughput monitor stopped.")


def run_command(
    cmd: list[str],
    check: bool = True,
    timeout: int = 3,
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


def get_local_ip(interface: str) -> str:
    try:
        result = run_command(["ipconfig", "getifaddr", interface])
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def get_local_ipv6(interface: str) -> str:
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



# Helper functions for IP address validation
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


def safe_call(fn, default, label: str):
    try:
        return fn()
    except Exception as e:
        append_log(f"{label} failed: {e}")
        return default

def get_public_ip() -> str:
    urls = [
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    ]
    for url in urls:
        try:
            req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with request.urlopen(req, timeout=1.2) as resp:
                value = resp.read().decode("utf-8", errors="replace").strip()
                if value and is_ipv4_address(value):
                    return value
        except Exception:
            continue

    curl_urls = [
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
    ]
    for url in curl_urls:
        try:
            result = run_command(
                ["curl", "-4", "-fsL", "--connect-timeout", "1", "--max-time", "2", url],
                check=True,
                timeout=2,
            )
            value = result.stdout.strip()
            if value and is_ipv4_address(value):
                return value
        except Exception:
            continue

    return "unknown"


def get_public_ipv6() -> str:
    urls = [
        "https://api64.ipify.org",
        "https://api6.ipify.org",
    ]
    for url in urls:
        try:
            req = request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with request.urlopen(req, timeout=1.2) as resp:
                value = resp.read().decode("utf-8", errors="replace").strip()
                if value and is_ipv6_address(value):
                    return value
        except Exception:
            continue

    curl_urls = [
        "https://api64.ipify.org",
    ]
    for url in curl_urls:
        try:
            result = run_command(
                ["curl", "-6", "-fsL", "--connect-timeout", "1", "--max-time", "2", url],
                check=True,
                timeout=2,
            )
            value = result.stdout.strip()
            if value and is_ipv6_address(value):
                return value
        except Exception:
            continue

    return "unknown"


from urllib.parse import quote


def get_ip_location(ip: str) -> str:
    if not ip or ip == "unknown":
        return "unknown"

    url = f"https://ipwho.is/{quote(ip)}"
    try:
        result = run_command(
            ["curl", "-fsL", "--connect-timeout", "1", "--max-time", "2", url],
            check=True,
            timeout=2,
        )
        payload = json.loads(result.stdout)

        returned_ip = str(payload.get("ip", "")).strip()
        if returned_ip and returned_ip != ip:
            return "unknown"

        country = str(payload.get("country", "")).strip()
        country_code = str(payload.get("country_code", "")).strip().upper()
        city = str(payload.get("city", "")).strip()
        region = str(payload.get("region", "")).strip()

        if country_code == "CN" or country in {"China", "中国"}:
            parts = [x for x in ["China", region or city] if x]
            return " / ".join(parts) if parts else "China"

        parts = [x for x in [country, city or region] if x]
        return " / ".join(parts) if parts else "unknown"
    except Exception:
        return "unknown"


def parse_lsof_ports(output: str) -> list[int]:
    ports = set()
    for line in output.splitlines():
        if "LISTEN" not in line and "UDP" not in line:
            continue
        parts = line.split()
        for part in parts:
            if "->" in part:
                continue
            if ":" in part:
                try:
                    port_str = part.rsplit(":", 1)[-1]
                    if port_str.isdigit():
                        ports.add(int(port_str))
                except Exception:
                    pass
    return sorted(ports)


def get_open_tcp_ports() -> list[int]:
    try:
        result = run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        return parse_lsof_ports(result.stdout)
    except Exception:
        return []


def get_open_udp_ports() -> list[int]:
    try:
        result = run_command(["lsof", "-nP", "-iUDP"])
        return parse_lsof_ports(result.stdout)
    except Exception:
        return []


def save_capture_state(state: dict):
    with open(CAPTURE_STATE_JSON, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def load_capture_state() -> dict | None:
    if not CAPTURE_STATE_JSON.exists():
        return None
    with open(CAPTURE_STATE_JSON, "r", encoding="utf-8") as f:
        return json.load(f)



def clear_capture_state():
    if CAPTURE_STATE_JSON.exists():
        CAPTURE_STATE_JSON.unlink()



def is_pid_alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        pid = int(pid)
    except Exception:
        return False

    if pid <= 0:
        return False

    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


# 读取指定 PID 的命令行，用于判断该 PID 是否仍然是预期的抓包/监控进程。
def get_pid_command(pid: int | None) -> str:
    if not is_pid_alive(pid):
        return ""

    try:
        result = run_command(
            ["ps", "-p", str(int(pid)), "-o", "command="],
            check=False,
            timeout=2,
        )
        return (result.stdout or "").strip().lower()
    except Exception:
        return ""


# 判断 capture pid 是否仍然对应 tcpdump。
def is_capture_process_alive(pid: int | None) -> bool:
    cmd = get_pid_command(pid)
    return bool(cmd) and "tcpdump" in cmd


# 判断 monitor pid 是否仍然对应当前脚本的监控模式。
def is_monitor_process_alive(pid: int | None) -> bool:
    cmd = get_pid_command(pid)
    return bool(cmd) and "local_realtime_analyzer.py" in cmd and "--monitor-capture" in cmd


# 自动修复残留抓包状态：只有真正的 tcpdump 仍在运行时，才认为当前抓包会话有效。
# 返回值：
# - 默认模式：保持原来的兼容行为，只返回 state 或 None
# - include_reason=True：返回 (state, state_reason)
def normalize_capture_state(include_reason: bool = False):
    state = load_capture_state()
    if not state or not state.get("active"):
        if include_reason:
            return state, "idle"
        return state

    capture_pid = state.get("pid")
    monitor_pid = state.get("monitor_pid")

    capture_alive = is_capture_process_alive(capture_pid)
    monitor_alive = is_monitor_process_alive(monitor_pid)
    capture_cmd = get_pid_command(capture_pid)
    monitor_cmd = get_pid_command(monitor_pid)

    # 只有真正的抓包进程 tcpdump 还活着时，才保留 active 状态。
    # 如果监控进程缺失，但抓包仍在运行，不影响当前会话有效性。
    if capture_alive:
        if include_reason:
            if monitor_alive:
                return state, "capturing"
            return state, "capturing_monitor_missing"
        return state

    # 如果监控进程残留，但抓包进程已经不在，主动结束这个残留监控进程。
    if monitor_alive and monitor_pid is not None:
        try:
            subprocess.run(
                ["kill", "-TERM", str(int(monitor_pid))],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=2,
                text=True,
            )
        except Exception:
            pass
        time.sleep(0.2)
        if is_monitor_process_alive(monitor_pid):
            try:
                subprocess.run(
                    ["kill", "-KILL", str(int(monitor_pid))],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=2,
                    text=True,
                )
            except Exception:
                pass

    append_log(
        "Found stale capture state "
        f"pid={capture_pid} capture_cmd='{capture_cmd}', "
        f"monitor_pid={monitor_pid} monitor_cmd='{monitor_cmd}'; clearing old state."
    )
    clear_capture_state()

    if include_reason:
        return None, "stale_state_cleared"
    return None


def capture_pcap(interface: str, duration: int):
    # One-shot capture mode.
    if PCAP_PATH.exists():
        PCAP_PATH.unlink()

    cmd = ["sudo", "-n", "tcpdump", "-i", interface, "-w", str(PCAP_PATH)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    append_log(f"Started one-shot capture on {interface} for {duration}s.")

    try:
        time.sleep(duration)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    if not PCAP_PATH.exists():
        stderr = ""
        if proc.stderr:
            try:
                stderr = proc.stderr.read()
            except Exception:
                pass
        raise RuntimeError(
            "tcpdump did not produce a pcap file. "
            "If you want in-app capture, configure passwordless tcpdump first. "
            f"Details: {stderr}"
        )

    append_log(f"Finished one-shot capture: {PCAP_PATH}")


def start_manual_capture(interface: str):
    state, state_reason = normalize_capture_state(include_reason=True)
    if state and state.get("active"):
        active_pid = state.get("pid")
        monitor_pid = state.get("monitor_pid")
        raise RuntimeError(
            "A capture session is already active. "
            f"state_reason={state_reason}, pid={active_pid}, monitor_pid={monitor_pid}. "
            "Stop it before starting a new one."
        )

    if PCAP_PATH.exists():
        PCAP_PATH.unlink()

    cmd = ["sudo", "-n", "tcpdump", "-i", interface, "-w", str(PCAP_PATH)]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    time.sleep(1.0)
    if proc.poll() is not None:
        stderr = ""
        if proc.stderr:
            try:
                stderr = proc.stderr.read()
            except Exception:
                pass
        raise RuntimeError(
            "Failed to start tcpdump. "
            "If you want in-app capture, configure passwordless tcpdump first. "
            f"Details: {stderr}"
        )

    state = {
        "active": True,
        "pid": proc.pid,
        "interface": interface,
        "pcap_path": str(PCAP_PATH),
        "started_at": now_iso(),
    }
    save_capture_state(state)
    append_log(f"Started manual capture on {interface}, pid={proc.pid}.")

    try:
        monitor_proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--monitor-capture"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        state["monitor_pid"] = monitor_proc.pid
        save_capture_state(state)
        append_log(f"Started capture throughput monitor pid={monitor_proc.pid}.")
    except Exception as e:
        append_log(f"Failed to start capture throughput monitor: {e}")

    return state

def stop_manual_capture(scope: str):
    state, state_reason = normalize_capture_state(include_reason=True)
    if not state or not state.get("active"):
        raise RuntimeError(f"No active capture session found. state_reason={state_reason}")

    pid = int(state["pid"])
    interface = str(state["interface"])
    started_at = str(state["started_at"])
    monitor_pid = state.get("monitor_pid")

    append_log(f"Stopping manual capture pid={pid} on {interface}.")

    try:
        proc = subprocess.Popen(
            ["kill", "-TERM", str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.wait(timeout=3)
    except Exception:
        pass

    time.sleep(1.0)

    if is_capture_process_alive(pid):
        try:
            subprocess.run(
                ["kill", "-KILL", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
                check=False,
            )
        except Exception:
            pass

    if monitor_pid:
        try:
            subprocess.run(
                ["kill", "-TERM", str(monitor_pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
                check=False,
            )
        except Exception:
            pass
        time.sleep(0.2)
        if is_monitor_process_alive(monitor_pid):
            try:
                subprocess.run(
                    ["kill", "-KILL", str(monitor_pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=2,
                    check=False,
                )
            except Exception:
                pass

    if not PCAP_PATH.exists():
        clear_capture_state()
        raise RuntimeError("Capture stopped, but no pcap file was produced.")

    append_log("Manual capture pipeline started.")
    run_pipeline(scope)
    append_log("Manual capture pipeline finished.")

    duration = elapsed_seconds_from_iso(started_at)
    df, summary = load_results()
    throughput = append_throughput_metrics(df, duration)

    append_log("Building realtime output.")
    result = build_output(df, summary, interface, duration=duration)
    result["throughput"] = throughput
    append_log("Realtime output built.")

    with open(FINAL_JSON, "w", encoding="utf-8") as f:
       json.dump(result, f, ensure_ascii=False, indent=2)
    append_log(f"Saved realtime result to {FINAL_JSON}.")

    try:
        archive_result(result, started_at=started_at, stopped_at=now_iso())
    except Exception as e:
        append_log(f"Archive skipped: {e}")

    clear_capture_state()
    append_log("Manual capture analysis complete.")

    return result


def elapsed_seconds_from_iso(started_at: str) -> int:
    try:
        start_dt = datetime.fromisoformat(started_at)
        delta = datetime.now(timezone.utc).astimezone() - start_dt
        return max(0, int(delta.total_seconds()))
    except Exception:
        return 0


def get_capture_status() -> dict:
    state, state_reason = normalize_capture_state(include_reason=True)

    if not state or not state.get("active"):
        return {
            "active": False,
            "state_reason": state_reason,
            "interface": None,
            "elapsed_seconds": 0,
            "started_at": None,
            "pid": None,
            "monitor_pid": None,
        }

    elapsed = elapsed_seconds_from_iso(str(state.get("started_at", now_iso())))
    return {
        "active": True,
        "state_reason": state_reason,
        "interface": state.get("interface"),
        "elapsed_seconds": elapsed,
        "started_at": state.get("started_at"),
        "pid": state.get("pid"),
        "monitor_pid": state.get("monitor_pid"),
        "pcap_path": state.get("pcap_path"),
    }

def run_pipeline(scope: str, input_pcap: Path | None = None):
    py = sys.executable
    pcap_path = Path(input_pcap).expanduser().resolve() if input_pcap is not None else PCAP_PATH

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    subprocess.run(
        [py, str(PROJECT_ROOT / "src" / "extract_local_flows.py"), "--input-pcap", str(pcap_path)],
        check=True,
    )
    subprocess.run([py, str(PROJECT_ROOT / "src" / "train_local_anomaly.py")], check=True)
    subprocess.run(
        [py, str(PROJECT_ROOT / "src" / "predict_local_risk.py"), "--scope", scope],
        check=True,
    )


def load_results():
    if not RISK_CSV.exists():
        raise FileNotFoundError(f"Missing risk CSV: {RISK_CSV}")
    if not RISK_SUMMARY_JSON.exists():
        raise FileNotFoundError(f"Missing risk summary: {RISK_SUMMARY_JSON}")

    df = pd.read_csv(RISK_CSV)
    with open(RISK_SUMMARY_JSON, "r", encoding="utf-8") as f:
        summary = json.load(f)

    return df, summary

def run_full_analysis(interface: str, duration: int, scope: str, input_pcap: Path | None = None):
    pcap_path = Path(input_pcap).expanduser().resolve() if input_pcap is not None else PCAP_PATH
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    run_pipeline(scope, input_pcap=pcap_path)
    df, summary = load_results()
    throughput = append_throughput_metrics(df, duration)
    result = build_output(df, summary, interface, duration)
    result["throughput"] = throughput

    with open(FINAL_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result

def risk_level_rank(value: str) -> int:
    text = str(value).strip().lower()
    if text == "high":
        return 0
    if text == "medium":
        return 1
    if text == "low":
        return 2
    return 3


def prepare_top_risks(df: pd.DataFrame) -> list[dict]:
    if df.empty:
        return []

    working = df.copy()

    if "risk_level" in working.columns:
        working["_risk_rank"] = working["risk_level"].map(risk_level_rank)
    else:
        working["_risk_rank"] = 3

    if "final_risk_score" not in working.columns:
        working["final_risk_score"] = 0.0

    sort_cols = ["_risk_rank", "final_risk_score"]
    ascending = [True, False]
    working = working.sort_values(sort_cols, ascending=ascending, kind="stable")

    preferred_columns = [
        "ip_version",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "resolved_host",
        "geo_label",
        "service",
        "service_hint",
        "endpoint_type",
        "network_scope",
        "user_label",
        "risk_level",
        "reason",
        "final_risk_score",
    ]
    available_columns = [col for col in preferred_columns if col in working.columns]
    if not available_columns:
        return []

    top_risks_df = working[available_columns].head(20).copy()
    return top_risks_df.fillna("").to_dict(orient="records")

def build_consumer_summary(
    summary: dict,
    top_risks: list[dict],
    interface: str,
    duration: int,
) -> dict:
    risk_counts = summary.get("risk_level_counts", {}) or {}
    high = int(risk_counts.get("High", 0))
    medium = int(risk_counts.get("Medium", 0))
    low = int(risk_counts.get("Low", 0))

    top_external = None
    top_local = None
    for item in top_risks:
        geo_label = str(item.get("geo_label", "")).lower()
        if top_external is None and "public" in geo_label:
            top_external = item
        if top_local is None and ("local" in geo_label or "private" in geo_label or "lan" in geo_label):
            top_local = item

    if high > 0 and top_external:
        status = "High-risk external activity"
        priority = "High"
        headline = "An external connection needs attention"
        summary_text = (
            f"A high-risk external endpoint was detected during the last {duration}s capture on {interface}. "
            f"Top item: {top_external.get('dst_ip', 'unknown')}:{top_external.get('dst_port', '')} "
            f"({top_external.get('service_hint', 'Unknown service')})."
        )
        next_steps = [
            "Review the top external endpoint first.",
            "Check whether the destination belongs to a known app, VPN, cloud service, or admin portal.",
            "Export the log and PCAP if the destination looks unfamiliar.",
        ]
    elif high > 0:
        status = "High-risk activity detected"
        priority = "High"
        headline = "A high-risk connection needs review"
        summary_text = (
            f"A high-risk connection was detected during the last {duration}s capture on {interface}. "
            "Review the top risk details to confirm whether it is expected."
        )
        next_steps = [
            "Open the top risk details first.",
            "Check whether the port and service are expected on this network.",
            "Export the log if you need a deeper review.",
        ]
    elif medium > 0 and top_external:
        status = "Some activity needs review"
        priority = "Medium"
        headline = "An unusual external connection was observed"
        summary_text = (
            f"Medium-risk external activity was detected during the last {duration}s capture on {interface}. "
            f"Top item: {top_external.get('dst_ip', 'unknown')}:{top_external.get('dst_port', '')}."
        )
        next_steps = [
            "Review unfamiliar external endpoints.",
            "Check whether this traffic is from browser sync, updates, cloud tools, or VPN software.",
            "Mark trusted items later to reduce repeated noise.",
        ]
    elif medium > 0:
        status = "Some activity needs review"
        priority = "Medium"
        headline = "A few unusual connections were observed"
        summary_text = (
            f"The capture on {interface} found medium-risk items, but no critical external threat stood out."
        )
        next_steps = [
            "Review the medium-risk list.",
            "Focus on items with unusual ports or high traffic volume.",
            "Keep this session as a baseline for comparison.",
        ]
    elif low > 0 and top_local:
        status = "Mostly normal"
        priority = "Low"
        headline = "Only lower-risk local activity was observed"
        summary_text = (
            f"The capture on {interface} mostly shows low-risk or local/private-network activity. "
            f"Top local item: {top_local.get('dst_ip', 'unknown')}:{top_local.get('dst_port', '')}."
        )
        next_steps = [
            "No urgent action is needed.",
            "Review only if you do not recognize the app or device.",
            "Use history to compare future sessions.",
        ]
    else:
        status = "Normal"
        priority = "Low"
        headline = "No major issues detected"
        summary_text = (
            f"No major high-risk or medium-risk network issues were detected during the last {duration}s capture on {interface}."
        )
        next_steps = [
            "No action is needed right now.",
            "Use longer captures if you want broader coverage.",
            "Keep this session as a clean baseline.",
        ]

    return {
        "status": status,
        "priority": priority,
        "headline": headline,
        "summary": summary_text,
        "next_steps": next_steps,
    }

def build_output(df: pd.DataFrame, summary: dict, interface: str, duration: int):
    append_log("build_output: collecting host summary.")

    local_ip = safe_call(lambda: get_local_ip(interface), "unknown", "get_local_ip")
    local_ipv6 = safe_call(lambda: get_local_ipv6(interface), "unknown", "get_local_ipv6")

    public_ip = safe_call(get_public_ip, "unknown", "get_public_ip")
    public_ipv6 = safe_call(get_public_ipv6, "unknown", "get_public_ipv6")

    if public_ipv6 == "unknown" and local_ipv6 != "unknown" and is_global_ipv6_candidate(local_ipv6):
        public_ipv6 = local_ipv6

    public_ip_location = (
        safe_call(lambda: get_ip_location(public_ip), "unknown", "get_ip_location_ipv4")
        if public_ip != "unknown" else "unknown"
    )
    public_ipv6_location = (
        safe_call(lambda: get_ip_location(public_ipv6), "unknown", "get_ip_location_ipv6")
        if public_ipv6 != "unknown" else "unknown"
    )

    open_tcp_ports = safe_call(get_open_tcp_ports, [], "get_open_tcp_ports")
    open_udp_ports = safe_call(get_open_udp_ports, [], "get_open_udp_ports")

    append_log("build_output: host summary collected.")

    ip_version_counts = df["ip_version"].value_counts(dropna=False).to_dict() if "ip_version" in df.columns else {}
    top_ports = df["dst_port"].value_counts(dropna=False).head(10).to_dict() if "dst_port" in df.columns else {}
    top_dns = (
        df["resolved_host"]
        .fillna("unresolved")
        .value_counts(dropna=False)
        .head(10)
        .to_dict()
        if "resolved_host" in df.columns else {}
    )

    top_risks = prepare_top_risks(df)
    consumer_summary = build_consumer_summary(summary, top_risks, interface, duration)

    result = {
        "capture_window_seconds": duration,
        "interface": interface,
        "host_summary": {
            "interface": interface,
            "local_ip": local_ip,
            "local_ipv6": local_ipv6,
            "public_ip": public_ip,
            "public_ipv6": public_ipv6,
            "public_ip_location": public_ip_location,
            "public_ipv6_location": public_ipv6_location,
            "open_tcp_ports": open_tcp_ports,
            "open_udp_ports": open_udp_ports,
        },
        "traffic_summary": {
            "total_flows": int(len(df)),
            "risk_level_counts": summary.get("risk_level_counts", {}),
            "ip_version_counts": ip_version_counts,
            "top_ports": top_ports,
            "top_dns": top_dns,
            "top_services": summary.get("service_counts", {}),
        },
        "top_risks": top_risks,
        "consumer_summary": consumer_summary,
    }
    return result

def archive_result(result: dict, started_at: str, stopped_at: str):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = HISTORY_DIR / f"session_{session_id}"
    session_dir.mkdir(parents=True, exist_ok=True)

    files_to_copy = [
        (PCAP_PATH, session_dir / "capture.pcap"),
        (RISK_CSV, session_dir / "local_risk_results.csv"),
        (RISK_SUMMARY_JSON, session_dir / "local_risk_summary.json"),
        (FINAL_JSON, session_dir / "realtime_result.json"),
    ]

    copied_files = {}
    for src, dst in files_to_copy:
        if src.exists():
            shutil.copy2(src, dst)
            copied_files[src.name] = str(dst)

    record = {
        "session_id": session_id,
        "started_at": started_at,
        "stopped_at": stopped_at,
        "interface": result.get("interface"),
        "capture_window_seconds": result.get("capture_window_seconds"),
        "risk_level_counts": result.get("traffic_summary", {}).get("risk_level_counts", {}),
        "files": copied_files,
    }

    index = []
    if HISTORY_INDEX_JSON.exists():
        try:
            with open(HISTORY_INDEX_JSON, "r", encoding="utf-8") as f:
                index = json.load(f)
        except Exception:
            index = []

    index.insert(0, record)

    with open(HISTORY_INDEX_JSON, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)

    append_log(f"Archived session {session_id} to {session_dir}")


def export_log(output_path: str):
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    if not LOG_FILE.exists():
        append_log("Export log requested but log file did not exist yet.")
        LOG_FILE.touch()

    shutil.copy2(LOG_FILE, target)
    print("Log exported to:", target)


def parse_args():
    parser = argparse.ArgumentParser(description="One-click local traffic analysis.")
    parser.add_argument("--interface", type=str, default="en0", help="Network interface, default en0.")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds.")
    parser.add_argument(
        "--scope",
        type=str,
        choices=["all", "exclude_lan", "lan_only", "external_only"],
        default="external_only",
        help="Risk analysis scope.",
    )
    parser.add_argument(
        "--skip-capture",
        action="store_true",
        help="Skip tcpdump capture and reuse existing local_test.pcap.",
    )

    parser.add_argument("--start-capture", action="store_true", help="Start manual capture session.")
    parser.add_argument("--stop-capture", action="store_true", help="Stop manual capture and analyze.")
    parser.add_argument("--input-pcap", type=str, default="", help="Analyze an existing pcap file without live capture.")
    parser.add_argument("--status", action="store_true", help="Show current capture status.")
    parser.add_argument("--monitor-capture", action="store_true", help="Internal background throughput monitor.")
    parser.add_argument("--export-log", type=str, default="", help="Export analysis log to a target path.")

    return parser.parse_args()


def main():
    args = parse_args()
    LOCAL_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    if args.export_log:
        export_log(args.export_log)
        return

    if args.monitor_capture:
        monitor_capture_throughput()
        return

    if args.status:
        status = get_capture_status()
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return

    if args.start_capture:
        state = start_manual_capture(args.interface)
        print("Manual capture started.")
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return

    if args.stop_capture:
        result = stop_manual_capture(args.scope)
        print("Manual capture stopped and analyzed.")
        print("Output JSON:", FINAL_JSON)
        print("Local IP:", result["host_summary"]["local_ip"])
        print("Local IPv6:", result["host_summary"]["local_ipv6"])
        print("Public IP:", result["host_summary"]["public_ip"])
        print("Public IPv6:", result["host_summary"]["public_ipv6"])
        print("Public IP Location:", result["host_summary"]["public_ip_location"])
        print("Public IPv6 Location:", result["host_summary"]["public_ipv6_location"])
        print("Open TCP ports:", result["host_summary"]["open_tcp_ports"])
        print("Open UDP ports:", result["host_summary"]["open_udp_ports"])
        print("Risk level counts:", result["traffic_summary"]["risk_level_counts"])
        if "throughput" in result:
            print(f"rx_bytes_per_second={result['throughput']['rx_bytes_per_second']:.2f}")
            print(f"tx_bytes_per_second={result['throughput']['tx_bytes_per_second']:.2f}")
            print(f"packets_per_second={result['throughput']['packets_per_second']:.2f}")
        return
    
    if args.input_pcap:
        input_pcap = Path(args.input_pcap).expanduser().resolve()
        append_log(f"Starting offline PCAP analysis for: {input_pcap}")

        result = run_full_analysis(
            interface=args.interface,
            duration=args.duration,
            scope=args.scope,
            input_pcap=input_pcap,
        )

        archive_result(result, started_at=now_iso(), stopped_at=now_iso())
        append_log("Offline PCAP analysis complete.")

        print("Offline PCAP analysis complete.")
        print("Input PCAP:", input_pcap)
        print("Output JSON:", FINAL_JSON)
        print("Local IP:", result["host_summary"]["local_ip"])
        print("Local IPv6:", result["host_summary"]["local_ipv6"])
        print("Public IP:", result["host_summary"]["public_ip"])
        print("Public IPv6:", result["host_summary"]["public_ipv6"])
        print("Public IP Location:", result["host_summary"]["public_ip_location"])
        print("Public IPv6 Location:", result["host_summary"]["public_ipv6_location"])
        print("Open TCP ports:", result["host_summary"]["open_tcp_ports"])
        print("Open UDP ports:", result["host_summary"]["open_udp_ports"])
        print("Risk level counts:", result["traffic_summary"]["risk_level_counts"])
        if "throughput" in result:
            print(f"rx_bytes_per_second={result['throughput']['rx_bytes_per_second']:.2f}")
            print(f"tx_bytes_per_second={result['throughput']['tx_bytes_per_second']:.2f}")
            print(f"packets_per_second={result['throughput']['packets_per_second']:.2f}")
        return
    
    if not args.skip_capture:
        capture_pcap(args.interface, args.duration)

    result = run_full_analysis(
        interface=args.interface,
        duration=args.duration,
        scope=args.scope,
    )

    archive_result(result, started_at=now_iso(), stopped_at=now_iso())

    print("Realtime analysis finished.")
    print("Output JSON:", FINAL_JSON)
    print("Local IP:", result["host_summary"]["local_ip"])
    print("Local IPv6:", result["host_summary"]["local_ipv6"])
    print("Public IP:", result["host_summary"]["public_ip"])
    print("Public IPv6:", result["host_summary"]["public_ipv6"])
    print("Public IP Location:", result["host_summary"]["public_ip_location"])
    print("Public IPv6 Location:", result["host_summary"]["public_ipv6_location"])
    print("Open TCP ports:", result["host_summary"]["open_tcp_ports"])
    print("Open UDP ports:", result["host_summary"]["open_udp_ports"])
    print("Risk level counts:", result["traffic_summary"]["risk_level_counts"])
    print(f"rx_bytes_per_second={result['throughput']['rx_bytes_per_second']:.2f}")
    print(f"tx_bytes_per_second={result['throughput']['tx_bytes_per_second']:.2f}")
    print(f"packets_per_second={result['throughput']['packets_per_second']:.2f}")


if __name__ == "__main__":
    main()