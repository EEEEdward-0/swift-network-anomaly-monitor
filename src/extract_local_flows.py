# extract_local_flows.py
# Extract simple bidirectional flow features from a local pcap file.
# Supports both IPv4 and IPv6.

from pathlib import Path
from dataclasses import dataclass
import ipaddress
import math

import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
LOCAL_ANALYSIS_DIR = REPORTS_DIR / "local_analysis"
LOCAL_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

PCAP_PATH = Path.home() / "Desktop" / "local_test.pcap"
OUTPUT_CSV = LOCAL_ANALYSIS_DIR / "local_flows.csv"


def is_private_ip(ip: str) -> int:
    # Mark whether an IP belongs to a private or local range.
    try:
        addr = ipaddress.ip_address(ip)
        return int(
            addr.is_private
            or addr.is_link_local
            or addr.is_loopback
            or addr.is_multicast
        )
    except ValueError:
        return 0


def get_service(src_port: int, dst_port: int, proto: str) -> str:
    # Map common ports to coarse service labels.
    # Check both source and destination ports to improve local traffic labeling.
    common = {
        53: "dns",
        80: "http",
        443: "https",
        22: "ssh",
        25: "smtp",
        110: "pop3",
        143: "imap",
        3306: "mysql",
        5432: "postgres",
        6379: "redis",
        8080: "http_alt",
        8443: "https_alt",
        5353: "mdns",
        123: "ntp",
        67: "dhcp",
        68: "dhcp",
        1900: "ssdp",
        3389: "rdp",
        445: "smb",
        139: "netbios",
        137: "netbios",
        138: "netbios",
        5000: "upnp",
        6000: "custom_tcp_6000",
        6001: "custom_tcp_6001",
        6010: "custom_tcp_6010",
        6011: "custom_tcp_6011",
        7826: "custom_tcp_7826",
    }

    for port in (int(dst_port), int(src_port)):
        if port in common:
            return common[port]

    if proto == "udp":
        return "udp_other"
    return "tcp_other"


def canonical_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str):
    # Create one bidirectional key for a flow.
    a = (src_ip, int(src_port))
    b = (dst_ip, int(dst_port))
    if a <= b:
        return (src_ip, int(src_port), dst_ip, int(dst_port), proto)
    return (dst_ip, int(dst_port), src_ip, int(src_port), proto)


@dataclass
class FlowStats:
    first_time: float
    last_time: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    ip_version: str

    total_packets: int = 0
    total_bytes: int = 0

    a_to_b_packets: int = 0
    b_to_a_packets: int = 0
    a_to_b_bytes: int = 0
    b_to_a_bytes: int = 0

    min_pkt_size: int = 10**9
    max_pkt_size: int = 0
    sum_pkt_size: int = 0
    sum_sq_pkt_size: float = 0.0

    tcp_syn_count: int = 0
    tcp_ack_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_psh_count: int = 0

    def update_time(self, ts: float):
        self.last_time = ts

    def update_packet(self, size: int):
        self.total_packets += 1
        self.total_bytes += size
        self.sum_pkt_size += size
        self.sum_sq_pkt_size += size * size
        self.min_pkt_size = min(self.min_pkt_size, size)
        self.max_pkt_size = max(self.max_pkt_size, size)

    def update_direction(self, forward: bool, size: int):
        if forward:
            self.a_to_b_packets += 1
            self.a_to_b_bytes += size
        else:
            self.b_to_a_packets += 1
            self.b_to_a_bytes += size

    def update_tcp_flags(self, flags: int):
        if flags & 0x02:
            self.tcp_syn_count += 1
        if flags & 0x10:
            self.tcp_ack_count += 1
        if flags & 0x01:
            self.tcp_fin_count += 1
        if flags & 0x04:
            self.tcp_rst_count += 1
        if flags & 0x08:
            self.tcp_psh_count += 1

    def to_feature_row(self):
        duration = max(self.last_time - self.first_time, 0.0)
        mean_pkt_size = self.sum_pkt_size / self.total_packets if self.total_packets else 0.0
        var_pkt_size = (
            self.sum_sq_pkt_size / self.total_packets - mean_pkt_size ** 2
            if self.total_packets else 0.0
        )
        std_pkt_size = math.sqrt(max(var_pkt_size, 0.0))

        a_to_b_ratio = self.a_to_b_packets / self.total_packets if self.total_packets else 0.0
        b_to_a_ratio = self.b_to_a_packets / self.total_packets if self.total_packets else 0.0
        bytes_per_second = self.total_bytes / duration if duration > 0 else 0.0
        packets_per_second = self.total_packets / duration if duration > 0 else 0.0

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "ip_version": self.ip_version,
            "service": get_service(self.src_port, self.dst_port, self.proto),
            "duration": duration,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "a_to_b_packets": self.a_to_b_packets,
            "b_to_a_packets": self.b_to_a_packets,
            "a_to_b_bytes": self.a_to_b_bytes,
            "b_to_a_bytes": self.b_to_a_bytes,
            "a_to_b_packet_ratio": a_to_b_ratio,
            "b_to_a_packet_ratio": b_to_a_ratio,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "min_pkt_size": 0 if self.min_pkt_size == 10**9 else self.min_pkt_size,
            "max_pkt_size": self.max_pkt_size,
            "mean_pkt_size": mean_pkt_size,
            "std_pkt_size": std_pkt_size,
            "tcp_syn_count": self.tcp_syn_count,
            "tcp_ack_count": self.tcp_ack_count,
            "tcp_fin_count": self.tcp_fin_count,
            "tcp_rst_count": self.tcp_rst_count,
            "tcp_psh_count": self.tcp_psh_count,
            "src_is_private": is_private_ip(self.src_ip),
            "dst_is_private": is_private_ip(self.dst_ip),
            "both_private": int(is_private_ip(self.src_ip) and is_private_ip(self.dst_ip)),
        }


def main():
    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Pcap not found: {PCAP_PATH}")

    flows = {}

    with PcapReader(str(PCAP_PATH)) as reader:
        for pkt in reader:
            src_ip = None
            dst_ip = None
            ip_version = None

            if IP in pkt:
                net = pkt[IP]
                src_ip = net.src
                dst_ip = net.dst
                ip_version = "ipv4"
            elif IPv6 in pkt:
                net = pkt[IPv6]
                src_ip = net.src
                dst_ip = net.dst
                ip_version = "ipv6"
            else:
                continue

            proto = None
            src_port = 0
            dst_port = 0
            tcp_flags = None

            if TCP in pkt:
                proto = "tcp"
                tcp = pkt[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                tcp_flags = int(tcp.flags)
            elif UDP in pkt:
                proto = "udp"
                udp = pkt[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
            else:
                continue

            ts = float(pkt.time)
            size = int(len(pkt))

            key = canonical_flow_key(src_ip, src_port, dst_ip, dst_port, proto)

            if key not in flows:
                flows[key] = FlowStats(
                    first_time=ts,
                    last_time=ts,
                    src_ip=key[0],
                    src_port=key[1],
                    dst_ip=key[2],
                    dst_port=key[3],
                    proto=key[4],
                    ip_version=ip_version,
                )

            flow = flows[key]
            flow.update_time(ts)
            flow.update_packet(size)

            forward = (src_ip == flow.src_ip and src_port == flow.src_port)
            flow.update_direction(forward, size)

            if tcp_flags is not None:
                flow.update_tcp_flags(tcp_flags)

    rows = [flow.to_feature_row() for flow in flows.values()]
    df = pd.DataFrame(rows)

    # Drop tiny flows for cleaner local testing.
    df = df[df["total_packets"] >= 2].copy()
    df = df.sort_values(by=["duration", "total_packets"], ascending=[False, False]).reset_index(drop=True)

    df.to_csv(OUTPUT_CSV, index=False)

    print("Flow extraction finished.")
    print("Input pcap:", PCAP_PATH)
    print("Output csv:", OUTPUT_CSV)
    print("Number of flows:", len(df))
    print("IP version counts:")
    print(df["ip_version"].value_counts(dropna=False))
    print("Service counts:")
    print(df["service"].value_counts(dropna=False).head(15))
    print("Columns:")
    print(list(df.columns))


if __name__ == "__main__":
    main()