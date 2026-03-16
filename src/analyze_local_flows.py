# analyze_local_flows.py
# Analyze extracted local flow features and generate summary reports.

from pathlib import Path
import json

import pandas as pd
import matplotlib.pyplot as plt


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

INPUT_CSV = REPORTS_DIR / "local_flows.csv"
OUTPUT_JSON = REPORTS_DIR / "local_flow_summary.json"
OUTPUT_TXT = REPORTS_DIR / "local_flow_summary.txt"


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


def save_bar_chart(series, title, xlabel, ylabel, output_path, top_n=None):
    # Save a simple bar chart.
    if top_n is not None:
        series = series.head(top_n)

    plt.figure(figsize=(10, 5))
    series.plot(kind="bar")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def main():
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"Missing input CSV: {INPUT_CSV}")

    df = pd.read_csv(INPUT_CSV)

    if df.empty:
        raise ValueError("local_flows.csv is empty.")

    # Add traffic scope label.
    df["network_scope"] = df.apply(classify_network_scope, axis=1)

    # Basic counts.
    total_flows = int(len(df))
    ip_version_counts = df["ip_version"].value_counts(dropna=False).to_dict()
    proto_counts = df["proto"].value_counts(dropna=False).to_dict()
    service_counts = df["service"].value_counts(dropna=False).to_dict()
    network_scope_counts = df["network_scope"].value_counts(dropna=False).to_dict()

    # Top ports.
    top_src_ports = df["src_port"].value_counts(dropna=False).head(20).to_dict()
    top_dst_ports = df["dst_port"].value_counts(dropna=False).head(20).to_dict()

    # Highlight selected ports/services.
    important_ports = [53, 80, 443, 8080, 5353, 6000, 6001, 6010, 6011, 7826]
    important_port_stats = {}

    for port in important_ports:
        subset = df[(df["src_port"] == port) | (df["dst_port"] == port)].copy()
        important_port_stats[str(port)] = {
            "flow_count": int(len(subset)),
            "avg_duration": float(subset["duration"].mean()) if len(subset) > 0 else 0.0,
            "avg_total_bytes": float(subset["total_bytes"].mean()) if len(subset) > 0 else 0.0,
            "network_scope_counts": subset["network_scope"].value_counts(dropna=False).to_dict(),
            "service_counts": subset["service"].value_counts(dropna=False).to_dict(),
        }

    # Top talkers.
    top_src_ips = df["src_ip"].value_counts(dropna=False).head(15).to_dict()
    top_dst_ips = df["dst_ip"].value_counts(dropna=False).head(15).to_dict()

    # Duration / traffic summaries.
    summary_stats = {
        "duration_mean": float(df["duration"].mean()),
        "duration_median": float(df["duration"].median()),
        "total_packets_mean": float(df["total_packets"].mean()),
        "total_bytes_mean": float(df["total_bytes"].mean()),
        "bytes_per_second_mean": float(df["bytes_per_second"].mean()),
        "packets_per_second_mean": float(df["packets_per_second"].mean()),
    }

    # Save charts.
    save_bar_chart(
        df["service"].value_counts(),
        title="Service Distribution",
        xlabel="Service",
        ylabel="Flow Count",
        output_path=REPORTS_DIR / "service_distribution.png",
        top_n=15,
    )

    save_bar_chart(
        df["network_scope"].value_counts(),
        title="Network Scope Distribution",
        xlabel="Scope",
        ylabel="Flow Count",
        output_path=REPORTS_DIR / "network_scope_distribution.png",
    )

    save_bar_chart(
        df["dst_port"].value_counts(),
        title="Top Destination Ports",
        xlabel="Destination Port",
        ylabel="Flow Count",
        output_path=REPORTS_DIR / "top_dst_ports.png",
        top_n=20,
    )

    # Build summary object.
    summary = {
        "total_flows": total_flows,
        "ip_version_counts": ip_version_counts,
        "proto_counts": proto_counts,
        "service_counts": service_counts,
        "network_scope_counts": network_scope_counts,
        "top_src_ports": top_src_ports,
        "top_dst_ports": top_dst_ports,
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips,
        "important_port_stats": important_port_stats,
        "summary_stats": summary_stats,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    # Save readable text summary.
    lines = []
    lines.append("Local Flow Analysis Summary")
    lines.append("=" * 40)
    lines.append(f"Total flows: {total_flows}")
    lines.append("")

    lines.append("IP version counts:")
    for k, v in ip_version_counts.items():
        lines.append(f"  {k}: {v}")
    lines.append("")

    lines.append("Protocol counts:")
    for k, v in proto_counts.items():
        lines.append(f"  {k}: {v}")
    lines.append("")

    lines.append("Top services:")
    for k, v in list(service_counts.items())[:15]:
        lines.append(f"  {k}: {v}")
    lines.append("")

    lines.append("Network scope counts:")
    for k, v in network_scope_counts.items():
        lines.append(f"  {k}: {v}")
    lines.append("")

    lines.append("Top destination ports:")
    for k, v in top_dst_ports.items():
        lines.append(f"  {k}: {v}")
    lines.append("")

    lines.append("Important port statistics:")
    for port, stats in important_port_stats.items():
        lines.append(f"  Port {port}:")
        lines.append(f"    flow_count: {stats['flow_count']}")
        lines.append(f"    avg_duration: {stats['avg_duration']:.4f}")
        lines.append(f"    avg_total_bytes: {stats['avg_total_bytes']:.4f}")
        lines.append(f"    network_scope_counts: {stats['network_scope_counts']}")
        lines.append(f"    service_counts: {stats['service_counts']}")
    lines.append("")

    lines.append("Summary stats:")
    for k, v in summary_stats.items():
        lines.append(f"  {k}: {v:.4f}")

    OUTPUT_TXT.write_text("\n".join(lines), encoding="utf-8")

    print("Local flow analysis finished.")
    print("Input:", INPUT_CSV)
    print("JSON summary:", OUTPUT_JSON)
    print("Text summary:", OUTPUT_TXT)
    print("Charts:")
    print(REPORTS_DIR / "service_distribution.png")
    print(REPORTS_DIR / "network_scope_distribution.png")
    print(REPORTS_DIR / "top_dst_ports.png")
    print()
    print("Top services:")
    print(df["service"].value_counts().head(15))
    print()
    print("Network scope counts:")
    print(df["network_scope"].value_counts())
    print()
    print("Top destination ports:")
    print(df["dst_port"].value_counts().head(20))


if __name__ == "__main__":
    main()