import argparse
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np


def load_summary(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def plot_ping(ax, before, after):
    metrics = ["Min", "Avg", "Max"]
    before_vals = [
        before.get("ping", {}).get("rtt_min_ms", 0) or 0,
        before.get("ping", {}).get("rtt_avg_ms", 0) or 0,
        before.get("ping", {}).get("rtt_max_ms", 0) or 0,
    ]
    after_vals = [
        after.get("ping", {}).get("rtt_min_ms", 0) or 0,
        after.get("ping", {}).get("rtt_avg_ms", 0) or 0,
        after.get("ping", {}).get("rtt_max_ms", 0) or 0,
    ]

    x = np.arange(len(metrics))
    width = 0.35
    ax.bar(x - width / 2, before_vals, width, label="Before IPsec", color="#e74c3c")
    ax.bar(x + width / 2, after_vals, width, label="After IPsec", color="#2ecc71")
    ax.set_ylabel("RTT (ms)")
    ax.set_title("Ping Round-Trip Time")
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.legend()


def plot_packet_loss(ax, before, after):
    labels = ["Before IPsec", "After IPsec"]
    values = [
        before.get("ping", {}).get("packet_loss_percent", 0) or 0,
        after.get("ping", {}).get("packet_loss_percent", 0) or 0,
    ]
    colors = ["#e74c3c", "#2ecc71"]
    bars = ax.bar(labels, values, color=colors)
    ax.set_ylabel("Packet Loss (%)")
    ax.set_title("Ping Packet Loss")
    ax.set_ylim(0, max(max(values) * 1.3, 5))

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                f"{val}%", ha="center", fontsize=10)


def plot_port_scan(ax, before, after):
    categories = ["Open", "Closed", "Filtered"]
    before_counts = before.get("scan", {}).get("status_counts", {})
    after_counts = after.get("scan", {}).get("status_counts", {})

    before_vals = [
        before_counts.get("OPEN", 0),
        before_counts.get("CLOSED", 0),
        before_counts.get("FILTERED", 0),
    ]
    after_vals = [
        after_counts.get("OPEN", 0),
        after_counts.get("CLOSED", 0),
        after_counts.get("FILTERED", 0),
    ]

    x = np.arange(len(categories))
    width = 0.35
    ax.bar(x - width / 2, before_vals, width, label="Before IPsec", color="#e74c3c")
    ax.bar(x + width / 2, after_vals, width, label="After IPsec", color="#2ecc71")
    ax.set_ylabel("Port Count")
    ax.set_title("Port Scan Results")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()


def plot_protocols(ax, before, after):
    before_protocols = before.get("sniff", {}).get("protocol_counts", {})
    after_protocols = after.get("sniff", {}).get("protocol_counts", {})
    all_protocols = sorted(set(before_protocols) | set(after_protocols))

    if not all_protocols:
        ax.text(0.5, 0.5, "No protocol data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Protocol Breakdown")
        return

    before_vals = [before_protocols.get(p, 0) for p in all_protocols]
    after_vals = [after_protocols.get(p, 0) for p in all_protocols]

    x = np.arange(len(all_protocols))
    width = 0.35
    ax.bar(x - width / 2, before_vals, width, label="Before IPsec", color="#e74c3c")
    ax.bar(x + width / 2, after_vals, width, label="After IPsec", color="#2ecc71")
    ax.set_ylabel("Packet Count")
    ax.set_title("Protocol Breakdown")
    ax.set_xticks(x)
    ax.set_xticklabels(all_protocols)
    ax.legend()


def plot_flood_stats(ax, before, after):
    labels = ["Packets Sent", "Duration (s)", "Packets/sec"]

    before_flood = before.get("flood", {})
    after_flood = after.get("flood", {})

    before_vals = [
        before_flood.get("sent_packets", 0) or 0,
        before_flood.get("duration_seconds", 0) or 0,
        before_flood.get("approx_packets_per_second", 0) or 0,
    ]
    after_vals = [
        after_flood.get("sent_packets", 0) or 0,
        after_flood.get("duration_seconds", 0) or 0,
        after_flood.get("approx_packets_per_second", 0) or 0,
    ]

    x = np.arange(len(labels))
    width = 0.35
    ax.bar(x - width / 2, before_vals, width, label="Before IPsec", color="#e74c3c")
    ax.bar(x + width / 2, after_vals, width, label="After IPsec", color="#2ecc71")
    ax.set_ylabel("Value")
    ax.set_title("SYN Flood Metrics")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.legend()


def plot_summary_table(ax, before, after):
    ax.axis("off")
    rows = [
        ["Ping Avg RTT",
         f"{before.get('ping', {}).get('rtt_avg_ms', 'n/a')} ms",
         f"{after.get('ping', {}).get('rtt_avg_ms', 'n/a')} ms"],
        ["Packet Loss",
         f"{before.get('ping', {}).get('packet_loss_percent', 'n/a')}%",
         f"{after.get('ping', {}).get('packet_loss_percent', 'n/a')}%"],
        ["Open Ports",
         str(len(before.get("scan", {}).get("open_ports", []))),
         str(len(after.get("scan", {}).get("open_ports", [])))],
        ["Captured Packets",
         str(before.get("sniff", {}).get("captured_packets", "n/a")),
         str(after.get("sniff", {}).get("captured_packets", "n/a"))],
        ["Flood Packets Sent",
         str(before.get("flood", {}).get("sent_packets", "n/a")),
         str(after.get("flood", {}).get("sent_packets", "n/a"))],
    ]

    table = ax.table(
        cellText=rows,
        colLabels=["Metric", "Before IPsec", "After IPsec"],
        loc="center",
        cellLoc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.5)
    ax.set_title("Summary Comparison", pad=20, fontsize=12, fontweight="bold")


def main():
    parser = argparse.ArgumentParser(description="Visualize before/after IPsec comparison")
    parser.add_argument("--before", required=True, help="Path to baseline run_summary.json")
    parser.add_argument("--after", required=True, help="Path to post-IPsec run_summary.json")
    parser.add_argument("--output", default="comparison.png", help="Output image file")
    args = parser.parse_args()

    before = load_summary(args.before)
    after = load_summary(args.after)

    fig, axes = plt.subplots(2, 3, figsize=(16, 10))
    fig.suptitle("Network Security Metrics: Before vs After IPsec", fontsize=14, fontweight="bold")

    plot_ping(axes[0, 0], before, after)
    plot_packet_loss(axes[0, 1], before, after)
    plot_port_scan(axes[0, 2], before, after)
    plot_protocols(axes[1, 0], before, after)
    plot_flood_stats(axes[1, 1], before, after)
    plot_summary_table(axes[1, 2], before, after)

    plt.tight_layout()
    plt.savefig(args.output, dpi=150)
    print(f"Saved comparison chart to {args.output}")
    plt.show()


if __name__ == "__main__":
    main()
