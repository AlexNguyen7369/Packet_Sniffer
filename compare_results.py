import argparse
import json
from pathlib import Path


def load_summary(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fmt(value, suffix=""):
    if value is None:
        return "n/a"
    return f"{value}{suffix}"


def print_change(label, before, after, suffix=""):
    print(f"{label}:")
    print(f"  before: {fmt(before, suffix)}")
    print(f"  after:  {fmt(after, suffix)}")
    if before is not None and after is not None:
        delta = round(after - before, 3)
        print(f"  delta:  {fmt(delta, suffix)}")


def main():
    parser = argparse.ArgumentParser(description="Compare two run_summary.json files")
    parser.add_argument("--before", required=True, help="Path to baseline run_summary.json")
    parser.add_argument("--after", required=True, help="Path to post-change run_summary.json")
    args = parser.parse_args()

    before = load_summary(args.before)
    after = load_summary(args.after)

    print("Run comparison")
    print(f"Before file: {args.before}")
    print(f"After file:  {args.after}")
    print("")

    print_change(
        "Ping average RTT",
        before.get("ping", {}).get("rtt_avg_ms"),
        after.get("ping", {}).get("rtt_avg_ms"),
        " ms",
    )
    print_change(
        "Ping packet loss",
        before.get("ping", {}).get("packet_loss_percent"),
        after.get("ping", {}).get("packet_loss_percent"),
        "%",
    )
    print_change(
        "Ports scanned",
        before.get("scan", {}).get("ports_scanned"),
        after.get("scan", {}).get("ports_scanned"),
    )
    print_change(
        "Open ports found",
        len(before.get("scan", {}).get("open_ports", [])),
        len(after.get("scan", {}).get("open_ports", [])),
    )
    print_change(
        "Captured packets",
        before.get("sniff", {}).get("captured_packets"),
        after.get("sniff", {}).get("captured_packets"),
    )
    print_change(
        "Flood packets sent",
        before.get("flood", {}).get("sent_packets"),
        after.get("flood", {}).get("sent_packets"),
    )

    before_protocols = before.get("sniff", {}).get("protocol_counts", {})
    after_protocols = after.get("sniff", {}).get("protocol_counts", {})
    all_protocols = sorted(set(before_protocols) | set(after_protocols))
    if all_protocols:
        print("")
        print("Protocol counts:")
        for protocol in all_protocols:
            print(
                f"  {protocol}: before={before_protocols.get(protocol, 0)} "
                f"after={after_protocols.get(protocol, 0)}"
            )

    before_open = before.get("scan", {}).get("open_ports", [])
    after_open = after.get("scan", {}).get("open_ports", [])
    if before_open or after_open:
        print("")
        print(f"Open ports before: {before_open}")
        print(f"Open ports after:  {after_open}")


if __name__ == "__main__":
    main()
