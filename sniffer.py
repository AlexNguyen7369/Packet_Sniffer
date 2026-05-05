import argparse
import csv
import json
import time
from collections import Counter

from scapy.all import IP, TCP, UDP, sniff


parser = argparse.ArgumentParser(description="Protocol Packet Sniffer (Default = IP)")
parser.add_argument("--iface", default="en0", help="Network interface to sniff")
parser.add_argument(
    "--count",
    type=int,
    default=10,
    help="Minimum number of packets to capture before exiting (0 = infinite)",
)
parser.add_argument("--filter", default="ip", help="BPF filter, default is ip")
parser.add_argument("--timeout", type=int, default=None, help="Stop after N seconds")
parser.add_argument("--output", help="Write packet records to a CSV file")
parser.add_argument("--summary-output", help="Write capture summary metrics to a JSON file")
args = parser.parse_args()

packet_count = 0
protocol_counts = Counter()
source_counts = Counter()
destination_counts = Counter()
capture_started_at = time.time()

csv_writer = None
csv_handle = None
if args.output:
    csv_handle = open(args.output, "w", newline="", encoding="utf-8")
    csv_writer = csv.DictWriter(
        csv_handle,
        fieldnames=[
            "timestamp",
            "packet_id",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
        ],
    )
    csv_writer.writeheader()


def packet_sniffer(pkt):
    global packet_count

    if IP not in pkt:
        return

    packet_count += 1
    pkt_src_ip = pkt[IP].src
    pkt_dst_ip = pkt[IP].dst
    pkt_proto = pkt.sprintf("%IP.proto%")
    source_port = ""
    destination_port = ""

    protocol_counts[pkt_proto] += 1
    source_counts[pkt_src_ip] += 1
    destination_counts[pkt_dst_ip] += 1

    print(f"Packet ID: {pkt[IP].id}")
    print(f"Source IP: {pkt_src_ip}")
    print(f"Destination IP: {pkt_dst_ip}")
    print(f"Protocol: {pkt_proto}")

    if TCP in pkt:
        source_port = pkt[TCP].sport
        destination_port = pkt[TCP].dport
        print(f"Source Port: {source_port}")
        print(f"Destination Port: {destination_port}")
    elif UDP in pkt:
        source_port = pkt[UDP].sport
        destination_port = pkt[UDP].dport
        print(f"Source Port: {source_port}")
        print(f"Destination Port: {destination_port}")

    print("")

    if csv_writer:
        csv_writer.writerow(
            {
                "timestamp": time.time(),
                "packet_id": pkt[IP].id,
                "source_ip": pkt_src_ip,
                "destination_ip": pkt_dst_ip,
                "protocol": pkt_proto,
                "source_port": source_port,
                "destination_port": destination_port,
            }
        )


sniff(
    iface=args.iface,
    prn=packet_sniffer,
    store=False,
    count=args.count,
    filter=args.filter,
    timeout=args.timeout,
)

capture_duration = round(time.time() - capture_started_at, 3)
summary = {
    "interface": args.iface,
    "filter": args.filter,
    "captured_packets": packet_count,
    "duration_seconds": capture_duration,
    "protocol_counts": dict(protocol_counts),
    "top_sources": source_counts.most_common(5),
    "top_destinations": destination_counts.most_common(5),
}

print("Capture summary:")
print(json.dumps(summary, indent=2))

if csv_handle:
    csv_handle.close()

if args.summary_output:
    with open(args.summary_output, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
