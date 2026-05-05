from scapy.all import *
import argparse
from collections import defaultdict

parser = argparse.ArgumentParser(description="Packet Logger - capture, log, and summarize traffic")
parser.add_argument("--iface", default="en0", help="Network interface to sniff")
parser.add_argument("--count", type=int, default=50, help="Number of packets to capture (0 = infinite)")
parser.add_argument("--filter", default="ip", help="BPF filter (e.g. tcp, udp, icmp)")
parser.add_argument("--output", default="capture.pcap", help="Output .pcap file name")
args = parser.parse_args()

# tracking stats during capture
stats = {
    "protocols": defaultdict(int),
    "src_ips": defaultdict(int),
    "dst_ips": defaultdict(int),
    "ports": defaultdict(int),
    "total_bytes": 0,
}


def log_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt.sprintf("%IP.proto%")
    size = len(pkt)

    # update stats
    stats["protocols"][proto] += 1
    stats["src_ips"][src] += 1
    stats["dst_ips"][dst] += 1
    stats["total_bytes"] += size

    # track destination ports
    if TCP in pkt:
        stats["ports"][pkt[TCP].dport] += 1
    elif UDP in pkt:
        stats["ports"][pkt[UDP].dport] += 1

    # print one-line summary per packet
    port_info = ""
    if TCP in pkt:
        port_info = f" | {pkt[TCP].sport} -> {pkt[TCP].dport}"
    elif UDP in pkt:
        port_info = f" | {pkt[UDP].sport} -> {pkt[UDP].dport}"

    print(f"[{proto:>5}] {src:>15} -> {dst:<15} | {size} bytes{port_info}")


def print_summary(packets):
    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)

    print(f"\nTotal packets: {len(packets)}")
    print(f"Total bytes:   {stats['total_bytes']}")

    print(f"\nProtocol breakdown:")
    for proto, count in sorted(stats["protocols"].items(), key=lambda x: x[1], reverse=True):
        print(f"  {proto:<10} {count} packets")

    print(f"\nTop source IPs:")
    for ip, count in sorted(stats["src_ips"].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip:<18} {count} packets")

    print(f"\nTop destination IPs:")
    for ip, count in sorted(stats["dst_ips"].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip:<18} {count} packets")

    if stats["ports"]:
        print(f"\nTop destination ports:")
        for port, count in sorted(stats["ports"].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {port:<8} {count} packets")

    print("=" * 60)


# capture
print(f"Capturing {args.count} packets on {args.iface} (filter: {args.filter})")
print(f"Saving to {args.output}\n")

packets = sniff(iface=args.iface, count=args.count, filter=args.filter, prn=log_packet)

# save and summarize
wrpcap(args.output, packets)
print_summary(packets)
print(f"\nSaved {len(packets)} packets to {args.output}")
