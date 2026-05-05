import argparse
import json
import random
import time

from scapy.all import IP, TCP, RandShort, sr1

parser = argparse.ArgumentParser(description="Port Scanner (lab use only)")
parser.add_argument("--target", required=True, help="Target IP address")
parser.add_argument("--start", type=int, default=1, help="Start of port range")
parser.add_argument("--end", type=int, default=1024, help="End of port range")
parser.add_argument("--mode", choices=["sequential", "random"], default="sequential", help="Scan mode")
parser.add_argument("--timeout", type=float, default=1.0, help="Per-port response timeout in seconds")
parser.add_argument("--output", help="Write scan summary to a JSON file")
args = parser.parse_args()


def scan_port(target, port):
    packet = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
    response = sr1(packet, timeout=args.timeout, verbose=False)
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK = open
            return "OPEN"
        elif response[TCP].flags == 0x14:  # RST = closed
            return "CLOSED"
    return "FILTERED"


ports = list(range(args.start, args.end + 1))
if args.mode == "random":
    random.shuffle(ports)

print(f"Scanning {args.target} ({args.mode}) ports {args.start}-{args.end}\n")
scan_started_at = time.time()
open_ports = []
status_counts = {"OPEN": 0, "CLOSED": 0, "FILTERED": 0}

for port in ports:
    status = scan_port(args.target, port)
    status_counts[status] += 1
    if status == "OPEN":
        open_ports.append(port)
        print(f"Port {port}: {status}")

summary = {
    "target": args.target,
    "mode": args.mode,
    "start_port": args.start,
    "end_port": args.end,
    "timeout_seconds": args.timeout,
    "duration_seconds": round(time.time() - scan_started_at, 3),
    "ports_scanned": len(ports),
    "open_ports": open_ports,
    "status_counts": status_counts,
}

print("\nScan summary:")
print(json.dumps(summary, indent=2))

if args.output:
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
