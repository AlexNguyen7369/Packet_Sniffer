from scapy.all import *
import argparse
from collections import defaultdict
import time

parser = argparse.ArgumentParser(description="SYN Flood Detector")
parser.add_argument("--iface", default="en0", help="Network interface to monitor")
parser.add_argument("--threshold", type=int, default=50, help="SYN packets per second to trigger alert")
args = parser.parse_args()

# track SYN count per source IP 
syn_counts = defaultdict(int)
last_reset = time.time()

def detect_syn_flood(pkt):
    global syn_counts, last_reset

    now = time.time()

    # reset counts every second
    if now - last_reset >= 1:
        for ip, count in syn_counts.items():
            if count >= args.threshold:
                print(f"[ALERT] Possible SYN flood from {ip} — {count} SYN packets/sec")
        syn_counts = defaultdict(int)
        last_reset = now

    # check for SYN flag (0x02) without ACK
    if TCP in pkt and pkt[TCP].flags == 0x02:
        src = pkt[IP].src
        syn_counts[src] += 1

print(f"Monitoring {args.iface} for SYN floods (threshold: {args.threshold} SYN/sec)")
print("Press Ctrl+C to stop\n")

sniff(iface=args.iface, prn=detect_syn_flood, store=False, filter="tcp")
