from scapy.all import IP, TCP, sr1, RandShort
import argparse
import random

parser = argparse.ArgumentParser(description="Port Scanner (lab use only)")
parser.add_argument("--target", required=True, help="Target IP address")
parser.add_argument("--start", type=int, default=1, help="Start of port range")
parser.add_argument("--end", type=int, default=1024, help="End of port range")
parser.add_argument("--mode", choices=["sequential", "random"], default="sequential", help="Scan mode")
args = parser.parse_args()

def scan_port(target, port):
    packet = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
    response = sr1(packet, timeout=1, verbose=False)
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
for port in ports:
    status = scan_port(args.target, port)
    if status == "OPEN":
        print(f"Port {port}: {status}")