from scapy.all import *
import argparse

# UDP Proto Number = 17
# TCP Proto Number = 6

parser = argparse.ArgumentParser(description="Protocol Packet Sniffer (Default = IP)")
parser.add_argument("--iface", default="en0", help="Network interface to sniff")
parser.add_argument("--count", type=int, default=10, help="minimum amount of packets to capture before exiting (0 = infinite)")
parser.add_argument("--filter", default="ip", help="Protocol to sniff in packets, default is ip")
args = parser.parse_args()

def packet_sniffer(pkt):

    if IP in pkt:

        pkt_SRC_IP = pkt[IP].src
        pkt_DST_IP = pkt[IP].dst
        pkt_proto = pkt.sprintf("%IP.proto%")

        print(f"Packet ID: {pkt[IP].id}")
        print(f"Source IP: {pkt_SRC_IP}")
        print(f"Destination IP: {pkt_DST_IP}")
        print(f"Protocol: {pkt_proto}")

        if TCP in pkt:
            print(f"Source Port: {pkt[TCP].sport}")
            print(f"Destination Port: {pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"Source Port: {pkt[UDP].sport}")
            print(f"Destination Port: {pkt[UDP].dport}")
        
        print("\n")


sniff(iface=args.iface, prn=packet_sniffer, store=False, count=args.count, filter=args.filter)