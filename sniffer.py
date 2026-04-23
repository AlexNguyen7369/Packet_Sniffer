from scapy.all import *

# UDP Proto Number = 17
# TCP Proto Number = 6

def IP_sniffer(pkt):

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


sniff(iface="en0", prn=IP_sniffer, store=False, count=10, filter="ip")