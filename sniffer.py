from scapy.all import *

# UDP Proto Number = 17
# TCP Proto Number = 6

def IP_sniffer(pkt):

    if IP in pkt:

        pkt_SRC_IP = pkt[IP].src
        pkt_DST_IP = pkt[IP].dst

        print(f"Packet ID: {pkt[IP].id}")
        print(f"Source IP: {pkt_SRC_IP}")
        print(f"Destination IP: {pkt_DST_IP}")

        if TCP in pkt:
            print(pkt.sprintf("%IP.proto%"))
            print(f"Source Port: {pkt[TCP].sport}")
            print(f"Destination Port: {pkt[TCP].dport}")
        elif UDP in pkt:
            print(pkt.sprintf("%IP.proto%"))
            print(f"Source Port: {pkt[UDP].sport}")
            print(f"Destination Port: {pkt[UDP].dport}")
        else:
            print(pkt.sprintf("%IP.proto%"))
        
        print("\n")


sniff(iface="en0", prn=IP_sniffer, store=False, count=10)