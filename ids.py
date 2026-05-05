from scapy.all import *
import argparse
import re
from collections import defaultdict
import time

# Simple Intrusion Detection System using Snort-style rules

parser = argparse.ArgumentParser(description="Rule-Based IDS (lab use only)")
parser.add_argument("--iface", default="en0", help="Network interface to monitor")
parser.add_argument("--rules", default="rules.txt", help="Path to rules file")
args = parser.parse_args()


# --- Rule Parser ---

def parse_rules(filepath):
    rules = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            rule = parse_single_rule(line)
            if rule:
                rules.append(rule)

    return rules


def parse_single_rule(line):
    # match: alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (options)
    pattern = r'alert\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.+)\)'
    match = re.match(pattern, line)
    if not match:
        print(f"[WARNING] Could not parse rule: {line}")
        return None

    proto, src_ip, src_port, dst_ip, dst_port, options_str = match.groups()

    # parse options like (msg:"text"; sid:1001; flags:S; threshold:50;)
    options = {}
    for opt in re.findall(r'(\w+):\s*"?([^";]+)"?\s*;', options_str):
        key, value = opt
        options[key] = value

    return {
        "proto": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "msg": options.get("msg", "No message"),
        "sid": options.get("sid", "0"),
        "flags": options.get("flags", None),
        "threshold": int(options.get("threshold", 0)),
    }


# --- Rule Matching ---

# for threshold-based rules: track packet counts per source IP per rule
threshold_counts = defaultdict(lambda: defaultdict(int))
last_reset = time.time()


def check_thresholds():
    global threshold_counts, last_reset

    now = time.time()
    if now - last_reset < 1:
        return

    for sid, ip_counts in threshold_counts.items():
        for ip, count in ip_counts.items():
            if count > 0:
                # find the rule to get its message
                for rule in loaded_rules:
                    if rule["sid"] == sid and count >= rule["threshold"]:
                        print(f"[ALERT] SID:{sid} | {rule['msg']} | {ip} — {count} packets/sec")
                        break

    threshold_counts = defaultdict(lambda: defaultdict(int))
    last_reset = now


def matches_ip(rule_ip, actual_ip):
    if rule_ip == "any":
        return True
    return rule_ip == actual_ip


def matches_port(rule_port, actual_port):
    if rule_port == "any":
        return True
    return int(rule_port) == actual_port


def matches_flags(rule_flags, pkt):
    if rule_flags is None:
        return True
    if TCP not in pkt:
        return False

    # map flag letters to scapy flag values
    flag_map = {"S": 0x02, "A": 0x10, "F": 0x01, "R": 0x04, "P": 0x08}
    expected = 0
    for char in rule_flags:
        expected |= flag_map.get(char, 0)

    return pkt[TCP].flags == expected


def match_packet(pkt, rule):
    if IP not in pkt:
        return False

    # check protocol
    proto = rule["proto"]
    if proto == "tcp" and TCP not in pkt:
        return False
    if proto == "udp" and UDP not in pkt:
        return False
    if proto == "icmp" and ICMP not in pkt:
        return False

    # check IPs
    if not matches_ip(rule["src_ip"], pkt[IP].src):
        return False
    if not matches_ip(rule["dst_ip"], pkt[IP].dst):
        return False

    # check ports (only for TCP/UDP)
    if proto in ("tcp", "udp"):
        layer = TCP if proto == "tcp" else UDP
        if not matches_port(rule["src_port"], pkt[layer].sport):
            return False
        if not matches_port(rule["dst_port"], pkt[layer].dport):
            return False

    # check flags
    if not matches_flags(rule["flags"], pkt):
        return False

    return True


# --- Packet Handler ---

def handle_packet(pkt):
    check_thresholds()

    for rule in loaded_rules:
        if match_packet(pkt, rule):
            # threshold rule: count instead of alerting immediately
            if rule["threshold"] > 0:
                src = pkt[IP].src
                threshold_counts[rule["sid"]][src] += 1
            else:
                src = pkt[IP].src
                dst = pkt[IP].dst
                print(f"[ALERT] SID:{rule['sid']} | {rule['msg']} | {src} -> {dst}")


# --- Main ---

loaded_rules = parse_rules(args.rules)
print(f"Loaded {len(loaded_rules)} rules from {args.rules}")
for rule in loaded_rules:
    print(f"  SID:{rule['sid']} — {rule['msg']}")

print(f"\nMonitoring {args.iface}... Press Ctrl+C to stop\n")

sniff(iface=args.iface, prn=handle_packet, store=False, filter="ip")
