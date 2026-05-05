# Packet Sniffer & Network Security Tools

A collection of Python network security scripts built with Scapy for CMPE 148 (Computer Networks) at SJSU.

## Requirements

- Python 3
- Scapy (`pip install scapy`)
- Root/sudo privileges (required for raw socket access)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy
```

## Tools

### Packet Sniffer

Captures and displays live network packets.

```bash
sudo python3 sniffer.py
sudo python3 sniffer.py --iface en0 --count 20 --filter tcp
```

| Flag       | Default | Description                          |
|------------|---------|--------------------------------------|
| `--iface`  | en0     | Network interface to sniff           |
| `--count`  | 10      | Number of packets to capture (0 = infinite) |
| `--filter` | ip      | BPF filter (e.g. tcp, udp, icmp)     |

### Port Scanner

Scans a target for open TCP ports using SYN packets.

```bash
sudo python3 port_scanner.py --target 192.168.1.1
sudo python3 port_scanner.py --target 192.168.1.1 --start 1 --end 1024 --mode random
```

| Flag       | Default    | Description              |
|------------|------------|--------------------------|
| `--target` | (required) | Target IP address        |
| `--start`  | 1          | Start of port range      |
| `--end`    | 1024       | End of port range        |
| `--mode`   | sequential | sequential or random     |

### SYN Flood Simulator

Sends spoofed SYN packets to a target to demonstrate a SYN flood attack.

```bash
sudo python3 syn_flood.py --target 192.168.1.1 --port 80
sudo python3 syn_flood.py --target 192.168.1.1 --port 80 --count 500
```

| Flag       | Default    | Description                              |
|------------|------------|------------------------------------------|
| `--target` | (required) | Target IP address                        |
| `--port`   | (required) | Target port                              |
| `--count`  | 100        | Number of SYN packets to send (0 = infinite) |

