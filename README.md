# Packet Sniffer & Network Security Tools

A collection of Python network security scripts built with Scapy for CMPE 148 (Computer Networks) at SJSU.

This project now supports two larger outcomes:

1. Deploy an IPsec VPN tunnel in Packet Tracer
2. Run repeatable attack simulations and compare metrics before and after IPsec

Use this only in a lab you own or have explicit authorization to test.

## Requirements

- Python 3
- Scapy
- Root or sudo privileges for raw socket access

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Tools

### Packet Sniffer

Captures and displays live network packets, and can now export CSV and summary JSON.

```bash
sudo python3 sniffer.py
sudo python3 sniffer.py --iface en0 --count 20 --filter tcp
sudo python3 sniffer.py --iface en0 --count 0 --timeout 15 --filter ip --output packets.csv --summary-output sniff_summary.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--iface` | `en0` | Network interface to sniff |
| `--count` | `10` | Number of packets to capture (`0` = infinite until timeout/manual stop) |
| `--filter` | `ip` | BPF filter such as `tcp`, `udp`, or `icmp` |
| `--timeout` | unset | Stop capture after N seconds |
| `--output` | unset | Write captured packet rows to CSV |
| `--summary-output` | unset | Write capture metrics to JSON |

### Port Scanner

Scans a target for open TCP ports using SYN packets and now saves a JSON summary.

```bash
sudo python3 port_scanner.py --target 192.168.1.1
sudo python3 port_scanner.py --target 192.168.1.1 --start 1 --end 1024 --mode random --output scan_summary.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | Target IP address |
| `--start` | `1` | Start of port range |
| `--end` | `1024` | End of port range |
| `--mode` | `sequential` | `sequential` or `random` |
| `--timeout` | `1.0` | Per-port response timeout in seconds |
| `--output` | unset | Write scan metrics to JSON |

### SYN Flood Simulator

Sends spoofed SYN packets to a target to demonstrate a SYN flood attack in the lab, with optional summary JSON output.

```bash
sudo python3 syn_flood.py --target 192.168.1.1 --port 80
sudo python3 syn_flood.py --target 192.168.1.1 --port 80 --count 500 --output flood_summary.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | Target IP address |
| `--port` | required | Target port |
| `--count` | `100` | Number of SYN packets to send (`0` = infinite) |
| `--output` | unset | Write flood metrics to JSON |

## Metrics workflow

### `metrics_runner.py`

Runs ping, port scan, optional sniffing, and optional flood traffic, then saves everything to a timestamped `results/<timestamp>/` directory.

Baseline run:

```bash
python3 metrics_runner.py --target 192.168.20.10 --port 80 --scan-start 1 --scan-end 1024 --skip-flood
```

Full authorized lab run:

```bash
sudo python3 metrics_runner.py \
  --target 192.168.20.10 \
  --port 80 \
  --scan-start 1 \
  --scan-end 1024 \
  --syn-count 200 \
  --sniff-iface en0 \
  --sniff-timeout 20
```

Each run can record:

- `ping.txt`
- `scan_summary.json`
- `scan_stdout.txt`
- `flood_summary.json`
- `flood_stdout.txt`
- `sniff_packets.csv`
- `sniff_summary.json`
- `sniff_stdout.txt`
- `run_summary.json`

### `compare_results.py`

Compares two `run_summary.json` files, such as before and after IPsec.

```bash
python3 compare_results.py \
  --before results/<before_timestamp>/run_summary.json \
  --after results/<after_timestamp>/run_summary.json
```

## IPsec VPN Tunnel in Packet Tracer

The `network_security_stack.pkt` file should be configured as a site-to-site IPsec tunnel between two routers.

### Recommended lab addressing

- Site A LAN: `192.168.10.0/24`
- Site A router outside: `209.165.200.225/30`
- Site B LAN: `192.168.20.0/24`
- Site B router outside: `209.165.200.230/30`

Adjust the commands below if your topology uses different interfaces or subnets.

### Router A

```text
enable
configure terminal

hostname R1

crypto isakmp policy 10
 encryption aes
 hash sha
 authentication pre-share
 group 2
 lifetime 86400
exit

crypto isakmp key cisco123 address 209.165.200.230

access-list 110 permit ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255

crypto ipsec transform-set TS esp-aes esp-sha-hmac
 mode tunnel
exit

crypto map VPN-MAP 10 ipsec-isakmp
 set peer 209.165.200.230
 set transform-set TS
 match address 110
exit

interface g0/0
 ip address 192.168.10.1 255.255.255.0
 no shutdown
exit

interface s0/0/0
 ip address 209.165.200.225 255.255.255.252
 crypto map VPN-MAP
 no shutdown
exit

ip route 192.168.20.0 255.255.255.0 209.165.200.230
end
write memory
```

### Router B

```text
enable
configure terminal

hostname R2

crypto isakmp policy 10
 encryption aes
 hash sha
 authentication pre-share
 group 2
 lifetime 86400
exit

crypto isakmp key cisco123 address 209.165.200.225

access-list 110 permit ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255

crypto ipsec transform-set TS esp-aes esp-sha-hmac
 mode tunnel
exit

crypto map VPN-MAP 10 ipsec-isakmp
 set peer 209.165.200.225
 set transform-set TS
 match address 110
exit

interface g0/0
 ip address 192.168.20.1 255.255.255.0
 no shutdown
exit

interface s0/0/0
 ip address 209.165.200.230 255.255.255.252
 crypto map VPN-MAP
 no shutdown
exit

ip route 192.168.10.0 255.255.255.0 209.165.200.225
end
write memory
```

### Tunnel verification

Run these on both routers after generating traffic across the tunnel:

```text
show crypto isakmp sa
show crypto ipsec sa
show access-lists
show crypto map
```

Expected result:

- ISAKMP state should show an active security association
- IPsec encaps and decaps counters should increase
- A ping from one inside PC to the other should succeed

## Suggested lab sequence

1. Run `metrics_runner.py` before IPsec is applied.
2. Bring up the VPN tunnel in Packet Tracer.
3. Repeat the same run after IPsec is active.
4. Save router output from `show crypto isakmp sa` and `show crypto ipsec sa`.
5. Run `compare_results.py` on the two summary files.

## What still needs real lab validation

These parts still need testing on the lab network:

- actual IPsec tunnel bring-up in the Packet Tracer topology
- packet capture on the correct interface
- raw SYN traffic behavior against your lab host
- before and after performance comparison using real traffic and router counters
