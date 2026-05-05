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

### Packet Logger

Captures packets, prints live one-line summaries, saves to `.pcap`, and prints a traffic summary after capture.

```bash
sudo python3 packet_logger.py
sudo python3 packet_logger.py --iface en0 --count 100 --filter tcp --output capture.pcap
```

| Flag       | Default      | Description                          |
|------------|--------------|--------------------------------------|
| `--iface`  | en0          | Network interface to sniff           |
| `--count`  | 50           | Number of packets to capture (0 = infinite) |
| `--filter` | ip           | BPF filter (e.g. tcp, udp, icmp)     |
| `--output` | capture.pcap | Output file name                     |

### SYN Flood Detector

Monitors network traffic and alerts when a possible SYN flood is detected.

```bash
sudo python3 syn_detect.py
sudo python3 syn_detect.py --iface en0 --threshold 100
```

| Flag          | Default | Description                              |
|---------------|---------|------------------------------------------|
| `--iface`     | en0     | Network interface to monitor             |
| `--threshold` | 50      | SYN packets/sec to trigger an alert      |

### Rule-Based IDS

Intrusion detection system that matches live traffic against Snort-style rules defined in a text file.

```bash
sudo python3 ids.py
sudo python3 ids.py --iface en0 --rules rules.txt
```

| Flag      | Default   | Description                |
|-----------|-----------|----------------------------|
| `--iface` | en0       | Network interface to monitor |
| `--rules` | rules.txt | Path to rules file         |

Rules are defined in `rules.txt` using this format:

```
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1001;)
alert tcp any any -> any any (msg:"Possible SYN flood"; flags:S; threshold:50; sid:1003;)
```

Supports: protocol matching, IP/port filtering, TCP flag checks, and rate-based threshold alerts.

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

## Firewall upgrades

After the VPN works, harden the outside interfaces with inbound ACLs. The goal is to allow only:

- IKE on UDP `500`
- NAT-T on UDP `4500`
- ESP for IPsec payload transport
- ICMP for lab testing

Everything else from the outside should be denied and logged.

### Router A outside firewall

Apply this to `R1` if the outside interface is `s0/0/0` and the peer is `209.165.200.230`:

```text
configure terminal

ip access-list extended OUTSIDE-IN
 permit udp host 209.165.200.230 host 209.165.200.225 eq 500
 permit udp host 209.165.200.230 host 209.165.200.225 eq 4500
 permit esp host 209.165.200.230 host 209.165.200.225
 permit icmp any any
 deny ip any any log
exit

interface s0/0/0
 ip access-group OUTSIDE-IN in
exit

end
write memory
```

### Router B outside firewall

Apply this to `R2` if the outside interface is `s0/0/0` and the peer is `209.165.200.225`:

```text
configure terminal

ip access-list extended OUTSIDE-IN
 permit udp host 209.165.200.225 host 209.165.200.230 eq 500
 permit udp host 209.165.200.225 host 209.165.200.230 eq 4500
 permit esp host 209.165.200.225 host 209.165.200.230
 permit icmp any any
 deny ip any any log
exit

interface s0/0/0
 ip access-group OUTSIDE-IN in
exit

end
write memory
```

### Stronger submission-ready version

If your instructor wants tighter rules, keep ICMP limited to testing only and allow only the exact inside-to-inside traffic required by the lab. A good explanation for your write-up is:

- first allow VPN control and transport traffic
- then allow only approved diagnostic traffic
- finally deny and log all other inbound traffic

### Firewall verification

After applying the ACLs, run:

```text
show access-lists
show run interface s0/0/0
show crypto isakmp sa
show crypto ipsec sa
```

Expected result:

- the ACL hit counters should increase on the VPN permit rules
- the tunnel should still establish successfully
- unwanted inbound traffic should be blocked by the final deny
- ping should still work if you kept the ICMP permit

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
