import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def run_command(command):
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )


def parse_ping_output(output):
    packet_loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", output)
    rtt_match = re.search(
        r"round-trip min/avg/max(?:/stddev)? = "
        r"(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)(?:/(\d+(?:\.\d+)?))?",
        output,
    )
    return {
        "packet_loss_percent": float(packet_loss_match.group(1)) if packet_loss_match else None,
        "rtt_min_ms": float(rtt_match.group(1)) if rtt_match else None,
        "rtt_avg_ms": float(rtt_match.group(2)) if rtt_match else None,
        "rtt_max_ms": float(rtt_match.group(3)) if rtt_match else None,
        "rtt_stddev_ms": float(rtt_match.group(4)) if rtt_match and rtt_match.group(4) else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Run lab metrics for the packet security stack")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, required=True, help="Primary service port to test")
    parser.add_argument("--scan-start", type=int, default=1, help="Start of port scan range")
    parser.add_argument("--scan-end", type=int, default=1024, help="End of port scan range")
    parser.add_argument("--scan-mode", choices=["sequential", "random"], default="sequential")
    parser.add_argument("--ping-count", type=int, default=5, help="Number of ping probes to send")
    parser.add_argument("--syn-count", type=int, default=100, help="Number of SYN packets for the flood simulation")
    parser.add_argument("--skip-flood", action="store_true", help="Skip the SYN flood phase")
    parser.add_argument("--sniff-iface", help="Interface for packet capture")
    parser.add_argument("--sniff-filter", default="ip", help="Capture filter for packet sniffing")
    parser.add_argument("--sniff-timeout", type=int, default=15, help="Seconds to sniff when capture is enabled")
    parser.add_argument("--output-dir", default="results", help="Directory for JSON and CSV artifacts")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    output_dir = script_dir / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "run_id": run_id,
        "target": args.target,
        "port_under_test": args.port,
        "started_at": datetime.now().isoformat(),
        "artifacts": {},
    }

    print(f"Run directory: {run_dir}")

    ping_result = run_command(["ping", "-c", str(args.ping_count), args.target])
    (run_dir / "ping.txt").write_text(ping_result.stdout + ping_result.stderr, encoding="utf-8")
    summary["artifacts"]["ping_output"] = str(run_dir / "ping.txt")
    summary["ping"] = parse_ping_output(ping_result.stdout)
    summary["ping"]["return_code"] = ping_result.returncode

    scan_json = run_dir / "scan_summary.json"
    scan_result = run_command(
        [
            sys.executable,
            str(script_dir / "port_scanner.py"),
            "--target",
            args.target,
            "--start",
            str(args.scan_start),
            "--end",
            str(args.scan_end),
            "--mode",
            args.scan_mode,
            "--output",
            str(scan_json),
        ]
    )
    (run_dir / "scan_stdout.txt").write_text(scan_result.stdout + scan_result.stderr, encoding="utf-8")
    summary["artifacts"]["scan_output"] = str(scan_json)
    summary["scan_return_code"] = scan_result.returncode
    if scan_json.exists():
        summary["scan"] = json.loads(scan_json.read_text(encoding="utf-8"))

    sniff_process = None
    sniff_summary_json = run_dir / "sniff_summary.json"
    sniff_csv = run_dir / "sniff_packets.csv"
    if args.sniff_iface:
        sniff_process = subprocess.Popen(
            [
                sys.executable,
                str(script_dir / "sniffer.py"),
                "--iface",
                args.sniff_iface,
                "--count",
                "0",
                "--timeout",
                str(args.sniff_timeout),
                "--filter",
                args.sniff_filter,
                "--output",
                str(sniff_csv),
                "--summary-output",
                str(sniff_summary_json),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        summary["artifacts"]["sniff_packets"] = str(sniff_csv)
        summary["artifacts"]["sniff_summary"] = str(sniff_summary_json)
        time.sleep(2)

    flood_json = run_dir / "flood_summary.json"
    if args.skip_flood:
        summary["flood_skipped"] = True
    else:
        flood_result = run_command(
            [
                sys.executable,
                str(script_dir / "syn_flood.py"),
                "--target",
                args.target,
                "--port",
                str(args.port),
                "--count",
                str(args.syn_count),
                "--output",
                str(flood_json),
            ]
        )
        (run_dir / "flood_stdout.txt").write_text(
            flood_result.stdout + flood_result.stderr,
            encoding="utf-8",
        )
        summary["artifacts"]["flood_output"] = str(flood_json)
        summary["flood_return_code"] = flood_result.returncode
        if flood_json.exists():
            summary["flood"] = json.loads(flood_json.read_text(encoding="utf-8"))

    if sniff_process:
        sniff_stdout, sniff_stderr = sniff_process.communicate(timeout=args.sniff_timeout + 10)
        (run_dir / "sniff_stdout.txt").write_text(sniff_stdout + sniff_stderr, encoding="utf-8")
        summary["sniff_return_code"] = sniff_process.returncode
        if sniff_summary_json.exists():
            summary["sniff"] = json.loads(sniff_summary_json.read_text(encoding="utf-8"))

    summary["completed_at"] = datetime.now().isoformat()
    summary_path = run_dir / "run_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Saved summary to {summary_path}")


if __name__ == "__main__":
    main()
