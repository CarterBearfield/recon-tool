#!/usr/bin/env python3
"""
recon_tool.py - A lightweight network reconnaissance tool.
Performs host discovery, port scanning, and basic service fingerprinting.

Usage:
    python recon_tool.py -t <target> [options]

Examples:
    python recon_tool.py -t 192.168.1.1
    python recon_tool.py -t 192.168.1.1 -p 1-1024
    python recon_tool.py -t scanme.nmap.org --top-ports
    python recon_tool.py -t 192.168.1.0/24 --ping-sweep
"""

import argparse
import socket
import struct
import sys
import ipaddress
import concurrent.futures
from datetime import datetime

# ──────────────────────────────────────────────
# Service banner / fingerprint database
# ──────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
             3306, 3389, 5900, 6379, 8080, 8443, 9200, 27017]


# ──────────────────────────────────────────────
# Utility helpers
# ──────────────────────────────────────────────
def print_banner():
    banner = r"""
  ____                      _____           _
 |  _ \ ___  ___ ___  _ __ |_   _|__   ___ | |
 | |_) / _ \/ __/ _ \| '_ \  | |/ _ \ / _ \| |
 |  _ <  __/ (_| (_) | | | | | | (_) | (_) | |
 |_| \_\___|\___\___/|_| |_| |_|\___/ \___/|_|

  Network Reconnaissance Tool  |  github.com/CarterBearfield
    """
    print("\033[92m" + banner + "\033[0m")


def timestamp():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, level="info"):
    colors = {"info": "\033[94m", "success": "\033[92m",
              "warn": "\033[93m", "error": "\033[91m"}
    reset = "\033[0m"
    prefix = {"info": "[*]", "success": "[+]", "warn": "[!]", "error": "[-]"}
    color = colors.get(level, "")
    tag   = prefix.get(level, "[?]")
    print(f"{color}{tag} [{timestamp()}] {msg}{reset}")


# ──────────────────────────────────────────────
# Host discovery
# ──────────────────────────────────────────────
def resolve_host(target: str) -> str | None:
    """Resolve a hostname to an IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Attempt a TCP connection to port 80 or 443 as a lightweight liveness check.
    A true ICMP ping requires root; this works unprivileged.
    """
    for port in (80, 443, 22):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return False


def ping_sweep(network: str, timeout: float = 0.5, threads: int = 100) -> list[str]:
    """Discover live hosts in a CIDR range."""
    log(f"Starting ping sweep on {network} ...")
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        log(f"Invalid network: {e}", "error")
        return []

    hosts = list(net.hosts())
    live  = []

    def check(ip):
        if ping_host(str(ip), timeout):
            return str(ip)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                live.append(result)
                log(f"Host up: {result}", "success")

    live.sort(key=lambda x: list(map(int, x.split("."))))
    return live


# ──────────────────────────────────────────────
# Port scanning
# ──────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 1.0) -> tuple[int, bool, str]:
    """Attempt a TCP connect to a single port. Returns (port, open, banner)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # Try to grab a banner (works for FTP, SSH, SMTP, etc.)
            sock.settimeout(0.5)
            banner = ""
            try:
                raw = sock.recv(1024)
                banner = raw.decode("utf-8", errors="replace").strip()
                banner = banner[:80]          # trim long banners
            except (socket.timeout, OSError):
                pass
            return (port, True, banner)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return (port, False, "")


def parse_port_range(port_str: str) -> list[int]:
    """Parse a port range string like '1-1024' or '80,443,8080'."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def port_scan(ip: str, ports: list[int], timeout: float = 1.0,
              threads: int = 100) -> list[dict]:
    """Scan a list of ports concurrently. Returns list of open port dicts."""
    log(f"Scanning {len(ports)} port(s) on {ip} ...")
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            port, is_open, banner = f.result()
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                results.append({"port": port, "service": service, "banner": banner})

    results.sort(key=lambda x: x["port"])
    return results


# ──────────────────────────────────────────────
# Reverse DNS lookup
# ──────────────────────────────────────────────
def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"


# ──────────────────────────────────────────────
# Output / reporting
# ──────────────────────────────────────────────
def print_results(ip: str, hostname: str, rdns: str, open_ports: list[dict]):
    divider = "─" * 60
    print(f"\n\033[1m{divider}\033[0m")
    print(f"\033[1m  Scan Report  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
    print(f"{divider}")
    print(f"  Target   : {hostname}")
    print(f"  IP       : {ip}")
    print(f"  rDNS     : {rdns}")
    print(f"  Open ports found: {len(open_ports)}")
    print(divider)

    if not open_ports:
        log("No open ports detected.", "warn")
    else:
        print(f"\033[1m  {'PORT':<8} {'SERVICE':<14} {'BANNER'}\033[0m")
        print(f"  {'─'*6:<8} {'─'*12:<14} {'─'*30}")
        for p in open_ports:
            port_str    = f"{p['port']}/tcp"
            service_str = p["service"]
            banner_str  = p["banner"] if p["banner"] else ""
            color = "\033[92m"   # green for open
            reset = "\033[0m"
            print(f"  {color}{port_str:<8} {service_str:<14} {banner_str}{reset}")

    print(divider + "\n")


def save_report(ip: str, hostname: str, rdns: str,
                open_ports: list[dict], filename: str):
    """Write a plain-text report to disk."""
    with open(filename, "w") as f:
        f.write(f"ReconTool Report\n")
        f.write(f"Generated : {datetime.now()}\n")
        f.write(f"Target    : {hostname}\n")
        f.write(f"IP        : {ip}\n")
        f.write(f"rDNS      : {rdns}\n\n")
        f.write(f"{'PORT':<10} {'SERVICE':<16} {'BANNER'}\n")
        f.write(f"{'─'*8:<10} {'─'*14:<16} {'─'*40}\n")
        for p in open_ports:
            f.write(f"{str(p['port'])+'/tcp':<10} {p['service']:<16} {p['banner']}\n")
    log(f"Report saved to {filename}", "success")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="recon_tool — lightweight network reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-t", "--target",    required=True,
                        help="Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",     default=None,
                        help="Port range or list, e.g. '1-1024' or '80,443,8080'")
    parser.add_argument("--top-ports",       action="store_true",
                        help="Scan the most common 20 ports")
    parser.add_argument("--ping-sweep",      action="store_true",
                        help="Perform a ping sweep on a CIDR range")
    parser.add_argument("--timeout",         type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads",         type=int,   default=100,
                        help="Max concurrent threads (default: 100)")
    parser.add_argument("-o", "--output",    default=None,
                        help="Save report to this file")
    return parser


def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    # ── Ping sweep mode ──────────────────────────
    if args.ping_sweep:
        live = ping_sweep(args.target, timeout=args.timeout, threads=args.threads)
        log(f"Sweep complete. {len(live)} host(s) responded.", "info")
        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(live) + "\n")
            log(f"Live hosts saved to {args.output}", "success")
        return

    # ── Single-host scan mode ────────────────────
    target = args.target

    log(f"Resolving {target} ...")
    ip = resolve_host(target)
    if not ip:
        log(f"Could not resolve host: {target}", "error")
        sys.exit(1)
    log(f"Resolved to {ip}", "success")

    rdns = reverse_dns(ip)
    log(f"Reverse DNS: {rdns}")

    # Determine port list
    if args.top_ports:
        ports = TOP_PORTS
        log(f"Using top {len(ports)} common ports.")
    elif args.ports:
        try:
            ports = parse_port_range(args.ports)
        except ValueError as e:
            log(f"Invalid port specification: {e}", "error")
            sys.exit(1)
        log(f"Port range: {args.ports} ({len(ports)} ports)")
    else:
        # Default: top ports
        ports = TOP_PORTS
        log(f"No port range specified — defaulting to top {len(ports)} ports.")

    open_ports = port_scan(ip, ports, timeout=args.timeout, threads=args.threads)

    print_results(target, target, rdns, open_ports)

    if args.output:
        save_report(ip, target, rdns, open_ports, args.output)


if __name__ == "__main__":
    main()