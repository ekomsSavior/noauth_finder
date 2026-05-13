#!/usr/bin/env python3
"""
noauth_finder.py — Find unauthenticated web UIs on your network.

Scans hosts/subnets for any web interface that doesn't require a login:
  - C2 panels, router configs, IoT dashboards
  - Printers, cameras, NAS admin panels
  - Kubernetes dashboards, Prometheus, Grafana, Jenkins
  - phpMyAdmin, Adminer, Portainer, Webmin
  - Any HTTP 200 on common admin paths

Internet-scale:
  - Scan /8, /16, or any CIDR range
  - Random sampling for wide coverage
  - Rate-limited scanning for politeness
  - Load multiple CIDRs from file (e.g., country ASN blocks)
  - JSON export for post-processing
"""

import argparse
import concurrent.futures
import ipaddress
import json
import random
import re
import socket
import sys
import time
import hashlib
import csv
import threading
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[-] Install requests: pip install requests")
    sys.exit(1)


# ── Config ────────────────────────────────────────────────────────────

COMMON_WEB_PORTS = [
    80, 443, 8080, 8443, 8888, 9090, 3000, 5000,
    8000, 8001, 8081, 8444, 9000, 9001, 9200, 5601,
    7070, 7443, 9443, 10000, 1234, 4443, 9999, 8880,
    8082, 8083, 8084, 9002, 18080, 18081, 8889, 9091,
    7474, 7687, 5432, 3306, 27017, 15672, 15692, 3001,
    9092, 9990, 9991, 4848, 8686, 8834, 8333, 8123,
]

ADMIN_PATHS = [
    "/", "/login", "/admin", "/dashboard", "/panel",
    "/index.html", "/index.php", "/status", "/api/status",
    "/api/v1/status", "/api/health", "/health", "/healthz",
    "/manage", "/manager", "/console", "/admin/status",
    "/device", "/webui", "/cgi-bin/status",
]

CRITICAL_PATHS = [
    "/config", "/config.js", "/config.json", "/api/config",
    "/api", "/api/v1", "/graphql", "/status",
    "/logs", "/backup", "/backups", "/export",
    "/api/export", "/api/state", "/api/findings",
    "/api/creds", "/api/credentials", "/api/tokens",
    "/api/keys", "/api/endpoints", "/shell", "/cmd",
    "/api/cmd", "/api/command", "/api/execute",
    "/api/upload", "/api/files", "/api/query",
    "/api/exec", "/api/shell", "/terminal",
    "/proxy", "/api/proxy", "/api/run",
    "/prometheus", "/metrics", "/api/agent",
    "/deployment", "/environment", "/secrets",
    "/.env", "/api/control", "/dump", "/api/dump",
]

AUTH_INDICATORS = [
    "login", "sign in", "signin", "log in", "authenticate",
    "unauthorized", "forbidden", "access denied",
    "authorization", "bearer", "api key required",
    "enter password", "password", "credentials required",
    "401 unauthorized", "401", "403 forbidden",
    "location.href.*login", "window.location.*login",
    "login-form", "login_form", "signin-form",
]

# ── UI ────────────────────────────────────────────────────────────────

C = type('C', (), {
    "G": "\033[92m", "R": "\033[91m", "Y": "\033[93m",
    "C": "\033[96m", "M": "\033[95m", "B": "\033[1m",
    "D": "\033[2m", "N": "\033[0m",
})()


def banner():
    print(f"""{C.C}
███▄▄▄▄    ▄██████▄          ▄████████ ███    █▄      ███        ▄█    █▄    
███▀▀▀██▄ ███    ███        ███    ███ ███    ███ ▀█████████▄   ███    ███   
███   ███ ███    ███        ███    ███ ███    ███    ▀███▀▀██   ███    ███   
███   ███ ███    ███        ███    ███ ███    ███     ███   ▀  ▄███▄▄▄▄███▄▄ 
███   ███ ███    ███      ▀███████████ ███    ███     ███     ▀▀███▀▀▀▀███▀  
███   ███ ███    ███        ███    ███ ███    ███     ███       ███    ███   
███   ███ ███    ███        ███    ███ ███    ███     ███       ███    ███   
 ▀█   █▀   ▀██████▀         ███    █▀  ████████▀     ▄████▀     ███    █▀    
                                                                             
  No-Auth Web UI Finder  ·  internet-scale  ·  by: ek0ms savi0r
{C.N}""")


# ── Performance: Session Reuse ────────────────────────────────────────

SESSION = None

def get_session():
    global SESSION
    if SESSION is None:
        SESSION = requests.Session()
        SESSION.verify = False
        SESSION.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
    return SESSION


# ── Target Resolution ────────────────────────────────────────────────

def expand_cidr(cidr):
    """Expand CIDR notation to list of IP strings. Handles /0 through /32."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError as e:
        print(f"  {C.R}✘ Invalid CIDR: {cidr} ({e}){C.N}")
        return []


def expand_cidr_sample(cidr, sample_size):
    """Sample N random IPs from a CIDR range without expanding it fully."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        num = net.num_addresses
        if num <= sample_size:
            return [str(ip) for ip in net.hosts()]

        # Randomly pick IPs from the range
        first = int(net[0])
        if net.prefixlen == 32:
            return [str(net[0])]

        result = set()
        max_attempts = sample_size * 10
        attempts = 0
        while len(result) < sample_size and attempts < max_attempts:
            attempts += 1
            offset = random.randint(1, num - 2)  # skip network/broadcast
            ip_str = str(ipaddress.IPv4Address(first + offset))
            result.add(ip_str)
        return list(result)
    except ValueError as e:
        print(f"  {C.R}✘ Invalid CIDR: {cidr} ({e}){C.N}")
        return []


def load_cidrs_from_file(path):
    """Load CIDR ranges from a file (one per line, # comments)."""
    cidrs = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    cidrs.append(line)
    except Exception as e:
        print(f"  {C.R}✘ Could not read {path}: {e}{C.N}")
    return cidrs


def resolve_target(target, randomize=False, sample=None):
    """Convert target string to list of IPs. Handles /24, /16, /8, /0, hostnames."""
    # File of CIDRs
    if target.startswith("file:"):
        path = target[5:]
        cidrs = load_cidrs_from_file(path)
        if not cidrs:
            return []
        all_ips = []
        for c in cidrs:
            if sample:
                all_ips.extend(expand_cidr_sample(c, max(1, sample // len(cidrs))))
            else:
                ips = expand_cidr(c)
                if len(ips) > 50000:
                    print(f"  {C.Y}⚠ {c} expands to {len(ips):,} hosts. "
                          f"Use --sample N to limit.{C.N}")
                all_ips.extend(ips)
        return all_ips

    # Standard CIDR notation
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.prefixlen < 8:
                print(f"  {C.Y}⚠ {target} = {net.num_addresses:,} IPs. "
                      f"Sampling recommended.{C.N}")
            if sample:
                ips = expand_cidr_sample(target, sample)
            else:
                ips = [str(ip) for ip in net.hosts()]
            return ips
        except ValueError:
            pass  # not CIDR, try hostname

    # Wildcard suffix: 10.0.0 → 10.0.0.0/24
    if target.count(".") == 2:
        return expand_cidr(f"{target}.0/24")

    # Single IP
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        return [target]

    # Hostname
    try:
        return [socket.gethostbyname(target)]
    except Exception:
        print(f"  {C.R}✘ Could not resolve: {target}{C.N}")
        return []


# ── Probing ───────────────────────────────────────────────────────────

def tcp_check(host, port, timeout=3, ipv6=False):
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((host, port))
        s.close()
        return r == 0
    except Exception:
        return False


def probe_http(host, port, path="/", timeout=5, ssl=False):
    proto = "https" if ssl else "http"
    url = f"{proto}://{host}:{port}{path}"
    session = get_session()
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        body_lower = (r.text or "").lower()[:3000]
        return {
            "status": r.status_code,
            "size": len(r.content),
            "title": extract_title(r.text),
            "server": r.headers.get("Server", ""),
            "auth": check_auth(r.status_code, body_lower, dict(r.headers)),
            "body": body_lower[:500],
            "url": url,
            "ssl": ssl,
            "headers": dict(r.headers),
            "body_hash": hashlib.md5(r.content[:5000]).hexdigest(),
        }
    except requests.exceptions.SSLError:
        return probe_http(host, port, path, timeout, ssl=False)
    except Exception:
        return None


def extract_title(html):
    if not html:
        return ""
    m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def check_auth(status, body_lower, headers):
    """Determine if a page requires authentication."""
    if status in (401, 403):
        return True
    if "www-authenticate" in {k.lower(): k for k in headers}:
        return True
    for ind in AUTH_INDICATORS:
        if ind in body_lower:
            return True
    return False


def classify_finding(title, body, path, server, status):
    """Identify the technology from response signatures."""
    text = f"{title} {body} {server}".lower()
    findings = []

    sigs = [
        ("Cockpit", ["cockpit"]),
        ("Kubernetes", ["kubernetes", "k8s"]),
        ("Grafana", ["grafana"]),
        ("Prometheus", ["prometheus"]),
        ("Jenkins", ["jenkins"]),
        ("phpMyAdmin", ["phpmyadmin"]),
        ("Adminer", ["adminer"]),
        ("Router/AP", ["router", "access point", "wifi settings"]),
        ("Camera", ["camera", "ip cam", "dvr"]),
        ("NAS", ["nas", "synology", "qnap", "truenas", "freenas"]),
        ("Printer", ["printer", "hp eprint", "brother"]),
        ("C2 Panel", ["c2 ", "command & control", "command and control",
                       "botnet", "agent panel"]),
        ("IoT Hub", ["smart home", "home assistant", "hassio"]),
        ("ESXi", ["vmware esxi", "vsphere"]),
        ("Pi-hole", ["pi-hole", "pihole"]),
        ("OctoPrint", ["octoprint"]),
        ("Jellyfin", ["jellyfin"]),
        ("Plex", ["plex"]),
        ("Portainer", ["portainer"]),
        ("RabbitMQ", ["rabbitmq", "management"]),
        ("Elasticsearch", ["elasticsearch"]),
        ("Kibana", ["kibana"]),
        ("Nginx", ["nginx"]),
        ("Apache", ["apache"]),
        ("Syncthing", ["syncthing"]),
        ("Nextcloud", ["nextcloud"]),
        ("WordPress", ["wordpress", "wp-"]),
        ("Webmin", ["webmin"]),
        ("Netdata", ["netdata"]),
        ("Node-RED", ["node-red"]),
        ("Flask", ["flask"]),
        ("Node.js", ["express", "node.js"]),
    ]

    for name, keywords in sigs:
        if any(k.lower() in text for k in keywords):
            findings.append(name)

    return findings


def scan_host_ports(host, ports, timeout=5, fast=False, ipv6=False):
    """Scan a single host for web UIs."""
    results = {}

    open_ports = []
    for port in ports:
        if tcp_check(host, port, timeout=2, ipv6=ipv6):
            open_ports.append(port)

    if not open_ports:
        return results

    ssl_first = {443, 8443, 9443, 7443}
    for port in open_ports:
        use_ssl = port in ssl_first
        resp = probe_http(host, port, "/", timeout, ssl=use_ssl)
        if not resp:
            resp = probe_http(host, port, "/", timeout, ssl=not use_ssl)
        if resp:
            results[port] = resp

            if not resp["auth"] and not fast:
                for path in ADMIN_PATHS + CRITICAL_PATHS:
                    if path == "/":
                        continue
                    r2 = probe_http(host, port, path, timeout, ssl=False)
                    if r2 and r2["status"] in (200, 301, 302) and not r2["auth"]:
                        if r2["body"] != resp["body"]:
                            resp.setdefault("extra_paths", []).append(path)
                    if len(resp.get("extra_paths", [])) >= 5:
                        break

    return results


def print_results(host, results):
    """Display scan results for one host."""
    noauth = {p: r for p, r in results.items() if not r.get("auth")}
    authed = {p: r for p, r in results.items() if r.get("auth")}

    if not noauth:
        return False

    noauth_ports = list(noauth.keys())
    r0 = noauth[noauth_ports[0]]
    title_str = f" — {C.B}{r0['title']}{C.N}" if r0.get("title") else ""

    print(f"\n{C.G}{C.B}[{len(noauth)} no-auth] {host}{title_str}{C.N}")
    print(f"  {'─' * 55}")

    for port, r in sorted(noauth.items()):
        server = f" [{r['server']}]" if r.get("server") else ""
        cls = classify_finding(r.get("title", ""), r.get("body", ""),
                               "/", r.get("server", ""), r.get("status", 0))
        tag = f" {C.M}{cls[0]}{C.N}" if cls else ""

        print(f"  {C.G}✔{C.N} :{port} ({r['status']}, {r.get('size', 0)}B){server}{tag}")

        extra = r.get("extra_paths", [])
        if extra:
            for path in extra[:3]:
                print(f"      {C.D}{path}{C.N}")

    if authed:
        authed_str = ", ".join(f":{p}" for p in authed)
        print(f"  {C.Y}⚠{C.N} Auth required: {authed_str}")

    return True


def full_report(host, results):
    """Generate a detailed report of findings."""
    noauth = {p: r for p, r in results.items() if not r.get("auth")}
    if not noauth:
        return None

    report = {
        "host": host,
        "timestamp": datetime.utcnow().isoformat(),
        "noauth_endpoints": [],
        "recommendations": [],
    }

    for port, r in sorted(noauth.items()):
        cls = classify_finding(r.get("title", ""), r.get("body", ""),
                               "/", r.get("server", ""), r.get("status", 0))
        entry = {
            "url": r.get("url"),
            "port": port,
            "status": r.get("status"),
            "title": r.get("title"),
            "server": r.get("server"),
            "tech": cls,
            "accessible_paths": r.get("extra_paths", []),
            "body_hash": r.get("body_hash", ""),
        }
        report["noauth_endpoints"].append(entry)
        report["recommendations"].append(
            f"Secure {r.get('url', f'http://{host}:{port}/')} — "
            f"no authentication required "
            f"({', '.join(cls) if cls else 'unknown'})"
        )

    for entry in report["noauth_endpoints"]:
        for path in entry.get("accessible_paths", []):
            if any(kw in path for kw in [
                    "api/state", "api/control", "api/command",
                    "api/exec", "shell", "cmd", "config",
                    "secrets", "keys", "export", "dump",
                    "api/creds", "api/findings", "terminal",
            ]):
                report["recommendations"].append(
                    f"CRITICAL: {entry['url']}{path} exposed without auth — "
                    "potential full system compromise"
                )

    return report


def export_csv(reports, filename):
    """Export findings to CSV format."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["host", "port", "url", "title", "tech", "status", "body_hash"])
        for report in reports:
            for ep in report["noauth_endpoints"]:
                writer.writerow([
                    report["host"],
                    ep["port"],
                    ep["url"],
                    ep["title"],
                    ", ".join(ep["tech"]),
                    ep["status"],
                    ep.get("body_hash", "")
                ])


def export_html(reports, filename):
    """Export findings to HTML format."""
    html = """<!DOCTYPE html>
<html>
<head><title>No-Auth Finder Results</title>
<style>
body { font-family: monospace; margin: 20px; background: #0a0a0a; color: #0f0; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #333; padding: 8px; text-align: left; }
th { background: #1a1a1a; }
.critical { background: #3a0000; }
</style>
</head>
<body>
<h1>No-Auth Web UI Finder Results</h1>
<table>
<tr><th>Host</th><th>Port</th><th>URL</th><th>Title</th><th>Tech</th><th>Status</th></tr>
"""
    for report in reports:
        for ep in report["noauth_endpoints"]:
            critical_class = ' class="critical"' if any(kw in str(ep.get("accessible_paths", [])) for kw in ["api/state", "api/control", "shell", "config"]) else ''
            html += f"<tr{critical_class}><td>{report['host']}</td><td>{ep['port']}</td><td>{ep['url']}</td><td>{ep['title']}</td><td>{', '.join(ep['tech'])}</td><td>{ep['status']}</td></tr>\n"
    html += "</table></body></html>"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)


# ── Internet-Scale Logic ──────────────────────────────────────────────

INTERNET_WARNING = f"""
{C.Y}[!] INTERNET-SCALE SCAN DETECTED{C.N}

  This will probe hosts across the open internet.
  • Use --sample N to limit hosts scanned
  • Use --random to avoid detection patterns
  • Use --delay MS to rate-limit requests (be polite)
  • Expect many timeouts — internet hosts are unreliable
  • Port 80/443 only recommended for internet-wide sweeps
"""


def is_internet_scan(targets, cidr_input):
    """Heuristic: if the CIDR covers public IP ranges, it's internet-scan."""
    if not targets:
        return False
    try:
        first = targets[0]
        octets = first.split(".")
        if octets[0] in ("10", "127"):
            return False
        if octets[0] == "172" and 16 <= int(octets[1]) <= 31:
            return False
        if octets[0] == "192" and octets[1] == "168":
            return False
        # Large broadcast ranges
        if len(targets) > 1000:
            return True
        return int(octets[0]) not in (10, 172, 192, 127)
    except Exception:
        return False


# ── Main ──────────────────────────────────────────────────────────────

def main():
    try:
        banner()

        parser = argparse.ArgumentParser(
            description="Find unauthenticated web UIs on your network"
        )
        parser.add_argument("target",
                            help="CIDR (192.168.1.0/24), IP, hostname, "
                                 "or file:ranges.txt (one CIDR per line)")
        parser.add_argument("--ports", type=str, default="web",
                            help="Ports: 'web' (~50), 'top10' (80,443,8080,8443), "
                                 "or comma list")
        parser.add_argument("--timeout", type=int, default=5)
        parser.add_argument("--threads", type=int, default=50)
        parser.add_argument("--deep", action="store_true",
                            help="Probe admin paths on every found service")
        parser.add_argument("--report", type=str, default="",
                            help="Save JSON report to file")
        parser.add_argument("--fast", action="store_true",
                            help="Skip deep path probing")
        parser.add_argument("--random", action="store_true",
                            help="Randomize host scan order (stealth)")
        parser.add_argument("--sample", type=int, default=0,
                            help="Randomly sample N IPs from CIDR range")
        parser.add_argument("--delay", type=int, default=0,
                            help="Delay in ms between hosts (rate limiting)")
        parser.add_argument("--top10", action="store_true",
                            help="Shorthand for --ports top10")
        parser.add_argument("--ipv6", action="store_true",
                            help="Enable IPv6 scanning")
        parser.add_argument("--output-format", choices=["json", "csv", "html"], default="json",
                            help="Output format for report")
        parser.add_argument("--no-color", action="store_true",
                            help="Disable colored output")
        parser.add_argument("--exclude", type=str, default="",
                            help="CIDR ranges to exclude (comma-separated)")

        args = parser.parse_args()

        # Disable colors if requested
        if args.no_color:
            for key in dir(C):
                if not key.startswith("_") and len(key) == 1:
                    setattr(C, key, "")

        # Port selection
        if args.top10:
            ports = [80, 443, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 9000]
        elif args.ports == "web":
            ports = COMMON_WEB_PORTS
        elif args.ports == "top10":
            ports = [80, 443, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 9000]
        elif "," in args.ports:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        else:
            ports = COMMON_WEB_PORTS

        # Resolve targets
        raw_target = args.target
        targets = resolve_target(raw_target, randomize=args.random,
                                 sample=args.sample)

        if not targets:
            return

        # Apply CIDR exclusions
        if args.exclude:
            excluded_nets = [ipaddress.ip_network(x.strip()) for x in args.exclude.split(",")]
            original_count = len(targets)
            targets = [ip for ip in targets if not any(ipaddress.ip_address(ip) in net for net in excluded_nets)]
            if len(targets) < original_count:
                print(f"  {C.Y}⚠ Excluded {original_count - len(targets)} IPs{C.N}")

        # Randomize if requested
        if args.random:
            random.shuffle(targets)

        # Internet scan check
        on_internet = is_internet_scan(targets, raw_target)
        if on_internet:
            print(INTERNET_WARNING)
            if args.sample == 0 and len(targets) > 50000:
                print(f"  {C.R}✘ {len(targets):,} hosts is too many without --sample.{C.N}")
                print(f"  {C.Y}  Use --sample N (e.g., --sample 10000) to limit.{C.N}")
                return

        total = len(targets)
        plural = "host" if total == 1 else "hosts"
        print(f"  {C.B}{total:,}{C.N} {plural} × {len(ports)} ports "
              f"({args.threads} threads)"
              + (f" — {C.D}{args.sample} sampled{C.N}" if args.sample else "")
              + (f" — {C.D}random order{C.N}" if args.random else "")
              + (f" — {C.D}IPv6{C.N}" if args.ipv6 else "")
              + "\n")

        done_count = 0
        found_any = False
        all_reports = []
        delay_sec = args.delay / 1000.0

        def scan_ip(ip):
            nonlocal done_count
            r = scan_host_ports(ip, ports, args.timeout, args.fast, ipv6=args.ipv6)
            done_count += 1
            if delay_sec:
                time.sleep(delay_sec)
            if total > 10 and done_count % max(1, total // 100) == 0:
                pct = done_count * 100 // total
                print(f"  {C.D}Progress: {done_count:,}/{total:,} ({pct}%){C.N}"
                      f"{'  [hit]' if r else ''}",
                      end="\r")
            return (ip, r)

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.threads) as ex:
            futmap = {ex.submit(scan_ip, ip): ip for ip in targets}
            for fut in concurrent.futures.as_completed(futmap):
                try:
                    ip, results = fut.result()
                    if results:
                        found = print_results(ip, results)
                        if found:
                            found_any = True
                            if args.report:
                                rpt = full_report(ip, results)
                                if rpt:
                                    all_reports.append(rpt)
                except Exception:
                    pass

        if total > 10:
            print(f"  {' ' * 60}", end="\r")

        if found_any:
            print(f"\n{C.G}{C.B}[+] Done. Found hosts with unauthenticated UIs.{C.N}")
        else:
            print(f"\n{C.Y}[-] No unauthenticated web UIs found.{C.N}")
            if on_internet:
                print(f"  {C.D}Tip: try --ports top10 for faster sweeps, "
                      f"or --sample 50000 for broader coverage{C.N}")

        # Export reports in requested format
        if args.report and all_reports:
            if args.output_format == "json":
                with open(args.report, "w") as f:
                    json.dump({"scan_meta": {
                        "target": raw_target,
                        "hosts_scanned": total,
                        "hosts_with_findings": len(all_reports),
                        "timestamp": datetime.utcnow().isoformat(),
                        "ports": ports,
                    }, "findings": all_reports}, f, indent=2)
            elif args.output_format == "csv":
                export_csv(all_reports, args.report)
            elif args.output_format == "html":
                export_html(all_reports, args.report)
            print(f"\n  Report saved: {args.report} ({len(all_reports)} hosts)")
            
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Scan interrupted by user{C.N}")
        if 'all_reports' in locals() and all_reports and 'args' in locals() and args.report:
            partial_file = args.report.replace('.json', '_partial.json')
            with open(partial_file, 'w') as f:
                json.dump({"partial": True, "findings": all_reports}, f, indent=2)
            print(f"  Partial report saved to {partial_file}")
        sys.exit(0)


if __name__ == "__main__":
    main()
