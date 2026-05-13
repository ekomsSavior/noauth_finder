# NoAuth Finder

**Find unauthenticated web interfaces — local network or internet-scale**

[![ek0ms](https://img.shields.io/badge/ek0ms-green)](ek0ms)

---

## What It Does

Scans any IP range for web interfaces that don't require a login. If it's serving content and there's no auth gate, you'll know it.

| Scope | Example | Hosts |
|-------|---------|-------|
| Single host | `python3 noauth_finder.py 10.0.0.42` | 1 |
| Local subnet | `python3 noauth_finder.py 192.168.1.0/24` | 254 |
| Large range | `python3 noauth_finder.py 10.0.0.0/16` | 65,534 |
| Internet sweep | `python3 noauth_finder.py 1.0.0.0/8 --sample 50000` | 16M+ sampled |
| CIDR file | `python3 noauth_finder.py file:ranges.txt` | Unlimited |

### Finds things like:

| Type | Examples |
|------|----------|
| C2 Panels | Nightcrawler, generic botnet dashboards, agent consoles |
| Infrastructure | Kubernetes, Grafana, Prometheus, Portainer, Jenkins |
| Network Gear | Routers, APs, ESXi, Webmin, Cockpit |
| IoT/Embedded | Cameras, printers, NAS (Synology/QNAP), Pi-hole |
| Databases | phpMyAdmin, Adminer, Mongo Express, Redis Commander |
| Dev Tools | Netdata, Node-RED, OctoPrint, Syncthing |
| Web Apps | WordPress, Nextcloud, Jellyfin, Plex |
| Custom APIs | Any `/api/state`, `/api/command`, `/api/config` left open |

---

## Features

- Session reuse for connection pooling and performance
- IPv6 support with `--ipv6` flag
- Response body hashing for deduplication
- Multiple output formats: JSON, CSV, HTML
- CIDR exclusion ranges with `--exclude`
- Color control with `--no-color` flag
- Graceful KeyboardInterrupt handling with partial report saving
- Rate limiting with `--delay MS`
- Random sampling and random host order for stealth
- Deep path probing on all unauthenticated services
- Automatic technology identification (40+ signatures)
- Critical path detection (api/state, api/control, shell, config)

---

## Quick Start

```bash
git clone https://github.com/ekomsSavior/NoAuth-Finder.git
cd NoAuth-Finder
pip install requests

# Single host
python3 noauth_finder.py 192.168.1.100

# Local subnet with deep admin path probing
python3 noauth_finder.py 192.168.1.0/24 --deep

# Save results as JSON
python3 noauth_finder.py 192.168.1.0/24 --report findings.json
```

---

## Internet-Scale Scanning

```bash
# Scan with random sampling (avoids sequential patterns)
python3 noauth_finder.py 1.0.0.0/8 --sample 50000 --random

# Scan only top 10 web ports for speed
python3 noauth_finder.py 1.0.0.0/8 --sample 100000 --ports top10 --random

# Scan from a file of CIDR ranges (e.g., country ASN blocks)
python3 noauth_finder.py file:asn_blocks.txt --sample 5000

# Rate-limited scan (be polite to the internet)
python3 noauth_finder.py 1.0.0.0/8 --sample 10000 --delay 50 --random

# Exclude specific ranges (e.g., your own IP space)
python3 noauth_finder.py 0.0.0.0/0 --sample 10000 --exclude 10.0.0.0/8,192.168.0.0/16

# Save as CSV for spreadsheet analysis
python3 noauth_finder.py 192.168.1.0/24 --report results.csv --output-format csv

# Save as HTML report
python3 noauth_finder.py 192.168.1.0/24 --report report.html --output-format html

# Disable colors for log files
python3 noauth_finder.py 192.168.1.0/24 --no-color
```

When scanning ranges larger than /8 (>16 million IPs), the tool will refuse to run without `--sample` to prevent accidental massive scans. Always sample when scanning internet ranges.

### CIDR File Format

```
# Country ASN blocks — one CIDR per line, # comments allowed
1.0.0.0/24
5.0.0.0/16
8.0.0.0/8
```

---

## Usage

```
positional arguments:
  target                CIDR (192.168.1.0/24), IP, hostname,
                        or file:ranges.txt (one CIDR per line)

options:
  --ports PORTS         Ports: 'web' (~50), 'top10' (80,443,8080,8443,
                        8888,9090,3000,5000,8000,9000), or comma list
  --timeout TIMEOUT     Request timeout in seconds (default: 5)
  --threads THREADS     Thread count (default: 50)
  --deep                Probe admin paths on every found service
  --report REPORT       Save report to file (JSON/CSV/HTML)
  --fast                Skip deep path probing
  --random              Randomize host scan order (stealth)
  --sample N            Randomly sample N IPs from CIDR range
  --delay MS            Delay in ms between hosts (rate limiting)
  --top10               Shorthand for --ports top10
  --ipv6                Enable IPv6 scanning
  --output-format       Output format: json, csv, html (default: json)
  --no-color            Disable colored output
  --exclude CIDRS       CIDR ranges to exclude (comma-separated)
```

---

## Example Output

```
$ python3 noauth_finder.py 0.0.0.0/0 --sample 10000 --ports top10

███▄▄▄▄    ▄██████▄          ▄████████ ███    █▄      ███        ▄█    █▄    
███▀▀▀██▄ ███    ███        ███    ███ ███    ███ ▀█████████▄   ███    ███   
███   ███ ███    ███        ███    ███ ███    ███    ▀███▀▀██   ███    ███   
███   ███ ███    ███        ███    ███ ███    ███     ███   ▀  ▄███▄▄▄▄███▄▄ 
███   ███ ███    ███      ▀███████████ ███    ███     ███     ▀▀███▀▀▀▀███▀  
███   ███ ███    ███        ███    ███ ███    ███     ███       ███    ███   
███   ███ ███    ███        ███    ███ ███    ███     ███       ███    ███   
 ▀█   █▀   ▀██████▀         ███    █▀  ████████▀     ▄████▀     ███    █▀    
                                                                             
  No-Auth Web UI Finder  ·  internet-scale  ·  by: ek0ms savi0r

  ⚠ 0.0.0.0/0 = 4,294,967,296 IPs. Sampling recommended.

[!] INTERNET-SCALE SCAN DETECTED

  This will probe hosts across the open internet.
  • Use --sample N to limit hosts scanned
  • Use --random to avoid detection patterns
  • Use --delay MS to rate-limit requests (be polite)
  • Expect many timeouts — internet hosts are unreliable
  • Port 80/443 only recommended for internet-wide sweeps

  10,000 hosts × 10 ports (50 threads) — 10000 sampled

  Progress: 100/10,000 (1%)
[2 no-auth] 199.11.11.169 — Welcome to nginx!
  ───────────────────────────────────────────────────────
  ✔ :80 (200, 612B) [nginx] Nginx
      /login
      /admin
      /dashboard
  ✔ :8443 (200, 612B) [nginx] Nginx

  Progress: 200/10,000 (2%)
[2 no-auth] 104.111.111.67
  ───────────────────────────────────────────────────────
  ✔ :80 (400, 310B) [AkamaiGHost]
  ✔ :443 (400, 310B) [AkamaiGHost]

[2 no-auth] 45.111.111.241 
  ───────────────────────────────────────────────────────
  ✔ :80 (400, 552B) [nginx] Nginx
  ✔ :443 (200, 1285B) [nginx] Nginx
      /index.html
      /api

[1 no-auth] 23.111.111.213 
  ───────────────────────────────────────────────────────
  ✔ :80 (404, 2597B) [nginx] Nginx
      /index.html

[+] Done. Found hosts with unauthenticated UIs.

  Report saved: findings.json (47 hosts)
```

---

## Ethical Use ONLY

For authorized testing and educational purposes only.

