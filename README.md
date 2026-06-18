# NoAuth Finder

**Find unauthenticated web interfaces during authorized testing**

[![ek0ms](https://img.shields.io/badge/ek0ms-green)](ek0ms)

---

## What It Does

NoAuth Finder scans IPs, hostnames, CIDRs, or scope files for web interfaces that are reachable without authentication.

It is built for professional security testing, internal network reviews, external attack surface checks, lab assessment, and team evidence collection.

The tool checks common web/admin ports, probes useful admin/API paths, fingerprints technologies, scores risk, saves evidence, and exports findings in JSON, CSV, HTML, and Markdown.

---

## Finds Things Like

| Type | Examples |
|---|---|
| Admin Panels | dashboards, consoles, management pages |
| Infrastructure | Kubernetes, Grafana, Prometheus, Portainer, Jenkins |
| Network Gear | routers, access points, ESXi, Webmin, Cockpit |
| IoT / Embedded | cameras, printers, NAS, Pi-hole |
| Databases / Data Tools | phpMyAdmin, Adminer, Elasticsearch, OpenSearch, Kibana |
| DevOps / Dev Tools | GitLab, Harbor, ArgoCD, Airflow, Nexus, Artifactory |
| API / Debug Surfaces | Swagger, OpenAPI, Spring Boot Actuator, `/metrics`, `/config` |
| Custom Apps | open dashboards, status pages, exposed APIs |

---

## Key Features

- Single host, CIDR, hostname, or scope-file scanning
- Public-scope safety gate with `--allow-public`
- Common web/admin port scanning
- Optional top-10 web port mode
- Deep path probing for admin, config, API, debug, and sensitive paths
- Smarter auth detection
- Technology fingerprinting
- Risk scoring and severity labels
- Reverse DNS / PTR enrichment
- RDAP network/org enrichment
- TLS SAN domain discovery
- Associated domain and link extraction
- Response body hashing
- Secret-like content and stack trace detection
- Resume mode with state file
- Per-host timeout budget
- Optional screenshots
- Evidence folders per finding
- Team exports:
  - JSON
  - CSV
  - HTML
  - Markdown

---

## Installation

```bash
git clone https://github.com/ekomsSavior/NoAuth-Finder.git
cd NoAuth-Finder
pip install requests
```

Optional screenshot support:

```bash
pip install playwright
python3 -m playwright install chromium
```

---

## Quick Start

### Scan a single private IP

```bash
python3 noauth_finder.py 192.168.1.100
```

### Scan a local subnet

```bash
python3 noauth_finder.py 192.168.1.0/24
```

### Scan a public IP in authorized scope

```bash
python3 noauth_finder.py 134.209.128.139 --allow-public
```

### Scan only top web ports

```bash
python3 noauth_finder.py 192.168.1.0/24 --top10
```

### Fast mode

```bash
python3 noauth_finder.py 192.168.1.0/24 --fast
```

### Save team evidence

```bash
python3 noauth_finder.py 192.168.1.0/24 --output-dir noauth_results
```

### Capture screenshots

```bash
python3 noauth_finder.py 192.168.1.0/24 --screenshots
```

---

## Scope Files

You can scan from a scope file:

```bash
python3 noauth_finder.py --scope-file scope.txt
```

Example `scope.txt`:

```text
192.168.1.0/24
10.10.10.5
example.internal
```

You can also use the legacy `file:` format:

```bash
python3 noauth_finder.py file:ranges.txt
```

---

## Public Scope Safety

NoAuth Finder refuses to scan public IPs unless you explicitly allow it.

```bash
python3 noauth_finder.py 134.209.128.139
```

This will stop and warn you.

To scan authorized public scope:

```bash
python3 noauth_finder.py 134.209.128.139 --allow-public
```

---

## Examples

### Public authorized target with default output

```bash
python3 noauth_finder.py 134.209.128.139 --allow-public
```

### Public target with screenshots

```bash
python3 noauth_finder.py 134.209.128.139 --allow-public --screenshots
```

### CIDR with exclusions

```bash
python3 noauth_finder.py 10.0.0.0/8 --exclude 10.10.0.0/16,10.20.0.0/16
```

### Randomized scan order

```bash
python3 noauth_finder.py 10.0.0.0/16 --random
```

### Sample a large CIDR

```bash
python3 noauth_finder.py 1.0.0.0/8 --allow-public --sample 50000 --random --top10
```

### Rate-limited scan

```bash
python3 noauth_finder.py 1.0.0.0/8 --allow-public --sample 10000 --delay 50 --random
```

### Resume a scan

```bash
python3 noauth_finder.py 10.0.0.0/16 --resume --state scan_state.json
```

### Per-host timeout budget

```bash
python3 noauth_finder.py 10.0.0.0/16 --host-timeout 20
```

---

## Output Folder

By default, results are saved under:

```text
noauth_results/
```

Generated structure:

```text
noauth_results/
├── findings.json
├── findings.csv
├── findings.html
├── findings.md
├── evidence/
│   └── <host_port_severity_score>/
│       ├── finding.json
│       ├── headers.json
│       ├── body_preview.txt
│       └── links.txt
├── screenshots/
└── raw/
```

---

## Example Terminal Output

```text
[3 no-auth] 134.209.128.139 — Apache2 Ubuntu Default Page: It works
Network: DIGITALOCEAN-134-209-0-0 ['134.209.0.0/16']
  Associated domains: 134.209.128.139, bugs.launchpad.net, fonts.googleapis.com, httpd.apache.org
  ──────────────────────────────────────────────────────────────────────
  Low      score=15  ✔ :80 (200, 10671B) [Apache/2.4.52 (Ubuntu)] Apache
      title: Apache2 Ubuntu Default Page: It works
      reasons: public_ip
      links:
        http://134.209.128.139:80/icons/ubuntu-logo.png
        http://134.209.128.139:80/manual
        http://httpd.apache.org/docs/2.4/mod/mod_userdir.html

  Medium   score=25  ✔ :8080 (200, 90997B)
      title: Visual Schedule Builder - KCTCS
      final: http://134.209.128.139:8080/criteria.jsp
      reasons: public_ip, nonstandard_web_port
      /index.html
```

---

## Risk Scoring

NoAuth Finder assigns a score and severity to each unauthenticated endpoint.

| Severity | Score Range | Meaning |
|---|---:|---|
| Low | 0–19 | Public page or low-signal open web UI |
| Medium | 20–39 | Nonstandard port, admin language, useful metadata |
| High | 40–59 | Sensitive paths, high-value tech, exposed API surfaces |
| Critical | 60+ | Secret-like content, dangerous paths, critical admin exposure |

Score reasons may include:

```text
public_ip
nonstandard_web_port
sensitive_path_accessible
secret_like_content
stacktrace_detected
json_endpoint
high_value_admin_tech
admin_or_dashboard_language
metrics_exposed
```

---

## Enrichment

For each host, the tool can collect:

- Reverse DNS / PTR
- RDAP network name
- RDAP CIDR
- Country
- TLS certificate SAN domains
- Associated domains from links and TLS
- Associated URLs discovered from page links
- Redirect/final URL chains

This helps identify shared hosting, SaaS platforms, exposed tenants, linked apps, and infrastructure ownership.

---

## Reports

### JSON

```bash
python3 noauth_finder.py 192.168.1.0/24 --output-format json
```

### CSV

```bash
python3 noauth_finder.py 192.168.1.0/24 --output-format csv
```

### HTML

```bash
python3 noauth_finder.py 192.168.1.0/24 --output-format html
```

### Markdown

```bash
python3 noauth_finder.py 192.168.1.0/24 --output-format md
```

You can also write a separate Markdown report:

```bash
python3 noauth_finder.py 192.168.1.0/24 --markdown-report report.md
```

---

## Options

| Option | Description |
|---|---|
| `target` | CIDR, IP, hostname, or `file:ranges.txt` |
| `--scope-file FILE` | File with CIDRs/IPs/hostnames, one per line |
| `--allow-public` | Allow scanning public IP space |
| `--ports web` | Scan default web/admin ports |
| `--ports top10` | Scan top 10 common web ports |
| `--ports 80,443,8080` | Custom comma-separated port list |
| `--top10` | Shorthand for `--ports top10` |
| `--timeout N` | Request timeout in seconds |
| `--host-timeout N` | Per-host timeout budget in seconds |
| `--threads N` | Thread count |
| `--fast` | Skip deeper path probing |
| `--random` | Randomize host scan order |
| `--sample N` | Randomly sample N IPs from CIDR range |
| `--delay MS` | Delay in milliseconds between hosts |
| `--exclude CIDRS` | Comma-separated CIDRs to exclude |
| `--resume` | Skip completed hosts using state file |
| `--state FILE` | Resume state file |
| `--screenshots` | Capture screenshots for findings |
| `--output-dir DIR` | Evidence/output folder |
| `--report FILE` | Save primary report path |
| `--output-format` | `json`, `csv`, `html`, or `md` |
| `--markdown-report FILE` | Also write a Markdown report |
| `--ipv6` | Enable IPv6 scanning |
| `--no-color` | Disable colored terminal output |


---

## Disclaimer

This tool is intended for authorized security testing, research, education, and defensive assessment only.

---

## Author

Built by **ek0ms savi0r**.
