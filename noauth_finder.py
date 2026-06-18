#!/usr/bin/env python3
"""
noauth_finder.py — Find unauthenticated web UIs during authorized testing.
"""

import argparse
import concurrent.futures
import csv
import hashlib
import html as html_escape
import ipaddress
import json
import random
import re
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[-] Install requests: pip install requests")
    sys.exit(1)


COMMON_WEB_PORTS = [
    80, 443, 8080, 8443, 8888, 9090, 3000, 5000,
    8000, 8001, 8081, 8444, 9000, 9001, 9200, 5601,
    7070, 7443, 9443, 10000, 1234, 4443, 9999, 8880,
    8082, 8083, 8084, 9002, 18080, 18081, 8889, 9091,
    7474, 7687, 5432, 3306, 27017, 15672, 15692, 3001,
    9092, 9990, 9991, 4848, 8686, 8834, 8333, 8123,
]

TOP10_PORTS = [80, 443, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 9000]

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
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/v2/api-docs", "/v3/api-docs", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/metrics", "/actuator/configprops",
    "/debug", "/debug/vars",
]

SENSITIVE_PATH_HINTS = [
    "api/state", "api/control", "api/command", "api/exec",
    "shell", "cmd", "config", "secrets", "keys", "export",
    "dump", "api/creds", "api/findings", "terminal",
    ".env", "actuator/env", "v3/api-docs", "openapi",
    "graphql", "metrics",
]

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    r"(?i)aws_secret_access_key",
    r"(?i)secret[_-]?key",
    r"(?i)api[_-]?key",
    r"(?i)access[_-]?token",
    r"(?i)refresh[_-]?token",
    r"(?i)bearer\s+[a-z0-9._\-]{20,}",
    r"(?i)password\s*[:=]",
    r"(?i)passwd\s*[:=]",
    r"(?i)private[_-]?key",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)mongodb://",
    r"(?i)postgres://",
    r"(?i)mysql://",
    r"(?i)redis://",
    r"(?i)jdbc:",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
]

AUTH_STRONG_PATTERNS = [
    r"<input[^>]+type=[\"']?password",
    r"<form[^>]+(?:login|signin|auth)",
    r"(?:location\.href|window\.location)[^;\n]+login",
    r"http-equiv=[\"']refresh[\"'][^>]+login",
    r"www-authenticate",
]

AUTH_TEXT_HINTS = [
    "sign in", "signin", "log in", "login required",
    "authenticate", "unauthorized", "forbidden",
    "access denied", "credentials required",
    "enter password", "401 unauthorized", "403 forbidden",
]

NOAUTH_POSITIVE_HINTS = [
    "dashboard", "admin", "status", "metrics", "configuration",
    "settings", "system", "overview", "console", "management",
    "prometheus", "grafana", "jenkins", "kibana", "swagger",
    "api documentation", "server status", "health",
]

TECH_SIGNATURES = [
    ("Cockpit", ["cockpit"]),
    ("Kubernetes", ["kubernetes", "k8s"]),
    ("Grafana", ["grafana"]),
    ("Prometheus", ["prometheus"]),
    ("Jenkins", ["jenkins"]),
    ("phpMyAdmin", ["phpmyadmin"]),
    ("Adminer", ["adminer"]),
    ("Router/AP", ["router", "access point", "wifi settings"]),
    ("Camera/DVR", ["camera", "ip cam", "dvr", "nvr"]),
    ("NAS", ["nas", "synology", "qnap", "truenas", "freenas"]),
    ("Printer", ["printer", "hp eprint", "brother"]),
    ("C2 Panel", ["c2 ", "command & control", "command and control", "botnet", "agent panel"]),
    ("IoT Hub", ["smart home", "home assistant", "hassio"]),
    ("ESXi/vSphere", ["vmware esxi", "vsphere"]),
    ("Pi-hole", ["pi-hole", "pihole"]),
    ("OctoPrint", ["octoprint"]),
    ("Jellyfin", ["jellyfin"]),
    ("Plex", ["plex"]),
    ("Portainer", ["portainer"]),
    ("RabbitMQ", ["rabbitmq", "management"]),
    ("Elasticsearch", ["elasticsearch"]),
    ("OpenSearch", ["opensearch"]),
    ("Kibana", ["kibana"]),
    ("Nginx", ["nginx"]),
    ("Apache", ["apache"]),
    ("Syncthing", ["syncthing"]),
    ("Nextcloud", ["nextcloud"]),
    ("WordPress", ["wordpress", "wp-content", "wp-includes"]),
    ("Webmin", ["webmin"]),
    ("Netdata", ["netdata"]),
    ("Node-RED", ["node-red"]),
    ("Flask", ["flask"]),
    ("Node.js/Express", ["express", "node.js"]),
    ("Spring Boot Actuator", ["spring boot", "actuator", "actuator/env", "actuator/health"]),
    ("Swagger/OpenAPI", ["swagger", "openapi", "swagger-ui", "api-docs"]),
    ("SonarQube", ["sonarqube", "sonar"]),
    ("GitLab", ["gitlab"]),
    ("Harbor", ["harbor"]),
    ("Keycloak", ["keycloak"]),
    ("ArgoCD", ["argocd", "argo cd"]),
    ("Airflow", ["airflow"]),
    ("Traefik", ["traefik"]),
    ("Consul", ["consul"]),
    ("Vault", ["vault"]),
    ("MinIO", ["minio"]),
    ("Jupyter", ["jupyter", "notebook"]),
    ("Splunk", ["splunk"]),
    ("Nexus", ["nexus repository", "sonatype"]),
    ("Artifactory", ["artifactory", "jfrog"]),
]

C = type("C", (), {
    "G": "\033[92m", "R": "\033[91m", "Y": "\033[93m",
    "C": "\033[96m", "M": "\033[95m", "B": "\033[1m",
    "D": "\033[2m", "N": "\033[0m",
})()

THREAD_LOCAL = threading.local()
STATE_LOCK = threading.Lock()
ENRICH_CACHE = {}
ENRICH_LOCK = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


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

  No-Auth Web UI Finder  ·  team evidence edition  ·  by: ek0ms savi0r
{C.N}""")


def get_session():
    if not hasattr(THREAD_LOCAL, "session"):
        THREAD_LOCAL.session = requests.Session()
        THREAD_LOCAL.session.verify = False
        THREAD_LOCAL.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })
    return THREAD_LOCAL.session


def ensure_dirs(base_dir):
    base = Path(base_dir)
    for name in ["evidence", "screenshots", "raw"]:
        (base / name).mkdir(parents=True, exist_ok=True)
    return base


def safe_name(value):
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value)).strip("_")[:160] or "finding"


def is_private_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except Exception:
        return False


def is_public_scan(targets):
    return any(not is_private_ip(t) for t in targets)


def expand_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError as e:
        print(f"  {C.R}✘ Invalid CIDR: {cidr} ({e}){C.N}")
        return []


def expand_cidr_sample(cidr, sample_size):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        num = net.num_addresses

        if net.version != 4:
            return [str(ip) for ip in net.hosts()][:sample_size]

        if num <= sample_size:
            return [str(ip) for ip in net.hosts()]

        first = int(net[0])
        if net.prefixlen == 32:
            return [str(net[0])]

        result = set()
        max_attempts = sample_size * 20
        attempts = 0

        while len(result) < sample_size and attempts < max_attempts:
            attempts += 1
            offset = random.randint(1, max(1, num - 2))
            ip_str = str(ipaddress.IPv4Address(first + offset))
            result.add(ip_str)

        return list(result)
    except ValueError as e:
        print(f"  {C.R}✘ Invalid CIDR: {cidr} ({e}){C.N}")
        return []


def load_lines_from_file(path):
    items = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    except Exception as e:
        print(f"  {C.R}✘ Could not read {path}: {e}{C.N}")
    return items


def resolve_target(target, sample=None):
    if target.startswith("file:"):
        path = target[5:]
        items = load_lines_from_file(path)
        all_ips = []
        per_range_sample = max(1, sample // max(1, len(items))) if sample else None
        for item in items:
            all_ips.extend(resolve_target(item, sample=per_range_sample))
        return all_ips

    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if sample:
                return expand_cidr_sample(target, sample)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            pass

    if target.count(".") == 2:
        return expand_cidr(f"{target}.0/24")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        return [target]

    try:
        return [socket.gethostbyname(target)]
    except Exception:
        print(f"  {C.R}✘ Could not resolve: {target}{C.N}")
        return []


def resolve_scope(scope_items, sample=0):
    targets = []
    for item in scope_items:
        targets.extend(resolve_target(item, sample=sample or None))

    deduped = []
    seen = set()
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)

    return deduped


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


def reverse_dns(ip):
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        return {
            "ptr": name.rstrip("."),
            "aliases": [a.rstrip(".") for a in aliases],
            "error": None,
        }
    except Exception as e:
        return {
            "ptr": None,
            "aliases": [],
            "error": f"{type(e).__name__}: {e}",
        }


def rdap_lookup(ip, timeout=5):
    result = {
        "handle": None,
        "name": None,
        "type": None,
        "country": None,
        "start_address": None,
        "end_address": None,
        "cidr": None,
        "parent_handle": None,
        "entities": [],
        "links": [],
        "raw_url": f"https://rdap.org/ip/{ip}",
        "error": None,
    }

    try:
        session = get_session()
        r = session.get(result["raw_url"], timeout=timeout)
        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result

        data = r.json()
        result["handle"] = data.get("handle")
        result["name"] = data.get("name")
        result["type"] = data.get("type")
        result["country"] = data.get("country")
        result["start_address"] = data.get("startAddress")
        result["end_address"] = data.get("endAddress")
        result["parent_handle"] = data.get("parentHandle")

        cidrs = []
        for item in data.get("cidr0_cidrs", []) or []:
            v4prefix = item.get("v4prefix")
            length = item.get("length")
            if v4prefix and length is not None:
                cidrs.append(f"{v4prefix}/{length}")
        result["cidr"] = cidrs

        entities = []
        for ent in data.get("entities", []) or []:
            roles = ent.get("roles", [])
            handle = ent.get("handle")
            name = None

            for vcard in ent.get("vcardArray", []) or []:
                if isinstance(vcard, list):
                    for row in vcard:
                        if isinstance(row, list) and len(row) >= 4 and row[0] in ("fn", "org"):
                            name = row[3]
                            break

            entities.append({
                "handle": handle,
                "roles": roles,
                "name": name,
            })

        result["entities"] = entities[:20]

        links = []
        for link in data.get("links", []) or []:
            href = link.get("href")
            if href:
                links.append(href)
        result["links"] = links[:20]

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def get_tls_domains(host, port, timeout=4):
    result = {
        "host": host,
        "port": port,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "san_dns": [],
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        result["subject"] = cert.get("subject")
        result["issuer"] = cert.get("issuer")
        result["not_before"] = cert.get("notBefore")
        result["not_after"] = cert.get("notAfter")

        sans = cert.get("subjectAltName", []) or []
        result["san_dns"] = sorted(set(v for k, v in sans if str(k).lower() == "dns"))

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def extract_title(html):
    if not html:
        return ""
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return re.sub(r"\s+", " ", m.group(1).strip()) if m else ""


def extract_links(html_text, base_url, limit=50):
    links = []
    seen = set()

    for match in re.finditer(r"""(?:href|src)=["']([^"']+)["']""", html_text or "", re.IGNORECASE):
        raw = match.group(1).strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue

        absolute = urljoin(base_url, raw)
        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https"):
            continue

        if absolute not in seen:
            seen.add(absolute)
            links.append(absolute)

        if len(links) >= limit:
            break

    return links


def check_auth(status, body_lower, headers, final_url=""):
    headers_lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}

    if status in (401, 403):
        return True

    if "www-authenticate" in headers_lower:
        return True

    if final_url and re.search(r"/(?:login|signin|auth)(?:/|$|\?)", final_url.lower()):
        return True

    for pattern in AUTH_STRONG_PATTERNS:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return True

    strong_hint_count = sum(1 for hint in AUTH_TEXT_HINTS if hint in body_lower)
    positive_hint_count = sum(1 for hint in NOAUTH_POSITIVE_HINTS if hint in body_lower)

    if strong_hint_count >= 2 and positive_hint_count == 0:
        return True

    return False


def detect_sensitive_content(body, headers=None):
    headers = headers or {}
    body_text = body or ""
    joined = body_text[:20000]
    hits = []

    for pattern in SECRET_PATTERNS:
        if re.search(pattern, joined):
            hits.append(pattern)

    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    looks_json = "json" in content_type.lower() or joined.strip().startswith(("{", "["))
    stacktrace = bool(re.search(r"(?i)(traceback|exception|stack trace|java\.lang\.|at\s+[a-z0-9_.]+\()", joined))

    return {
        "secret_pattern_hits": len(hits),
        "secret_patterns": hits[:10],
        "looks_json": looks_json,
        "stacktrace": stacktrace,
        "content_type": content_type,
    }


def probe_http(host, port, path="/", timeout=5, ssl_enabled=False):
    proto = "https" if ssl_enabled else "http"
    url = f"{proto}://{host}:{port}{path}"
    session = get_session()

    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        text = r.text or ""
        body_lower = text.lower()[:5000]
        headers = dict(r.headers)

        redirect_chain = []
        for hist in r.history:
            redirect_chain.append({
                "status": hist.status_code,
                "url": hist.url,
                "location": hist.headers.get("Location"),
            })

        return {
            "status": r.status_code,
            "size": len(r.content),
            "title": extract_title(text),
            "server": r.headers.get("Server", ""),
            "auth": check_auth(r.status_code, body_lower, headers, final_url=r.url),
            "body": body_lower[:1000],
            "body_preview": text[:2000],
            "links": extract_links(text, r.url),
            "url": url,
            "final_url": r.url,
            "redirect_chain": redirect_chain,
            "ssl": ssl_enabled,
            "headers": headers,
            "body_hash": hashlib.md5(r.content[:5000]).hexdigest(),
            "sensitive": detect_sensitive_content(text, headers),
        }
    except requests.exceptions.SSLError:
        if ssl_enabled:
            return probe_http(host, port, path, timeout, ssl_enabled=False)
        return None
    except Exception:
        return None


def classify_finding(title, body, path, server, status, headers=None):
    text = f"{title} {body} {path} {server} {json.dumps(headers or {})}".lower()
    findings = []

    for name, keywords in TECH_SIGNATURES:
        if any(k.lower() in text for k in keywords):
            findings.append(name)

    return sorted(set(findings))


def score_endpoint(host, port, response, tech, paths):
    score = 0
    reasons = []

    path_text = " ".join(paths).lower()
    title = (response.get("title") or "").lower()
    body = (response.get("body") or "").lower()
    url = response.get("url", "")

    if not is_private_ip(host):
        score += 15
        reasons.append("public_ip")

    if port not in (80, 443):
        score += 10
        reasons.append("nonstandard_web_port")

    if any(x in path_text for x in SENSITIVE_PATH_HINTS):
        score += 25
        reasons.append("sensitive_path_accessible")

    if response.get("sensitive", {}).get("secret_pattern_hits", 0) > 0:
        score += 30
        reasons.append("secret_like_content")

    if response.get("sensitive", {}).get("stacktrace"):
        score += 15
        reasons.append("stacktrace_detected")

    if response.get("sensitive", {}).get("looks_json"):
        score += 8
        reasons.append("json_endpoint")

    high_value_tech = {
        "Jenkins", "Kubernetes", "Grafana", "Prometheus", "phpMyAdmin",
        "Adminer", "Portainer", "RabbitMQ", "Elasticsearch", "OpenSearch",
        "Kibana", "Spring Boot Actuator", "Swagger/OpenAPI", "SonarQube",
        "GitLab", "Harbor", "Keycloak", "ArgoCD", "Airflow", "Consul",
        "Vault", "MinIO", "Jupyter", "Splunk", "Nexus", "Artifactory",
        "Webmin", "Node-RED"
    }

    if any(t in high_value_tech for t in tech):
        score += 20
        reasons.append("high_value_admin_tech")

    if any(word in title + " " + body for word in ["dashboard", "admin", "console", "management"]):
        score += 10
        reasons.append("admin_or_dashboard_language")

    if url.endswith("/metrics") or "/metrics" in url:
        score += 10
        reasons.append("metrics_exposed")

    if score >= 60:
        severity = "Critical"
    elif score >= 40:
        severity = "High"
    elif score >= 20:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity, reasons


def enrich_ip(ip, open_ports=None, timeout=5):
    open_ports = open_ports or []

    with ENRICH_LOCK:
        if ip in ENRICH_CACHE:
            return ENRICH_CACHE[ip]

    enrichment = {
        "ip": ip,
        "reverse_dns": reverse_dns(ip),
        "rdap": rdap_lookup(ip, timeout=timeout),
        "tls": {},
        "associated_domains": [],
        "associated_urls": [],
    }

    associated_domains = set()

    ptr = enrichment["reverse_dns"].get("ptr")
    if ptr:
        associated_domains.add(ptr)

    if 443 in open_ports:
        tls_info = get_tls_domains(ip, 443)
        enrichment["tls"]["443"] = tls_info
        for domain in tls_info.get("san_dns", []) or []:
            associated_domains.add(domain)

    enrichment["associated_domains"] = sorted(associated_domains)

    with ENRICH_LOCK:
        ENRICH_CACHE[ip] = enrichment

    return enrichment


def scan_host_ports(host, ports, timeout=5, fast=False, ipv6=False, host_timeout=0):
    results = {}
    start = time.time()

    def budget_left():
        if not host_timeout:
            return True
        return (time.time() - start) < host_timeout

    open_ports = []
    for port in ports:
        if not budget_left():
            break
        if tcp_check(host, port, timeout=min(2, timeout), ipv6=ipv6):
            open_ports.append(port)

    if not open_ports:
        return results

    enrichment = enrich_ip(host, open_ports=open_ports, timeout=timeout)

    ssl_first = {443, 8443, 9443, 7443}

    for port in open_ports:
        if not budget_left():
            break

        use_ssl = port in ssl_first
        resp = probe_http(host, port, "/", timeout, ssl_enabled=use_ssl)

        if not resp:
            resp = probe_http(host, port, "/", timeout, ssl_enabled=not use_ssl)

        if not resp:
            continue

        results[port] = resp

        if not resp["auth"] and not fast:
            resp.setdefault("extra_paths", [])
            resp.setdefault("extra_path_details", [])

            for path in ADMIN_PATHS + CRITICAL_PATHS:
                if not budget_left():
                    break
                if path == "/":
                    continue

                r2 = probe_http(host, port, path, timeout, ssl_enabled=resp.get("ssl", False))
                if r2 and r2["status"] in (200, 204, 301, 302) and not r2["auth"]:
                    if r2["body_hash"] != resp.get("body_hash") or any(h in path.lower() for h in SENSITIVE_PATH_HINTS):
                        resp["extra_paths"].append(path)
                        resp["extra_path_details"].append({
                            "path": path,
                            "url": r2.get("url"),
                            "final_url": r2.get("final_url"),
                            "status": r2.get("status"),
                            "title": r2.get("title"),
                            "size": r2.get("size"),
                            "body_hash": r2.get("body_hash"),
                            "sensitive": r2.get("sensitive"),
                            "links": r2.get("links", [])[:20],
                        })

                if len(resp.get("extra_paths", [])) >= 8:
                    break

    if results:
        results["_enrichment"] = enrichment

        urls = set()
        domains = set(enrichment.get("associated_domains", []))

        for port, response in results.items():
            if str(port).startswith("_"):
                continue
            for key in ("url", "final_url"):
                if response.get(key):
                    urls.add(response[key])
            for link in response.get("links", []) or []:
                urls.add(link)
                parsed = urlparse(link)
                if parsed.hostname:
                    domains.add(parsed.hostname)

        enrichment["associated_urls"] = sorted(urls)[:100]
        enrichment["associated_domains"] = sorted(domains)[:100]

    return results


def print_results(host, results):
    enrichment = results.get("_enrichment", {})
    filtered = {p: r for p, r in results.items() if not str(p).startswith("_")}
    noauth = {p: r for p, r in filtered.items() if not r.get("auth")}
    authed = {p: r for p, r in filtered.items() if r.get("auth")}

    if not noauth:
        return False

    noauth_ports = list(noauth.keys())
    r0 = noauth[noauth_ports[0]]
    title_str = f" — {C.B}{r0['title']}{C.N}" if r0.get("title") else ""

    print(f"\n{C.G}{C.B}[{len(noauth)} no-auth] {host}{title_str}{C.N}")

    rdap = enrichment.get("rdap", {}) or {}
    ptr = (enrichment.get("reverse_dns", {}) or {}).get("ptr")
    if ptr:
        print(f"  PTR: {ptr}")
    if rdap.get("name") or rdap.get("country") or rdap.get("cidr"):
        print(f"  Network: {rdap.get('name') or 'unknown'} {rdap.get('cidr') or ''} {rdap.get('country') or ''}".strip())

    domains = enrichment.get("associated_domains", [])[:8]
    if domains:
        print(f"  Associated domains: {', '.join(domains)}")

    print(f"  {'─' * 70}")

    for port, r in sorted(noauth.items()):
        tech = classify_finding(r.get("title", ""), r.get("body", ""), "/", r.get("server", ""), r.get("status", 0), r.get("headers"))
        score, severity, reasons = score_endpoint(host, port, r, tech, r.get("extra_paths", []))
        server = f" [{r['server']}]" if r.get("server") else ""
        tag = f" {C.M}{', '.join(tech[:2])}{C.N}" if tech else ""

        sev_color = C.R if severity in ("Critical", "High") else C.Y if severity == "Medium" else C.G
        print(f"  {sev_color}{severity:<8}{C.N} score={score:<3} {C.G}✔{C.N} :{port} ({r['status']}, {r.get('size', 0)}B){server}{tag}")

        if r.get("title"):
            print(f"      title: {r.get('title')}")
        if r.get("final_url") and r.get("final_url") != r.get("url"):
            print(f"      final: {r.get('final_url')}")
        if reasons:
            print(f"      reasons: {', '.join(reasons)}")

        for path in r.get("extra_paths", [])[:5]:
            print(f"      {C.D}{path}{C.N}")

        links = r.get("links", [])[:5]
        if links:
            print(f"      links:")
            for link in links:
                print(f"        {C.D}{link}{C.N}")

    if authed:
        authed_str = ", ".join(f":{p}" for p in authed)
        print(f"  {C.Y}⚠{C.N} Auth required: {authed_str}")

    return True


def save_evidence(base_dir, host, port, response, entry):
    evidence_dir = Path(base_dir) / "evidence" / safe_name(f"{host}_{port}_{entry['severity']}_{entry['score']}")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    with open(evidence_dir / "finding.json", "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)

    with open(evidence_dir / "headers.json", "w", encoding="utf-8") as f:
        json.dump(response.get("headers", {}), f, indent=2)

    with open(evidence_dir / "body_preview.txt", "w", encoding="utf-8", errors="ignore") as f:
        f.write(response.get("body_preview", ""))

    with open(evidence_dir / "links.txt", "w", encoding="utf-8", errors="ignore") as f:
        f.write("\n".join(response.get("links", [])))

    return str(evidence_dir)


def full_report(host, results, output_dir="noauth_results"):
    enrichment = results.get("_enrichment", {})
    filtered = {p: r for p, r in results.items() if not str(p).startswith("_")}
    noauth = {p: r for p, r in filtered.items() if not r.get("auth")}

    if not noauth:
        return None

    report = {
        "host": host,
        "timestamp": utc_now(),
        "enrichment": enrichment,
        "noauth_endpoints": [],
        "recommendations": [],
    }

    for port, r in sorted(noauth.items()):
        tech = classify_finding(
            r.get("title", ""),
            r.get("body", ""),
            "/",
            r.get("server", ""),
            r.get("status", 0),
            r.get("headers"),
        )
        score, severity, reasons = score_endpoint(host, port, r, tech, r.get("extra_paths", []))

        entry = {
            "host": host,
            "url": r.get("url"),
            "final_url": r.get("final_url"),
            "redirect_chain": r.get("redirect_chain", []),
            "links": r.get("links", []),
            "port": port,
            "status": r.get("status"),
            "title": r.get("title"),
            "server": r.get("server"),
            "tech": tech,
            "severity": severity,
            "score": score,
            "score_reasons": reasons,
            "accessible_paths": r.get("extra_paths", []),
            "accessible_path_details": r.get("extra_path_details", []),
            "sensitive": r.get("sensitive", {}),
            "body_hash": r.get("body_hash", ""),
            "evidence_dir": None,
            "screenshot": None,
        }

        entry["evidence_dir"] = save_evidence(output_dir, host, port, r, entry)
        report["noauth_endpoints"].append(entry)

        report["recommendations"].append(
            f"{severity}: Secure {r.get('url', f'http://{host}:{port}/')} — "
            f"no authentication required ({', '.join(tech) if tech else 'unknown technology'})."
        )

        for path in entry.get("accessible_paths", []):
            if any(kw in path.lower() for kw in SENSITIVE_PATH_HINTS):
                report["recommendations"].append(
                    f"CRITICAL: {entry['url']}{path} exposed without auth — validate impact and restrict access."
                )

    return report


def export_csv(reports, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "severity", "score", "host", "ptr", "network", "country", "cidr",
            "port", "url", "final_url", "title", "tech", "status", "server",
            "associated_domains", "body_hash", "evidence_dir"
        ])
        for report in reports:
            enrich = report.get("enrichment", {})
            ptr = (enrich.get("reverse_dns", {}) or {}).get("ptr")
            rdap = enrich.get("rdap", {}) or {}
            domains = ", ".join(enrich.get("associated_domains", [])[:20])
            for ep in report["noauth_endpoints"]:
                writer.writerow([
                    ep["severity"], ep["score"], report["host"], ptr,
                    rdap.get("name"), rdap.get("country"), ", ".join(rdap.get("cidr") or []),
                    ep["port"], ep["url"], ep.get("final_url"), ep["title"],
                    ", ".join(ep["tech"]), ep["status"], ep.get("server"),
                    domains, ep.get("body_hash", ""), ep.get("evidence_dir", "")
                ])


def export_html(reports, filename):
    rows = []
    for report in reports:
        enrich = report.get("enrichment", {})
        ptr = (enrich.get("reverse_dns", {}) or {}).get("ptr") or ""
        rdap = enrich.get("rdap", {}) or {}
        domains = ", ".join(enrich.get("associated_domains", [])[:10])

        for ep in report["noauth_endpoints"]:
            cls = ep["severity"].lower()
            rows.append(f"""
<tr class="{cls}">
<td>{html_escape.escape(ep["severity"])}</td>
<td>{ep["score"]}</td>
<td>{html_escape.escape(report["host"])}</td>
<td>{html_escape.escape(ptr)}</td>
<td>{html_escape.escape(str(rdap.get("name") or ""))}</td>
<td>{html_escape.escape(domains)}</td>
<td>{ep["port"]}</td>
<td>{html_escape.escape(ep.get("url") or "")}</td>
<td>{html_escape.escape(ep.get("title") or "")}</td>
<td>{html_escape.escape(", ".join(ep.get("tech", [])))}</td>
<td>{html_escape.escape(ep.get("evidence_dir") or "")}</td>
</tr>
""")

    doc = f"""<!DOCTYPE html>
<html>
<head>
<title>No-Auth Finder Results</title>
<style>
body {{ font-family: monospace; margin: 20px; background: #0a0a0a; color: #d0ffd0; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #1a1a1a; }}
.critical {{ background: #4a0000; }}
.high {{ background: #3a1f00; }}
.medium {{ background: #333000; }}
.low {{ background: #003000; }}
</style>
</head>
<body>
<h1>No-Auth Web UI Finder Results</h1>
<table>
<tr><th>Severity</th><th>Score</th><th>Host</th><th>PTR</th><th>Network</th><th>Associated Domains</th><th>Port</th><th>URL</th><th>Title</th><th>Tech</th><th>Evidence</th></tr>
{''.join(rows)}
</table>
</body>
</html>"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(doc)


def export_markdown(reports, filename):
    lines = [
        "# No-Auth Web UI Finder Report",
        "",
        f"Generated: {utc_now()}",
        "",
        "| Severity | Score | Host | PTR | Network | Port | URL | Title | Tech | Evidence |",
        "|---|---:|---|---|---|---:|---|---|---|---|",
    ]

    for report in reports:
        enrich = report.get("enrichment", {})
        ptr = (enrich.get("reverse_dns", {}) or {}).get("ptr") or ""
        rdap = enrich.get("rdap", {}) or {}
        network = rdap.get("name") or ""

        for ep in report["noauth_endpoints"]:
            lines.append(
                f"| {ep['severity']} | {ep['score']} | {report['host']} | {ptr} | {network} | "
                f"{ep['port']} | `{ep.get('url')}` | {ep.get('title') or ''} | "
                f"{', '.join(ep.get('tech', []))} | `{ep.get('evidence_dir')}` |"
            )

    lines.append("")
    lines.append("## Associated Domains and Links")
    lines.append("")

    for report in reports:
        enrich = report.get("enrichment", {})
        lines.append(f"### {report['host']}")
        domains = enrich.get("associated_domains", [])
        urls = enrich.get("associated_urls", [])
        if domains:
            lines.append("")
            lines.append("Associated domains:")
            for d in domains[:30]:
                lines.append(f"- `{d}`")
        if urls:
            lines.append("")
            lines.append("Associated URLs:")
            for u in urls[:30]:
                lines.append(f"- `{u}`")
        lines.append("")

    lines.append("## Recommendations")
    lines.append("")

    for report in reports:
        for rec in report.get("recommendations", []):
            lines.append(f"- {rec}")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def load_state(path):
    if not path or not Path(path).exists():
        return {"completed": []}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"completed": []}


def save_state(path, state):
    if not path:
        return
    with STATE_LOCK:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)


def capture_screenshots(reports, output_dir, timeout=8):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print(f"  {C.Y}⚠ Playwright not available for screenshots. Install: pip install playwright && python3 -m playwright install chromium{C.N}")
        return

    screenshots_dir = Path(output_dir) / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 1000})

        for report in reports:
            for ep in report["noauth_endpoints"]:
                url = ep.get("final_url") or ep.get("url")
                if not url:
                    continue

                filename = screenshots_dir / f"{safe_name(report['host'] + '_' + str(ep['port']))}.png"

                try:
                    page = context.new_page()
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
                    page.wait_for_timeout(1000)
                    page.screenshot(path=str(filename), full_page=True)
                    page.close()
                    ep["screenshot"] = str(filename)

                    evidence_dir = ep.get("evidence_dir")
                    if evidence_dir:
                        with open(Path(evidence_dir) / "finding.json", "w", encoding="utf-8") as f:
                            json.dump(ep, f, indent=2)
                except Exception:
                    pass

        browser.close()


def parse_ports(args):
    if args.top10:
        return TOP10_PORTS
    if args.ports == "web":
        return COMMON_WEB_PORTS
    if args.ports == "top10":
        return TOP10_PORTS
    if "," in args.ports:
        return [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    return COMMON_WEB_PORTS


INTERNET_WARNING = f"""
{C.Y}[!] PUBLIC-IP SCOPE DETECTED{C.N}

  This target list includes public IP space.
  Gating is enabled so this does not accidentally scan the internet.
  Use --allow-public only when this is explicitly authorized scope.
"""


def main():
    try:
        banner()

        parser = argparse.ArgumentParser(description="Find unauthenticated web UIs in authorized scope")
        parser.add_argument("target", nargs="?", help="CIDR, IP, hostname, or file:ranges.txt")
        parser.add_argument("--scope-file", default="", help="File containing CIDRs/IPs/hostnames, one per line")
        parser.add_argument("--allow-public", action="store_true", help="Allow scanning public IP space")
        parser.add_argument("--ports", type=str, default="web", help="Ports: web, top10, or comma list")
        parser.add_argument("--timeout", type=int, default=5)
        parser.add_argument("--host-timeout", type=int, default=0, help="Max seconds per host budget")
        parser.add_argument("--threads", type=int, default=50)
        parser.add_argument("--fast", action="store_true", help="Skip deep path probing")
        parser.add_argument("--report", type=str, default="", help="Save report path")
        parser.add_argument("--output-dir", default="noauth_results", help="Team evidence output folder")
        parser.add_argument("--random", action="store_true", help="Randomize host scan order")
        parser.add_argument("--sample", type=int, default=0, help="Randomly sample N IPs from CIDR range")
        parser.add_argument("--delay", type=int, default=0, help="Delay in ms between hosts")
        parser.add_argument("--top10", action="store_true", help="Shorthand for --ports top10")
        parser.add_argument("--ipv6", action="store_true", help="Enable IPv6 scanning")
        parser.add_argument("--output-format", choices=["json", "csv", "html", "md"], default="json")
        parser.add_argument("--markdown-report", default="", help="Also write a Markdown report")
        parser.add_argument("--screenshots", action="store_true", help="Capture screenshots for findings")
        parser.add_argument("--no-color", action="store_true", help="Disable colored output")
        parser.add_argument("--exclude", type=str, default="", help="CIDR ranges to exclude, comma-separated")
        parser.add_argument("--resume", action="store_true", help="Skip hosts already in state file")
        parser.add_argument("--state", default="scan_state.json", help="Resume state file")

        args = parser.parse_args()

        if args.no_color:
            for key in dir(C):
                if not key.startswith("_") and len(key) == 1:
                    setattr(C, key, "")

        if not args.target and not args.scope_file:
            print(f"{C.R}[-] Provide a target or --scope-file{C.N}")
            sys.exit(1)

        output_dir = ensure_dirs(args.output_dir)
        ports = parse_ports(args)

        scope_items = []
        if args.target:
            scope_items.append(args.target)
        if args.scope_file:
            scope_items.extend(load_lines_from_file(args.scope_file))

        targets = resolve_scope(scope_items, sample=args.sample)

        if not targets:
            print(f"{C.R}[-] No targets resolved.{C.N}")
            return

        if args.exclude:
            excluded_nets = [ipaddress.ip_network(x.strip(), strict=False) for x in args.exclude.split(",") if x.strip()]
            original_count = len(targets)
            targets = [
                ip for ip in targets
                if not any(ipaddress.ip_address(ip) in net for net in excluded_nets)
            ]
            if len(targets) < original_count:
                print(f"  {C.Y}⚠ Excluded {original_count - len(targets)} IPs{C.N}")

        if is_public_scan(targets) and not args.allow_public:
            print(INTERNET_WARNING)
            print(f"  {C.R}✘ Refusing public scan without --allow-public.{C.N}")
            return

        if args.random:
            random.shuffle(targets)

        state = load_state(args.state) if args.resume else {"completed": []}
        completed = set(state.get("completed", []))

        if args.resume:
            before = len(targets)
            targets = [t for t in targets if t not in completed]
            print(f"  {C.Y}↻ Resume mode: skipped {before - len(targets)} completed hosts{C.N}")

        total = len(targets)
        print(f"  {C.B}{total:,}{C.N} hosts × {len(ports)} ports ({args.threads} threads)")
        print(f"  Output folder: {output_dir}\n")

        done_count = 0
        found_any = False
        all_reports = []
        delay_sec = args.delay / 1000.0

        def scan_ip(ip):
            nonlocal done_count

            results = scan_host_ports(
                ip,
                ports,
                timeout=args.timeout,
                fast=args.fast,
                ipv6=args.ipv6,
                host_timeout=args.host_timeout,
            )

            done_count += 1

            if args.resume:
                completed.add(ip)
                state["completed"] = sorted(completed)
                save_state(args.state, state)

            if delay_sec:
                time.sleep(delay_sec)

            if total > 10 and done_count % max(1, total // 100) == 0:
                pct = done_count * 100 // total
                print(f"  {C.D}Progress: {done_count:,}/{total:,} ({pct}%){C.N}", end="\r")

            return ip, results

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futmap = {ex.submit(scan_ip, ip): ip for ip in targets}

            for fut in concurrent.futures.as_completed(futmap):
                try:
                    ip, results = fut.result()
                    if results:
                        found = print_results(ip, results)
                        if found:
                            found_any = True
                            rpt = full_report(ip, results, output_dir=str(output_dir))
                            if rpt:
                                all_reports.append(rpt)
                except Exception:
                    pass

        if total > 10:
            print(f"  {' ' * 80}", end="\r")

        if args.screenshots and all_reports:
            print(f"\n{C.C}[*] Capturing screenshots for findings...{C.N}")
            capture_screenshots(all_reports, str(output_dir), timeout=args.timeout)

        all_reports = sorted(
            all_reports,
            key=lambda r: max([ep.get("score", 0) for ep in r.get("noauth_endpoints", [])] or [0]),
            reverse=True,
        )

        if found_any:
            print(f"\n{C.G}{C.B}[+] Done. Found hosts with unauthenticated UIs.{C.N}")
        else:
            print(f"\n{C.Y}[-] No unauthenticated web UIs found.{C.N}")

        report_path = args.report
        if not report_path:
            report_path = str(output_dir / f"findings.{args.output_format}")

        scan_meta = {
            "target": args.target,
            "scope_file": args.scope_file,
            "hosts_scanned": total,
            "hosts_with_findings": len(all_reports),
            "timestamp": utc_now(),
            "ports": ports,
            "allow_public": args.allow_public,
            "sample": args.sample,
            "threads": args.threads,
            "fast": args.fast,
        }

        if all_reports:
            if args.output_format == "json":
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump({"scan_meta": scan_meta, "findings": all_reports}, f, indent=2)
            elif args.output_format == "csv":
                export_csv(all_reports, report_path)
            elif args.output_format == "html":
                export_html(all_reports, report_path)
            elif args.output_format == "md":
                export_markdown(all_reports, report_path)

            print(f"\n  Report saved: {report_path} ({len(all_reports)} hosts)")

            csv_path = output_dir / "findings.csv"
            html_path = output_dir / "findings.html"
            md_path = output_dir / "findings.md"
            json_path = output_dir / "findings.json"

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({"scan_meta": scan_meta, "findings": all_reports}, f, indent=2)

            export_csv(all_reports, csv_path)
            export_html(all_reports, html_path)
            export_markdown(all_reports, md_path)

            if args.markdown_report:
                export_markdown(all_reports, args.markdown_report)

            print(f"  Team exports:")
            print(f"    JSON: {json_path}")
            print(f"    CSV:  {csv_path}")
            print(f"    HTML: {html_path}")
            print(f"    MD:   {md_path}")

    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Scan interrupted by user{C.N}")
        sys.exit(0)


if __name__ == "__main__":
    main()
