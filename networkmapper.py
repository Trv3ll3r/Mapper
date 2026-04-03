#!/usr/bin/env python3
"""
networkmapper.py — Map the network path from a URL to the application.

Detects WAFs, CDNs, firewalls, and proxies at each hop.
Works even when ICMP ping is disabled (uses TCP SYN traceroute).

Requirements:
    pip install scapy requests dnspython colorama

Scapy requires elevated privileges (run as Administrator on Windows,
or with sudo on Linux/macOS) for raw-socket traceroute.
If not elevated, HTTP-layer analysis still works.

Usage:
    python networkmapper.py https://example.com
    python networkmapper.py https://example.com --max-hops 30 --port 443
    python networkmapper.py https://example.com --no-traceroute
"""

import sys
import os
import ssl
import socket
import struct
import time
import json
import re
import ipaddress
import argparse
import urllib.parse
import datetime
from typing import Optional, List, Dict, Tuple, Any

# ── Optional dependencies ─────────────────────────────────────────────────────

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import (
        sr1, sr, conf as scapy_conf,
        IP, TCP, UDP, ICMP,
        RandShort, ICMP
    )
    scapy_conf.verb = 0          # silence scapy output
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# ── Colour helpers ────────────────────────────────────────────────────────────

def _c(text: str, colour: str) -> str:
    if not COLORAMA_AVAILABLE:
        return text
    colours = {
        "red":    Fore.RED,
        "green":  Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan":   Fore.CYAN,
        "blue":   Fore.BLUE,
        "magenta": Fore.MAGENTA,
        "white":  Fore.WHITE,
        "bold":   Style.BRIGHT,
        "reset":  Style.RESET_ALL,
    }
    return colours.get(colour, "") + str(text) + Style.RESET_ALL


def header(text: str) -> None:
    width = 70
    print()
    print(_c("─" * width, "cyan"))
    print(_c(f"  {text}", "bold"))
    print(_c("─" * width, "cyan"))


def info(label: str, value: str, colour: str = "white") -> None:
    print(f"  {_c(label + ':', 'cyan'):<30} {_c(value, colour)}")


# ── WAF / CDN / Proxy signatures ──────────────────────────────────────────────

WAF_SIGNATURES: Dict[str, Dict] = {
    "Cloudflare": {
        "response_headers": ["CF-RAY", "CF-Cache-Status", "cf-request-id", "CF-Connecting-IP"],
        "server_contains": ["cloudflare"],
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "via_contains": [],
    },
    "AWS CloudFront": {
        "response_headers": ["X-Amz-Cf-Id", "X-Amz-Cf-Pop"],
        "server_contains": ["CloudFront", "AmazonS3"],
        "cookies": [],
        "via_contains": ["cloudfront"],
    },
    "AWS WAF": {
        "response_headers": ["x-amzn-requestid", "x-amzn-trace-id", "x-amz-apigw-id"],
        "server_contains": [],
        "cookies": ["aws-waf-token"],
        "via_contains": [],
    },
    "Akamai": {
        "response_headers": [
            "X-Akamai-Transformed", "X-Check-Cacheable",
            "Akamai-Origin-Hop", "X-Akamai-SSL-Client-Sid",
        ],
        "server_contains": ["AkamaiGHost"],
        "cookies": ["ak_bmsc", "bm_sz", "bm_sv"],
        "via_contains": ["akamai"],
    },
    "Imperva / Incapsula": {
        "response_headers": ["X-CDN", "X-Iinfo", "X-Incap-Ses"],
        "server_contains": ["Incapsula"],
        "cookies": ["incap_ses", "visid_incap", "_incap_"],
        "via_contains": [],
    },
    "Sucuri": {
        "response_headers": ["X-Sucuri-ID", "X-Sucuri-Cache", "X-Sucuri-Country"],
        "server_contains": ["Sucuri/Cloudproxy"],
        "cookies": [],
        "via_contains": [],
    },
    "F5 BIG-IP ASM": {
        "response_headers": ["X-WA-Info", "X-Cnection"],
        "server_contains": ["BigIP", "BIG-IP"],
        "cookies": ["BIGipServer", "TS01", "TS"],
        "via_contains": [],
    },
    "Barracuda": {
        "response_headers": ["X-Barracuda-Connect", "X-Barracuda-URL"],
        "server_contains": [],
        "cookies": ["barra_counter_session"],
        "via_contains": [],
    },
    "Fastly": {
        "response_headers": ["X-Fastly-Request-ID", "Fastly-Debug-Digest"],
        "server_contains": ["Fastly"],
        "cookies": [],
        "via_contains": ["varnish"],
    },
    "Varnish Cache": {
        "response_headers": ["X-Varnish", "X-Varnish-Cache"],
        "server_contains": ["Varnish"],
        "cookies": [],
        "via_contains": ["varnish"],
    },
    "Nginx": {
        "response_headers": [],
        "server_contains": ["nginx"],
        "cookies": [],
        "via_contains": [],
    },
    "Apache": {
        "response_headers": [],
        "server_contains": ["Apache"],
        "cookies": [],
        "via_contains": [],
    },
    "Microsoft IIS": {
        "response_headers": ["X-Powered-By", "X-AspNet-Version"],
        "server_contains": ["IIS", "Microsoft-IIS"],
        "cookies": ["ASP.NET_SessionId"],
        "via_contains": [],
    },
    "DDoS-Guard": {
        "response_headers": ["X-Ddos-Protection"],
        "server_contains": ["ddos-guard"],
        "cookies": ["__ddg1", "__ddg2", "__ddgid"],
        "via_contains": [],
    },
    "Reblaze": {
        "response_headers": ["X-Reblaze-Protection"],
        "server_contains": [],
        "cookies": ["rbzid"],
        "via_contains": [],
    },
    "Wordfence": {
        "response_headers": [],
        "server_contains": [],
        "cookies": ["wfwaf-authcookie"],
        "via_contains": [],
    },
    "ModSecurity": {
        # Detected by body content on block pages
        "body_patterns": [r"mod_security", r"ModSecurity", r"NOYB", r"406 Not Acceptable"],
        "response_headers": [],
        "server_contains": [],
        "cookies": [],
        "via_contains": [],
    },
    "Palo Alto": {
        "response_headers": ["X-PAN-", "X-Panorama-"],
        "server_contains": [],
        "cookies": [],
        "via_contains": [],
    },
    "Fortinet FortiWeb": {
        "response_headers": ["X-Fw-"],
        "server_contains": ["FortiWeb"],
        "cookies": [],
        "via_contains": [],
    },
}

# IPs/ranges known to belong to major CDNs (spot-check, not exhaustive)
CDN_ASN_HINTS = {
    "13335": "Cloudflare",
    "16509": "Amazon AWS",
    "15169": "Google",
    "32934": "Facebook/Meta",
    "20940": "Akamai",
    "54113": "Fastly",
    "46489": "Twitch/Fastly",
}


# ── Utilities ─────────────────────────────────────────────────────────────────

def parse_url(raw: str) -> Tuple[str, str, int, str]:
    """Return (scheme, host, port, path)."""
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urllib.parse.urlparse(raw)
    scheme = p.scheme.lower()
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return scheme, host, port, path


def resolve_host(host: str) -> List[str]:
    """Resolve hostname to list of IPs."""
    results = []
    try:
        infos = socket.getaddrinfo(host, None)
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                results.append(ip)
    except socket.gaierror as e:
        print(_c(f"  [!] DNS resolution failed: {e}", "red"))
    return results


def reverse_dns(ip: str) -> str:
    """Attempt PTR lookup for an IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_tls_cert(host: str, port: int, timeout: float = 5.0) -> Optional[Dict]:
    """Grab TLS certificate details."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {"cert": cert, "cipher": cipher, "tls_version": version}
    except Exception:
        return None


def format_cert_info(tls: Dict) -> List[str]:
    lines = []
    cert = tls.get("cert", {})
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuerAlt", cert.get("issuer", [])))
    lines.append(f"TLS Version : {tls.get('tls_version', 'unknown')}")
    lines.append(f"Cipher      : {tls.get('cipher', ('?', '?', '?'))[0]}")
    if "commonName" in subject:
        lines.append(f"Subject CN  : {subject['commonName']}")
    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    if sans:
        lines.append(f"SANs        : {', '.join(sans[:8])}" + (" ..." if len(sans) > 8 else ""))
    not_after = cert.get("notAfter", "")
    if not_after:
        lines.append(f"Expires     : {not_after}")
    return lines


# ── WAF Detection ─────────────────────────────────────────────────────────────

def detect_waf(
    response_headers: Dict[str, str],
    cookies: Dict[str, str],
    body: str = "",
    status_code: int = 200,
) -> List[str]:
    """Return list of detected WAF/CDN/server names."""
    detected = []
    headers_lower = {k.lower(): v for k, v in response_headers.items()}
    cookies_lower = {k.lower(): v for k, v in cookies.items()}
    server_val = headers_lower.get("server", "").lower()
    via_val    = headers_lower.get("via", "").lower()

    for name, sig in WAF_SIGNATURES.items():
        matched = False

        # Check response header keys
        for h in sig.get("response_headers", []):
            if h.lower() in headers_lower:
                matched = True
                break

        # Check server string
        if not matched:
            for s in sig.get("server_contains", []):
                if s.lower() in server_val:
                    matched = True
                    break

        # Check via header
        if not matched:
            for v in sig.get("via_contains", []):
                if v.lower() in via_val:
                    matched = True
                    break

        # Check cookies
        if not matched:
            for ck in sig.get("cookies", []):
                if any(ck.lower() in k for k in cookies_lower):
                    matched = True
                    break

        # Check body patterns (for block pages)
        if not matched:
            for pat in sig.get("body_patterns", []):
                if re.search(pat, body, re.I):
                    matched = True
                    break

        if matched:
            detected.append(name)

    # Detect generic CDN via Via header
    if "via" in headers_lower and not any(
        "CDN" in d or "Cache" in d or "Fastly" in d or "Varnish" in d for d in detected
    ):
        detected.append(f"Proxy/CDN (Via: {headers_lower['via'][:60]})")

    return detected


def detect_waf_by_probe(
    scheme: str, host: str, port: int, path: str, timeout: float = 10.0
) -> Tuple[Dict, Dict, str, int, str]:
    """
    Make an HTTP/S request and return (headers, cookies, body, status_code, redirect_chain).
    Also probes with a malformed request to trigger WAF block pages.
    """
    if not REQUESTS_AVAILABLE:
        return {}, {}, "", 0, ""

    session = requests.Session()
    # Suppress SSL warnings for scan purposes
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers_out = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    url = f"{scheme}://{host}:{port}{path}" if port not in (80, 443) else f"{scheme}://{host}{path}"
    redirect_chain = []

    try:
        resp = session.get(
            url,
            headers=headers_out,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        for r in resp.history:
            redirect_chain.append(f"{r.status_code} → {r.headers.get('Location', '?')}")
        return (
            dict(resp.headers),
            dict(resp.cookies),
            resp.text[:4096],
            resp.status_code,
            " | ".join(redirect_chain),
        )
    except requests.exceptions.SSLError:
        try:
            resp = session.get(url, headers=headers_out, timeout=timeout, verify=False)
            return dict(resp.headers), dict(resp.cookies), resp.text[:4096], resp.status_code, ""
        except Exception as e:
            return {}, {}, "", 0, str(e)
    except Exception as e:
        return {}, {}, "", 0, str(e)


# ── Application-layer proxy chain extraction ─────────────────────────────────

def extract_proxy_chain(resp_headers: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Parse X-Forwarded-For, Forwarded, Via and X-Real-IP headers to reconstruct
    the chain of proxies/load-balancers the application actually sees.
    Returns list of dicts: [{ip, source_header, hostname}]
    """
    chain: List[Dict[str, str]] = []
    headers_lower = {k.lower(): v for k, v in resp_headers.items()}

    # X-Forwarded-For: client, proxy1, proxy2, ...
    xff = headers_lower.get("x-forwarded-for", "")
    if xff:
        for raw_ip in [x.strip() for x in xff.split(",")]:
            ip = raw_ip.split(":")[0]  # strip port if present
            try:
                ipaddress.ip_address(ip)
                chain.append({"ip": ip, "source": "X-Forwarded-For",
                               "hostname": reverse_dns(ip)})
            except ValueError:
                pass

    # Forwarded: for=<ip>;by=<ip>;host=<host>;proto=<proto>
    forwarded = headers_lower.get("forwarded", "")
    for part in forwarded.split(","):
        for segment in part.split(";"):
            segment = segment.strip()
            if segment.lower().startswith("for="):
                raw = segment[4:].strip('"').strip("[]")
                ip = raw.split(":")[0]
                try:
                    ipaddress.ip_address(ip)
                    if not any(e["ip"] == ip for e in chain):
                        chain.append({"ip": ip, "source": "Forwarded",
                                      "hostname": reverse_dns(ip)})
                except ValueError:
                    pass

    # X-Real-IP: single upstream IP (nginx convention)
    real_ip = headers_lower.get("x-real-ip", "").strip()
    if real_ip:
        try:
            ipaddress.ip_address(real_ip)
            if not any(e["ip"] == real_ip for e in chain):
                chain.append({"ip": real_ip, "source": "X-Real-IP",
                              "hostname": reverse_dns(real_ip)})
        except ValueError:
            pass

    # Via: 1.1 proxy1.example.com (squid/4.x), 1.1 proxy2.example.com
    via = headers_lower.get("via", "")
    for segment in via.split(","):
        segment = segment.strip()
        # format: version proxy-name [comment]
        parts = segment.split()
        if len(parts) >= 2:
            proxy_name = parts[1].split(":")[0]  # strip port
            if proxy_name and proxy_name not in ("anonymous", "unknown"):
                try:
                    ipaddress.ip_address(proxy_name)
                    entry = {"ip": proxy_name, "source": "Via",
                             "hostname": reverse_dns(proxy_name)}
                except ValueError:
                    entry = {"ip": "", "source": "Via", "hostname": proxy_name}
                if not any(
                    e["ip"] == entry["ip"] and e["hostname"] == entry["hostname"]
                    for e in chain
                ):
                    chain.append(entry)

    return chain


# ── Firewall behaviour fingerprinting ─────────────────────────────────────────

FIREWALL_SIGNATURES = {
    # (icmp_type, icmp_code) → (name, description)
    (3, 0):  ("Router/FW",     "Network unreachable — routing failure or ACL"),
    (3, 1):  ("Router/FW",     "Host unreachable — host-based firewall or no route"),
    (3, 2):  ("FW",            "Protocol unreachable — protocol filtering"),
    (3, 3):  ("FW",            "Port unreachable — port filtered (stateless FW)"),
    (3, 9):  ("ACL FW",        "Net admin prohibited — router ACL"),
    (3, 10): ("ACL FW",        "Host admin prohibited — router ACL"),
    (3, 11): ("ACL FW",        "Net ToS admin prohibited"),
    (3, 12): ("ACL FW",        "Host ToS admin prohibited"),
    (3, 13): ("Stateful FW",   "Admin prohibited — stateful firewall (iptables REJECT)"),
}

TCP_FW_SIGNATURES = {
    # tcp_flags bitmask → (name, description)
    0x04: ("FW/Host",   "RST — connection reset; port closed or stateless firewall"),
    0x14: ("FW/Host",   "RST-ACK — connection reset by host or inline device"),
}


def fingerprint_firewall_hop(hop: "HopResult") -> Optional[Tuple[str, str]]:
    """Return (firewall_type, description) if hop looks like a firewall."""
    if hop.icmp_type is not None and hop.icmp_code is not None:
        key = (hop.icmp_type, hop.icmp_code)
        if key in FIREWALL_SIGNATURES:
            return FIREWALL_SIGNATURES[key]
    return None


def classify_silence(ttl_before: int, ttl_after: int, target_reached: bool) -> str:
    """Interpret a block of timeout hops."""
    span = ttl_after - ttl_before
    if not target_reached:
        return (
            f"{span} consecutive timeouts then target NOT reached — "
            "firewall is silently dropping packets (stateful DROP rule or ACL)"
        )
    return (
        f"{span} consecutive timeouts — hops are suppressing ICMP TTL-exceeded "
        "(common for load-balancers, CDN PoPs, or firewalls with ICMP rate-limiting)"
    )


# ── Allowed-port discovery ────────────────────────────────────────────────────

PROBE_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
    993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 8888,
]


def discover_allowed_ports(
    target_ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.5,
) -> Tuple[List[int], List[int]]:
    """
    Connect-scan to classify ports as open, closed (RST), or filtered (no reply).
    Returns (open_ports, filtered_ports).
    Filtered = firewall is passing the SYN but the port isn't listening,
    or the firewall is silently dropping.  We distinguish by timeout vs RST.
    """
    if ports is None:
        ports = PROBE_PORTS

    open_ports: List[int] = []
    filtered_ports: List[int] = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
            elif result in (111, 10061):  # ECONNREFUSED — RST received
                pass  # port closed but reachable (FW passes traffic)
        except socket.timeout:
            filtered_ports.append(port)  # silence — likely filtered
        except Exception:
            pass

    return open_ports, filtered_ports


# ── Multi-port TCP SYN traceroute ─────────────────────────────────────────────

def multi_port_traceroute(
    target_ip: str,
    ports: Optional[List[int]] = None,
    max_hops: int = 30,
    timeout: float = 2.0,
    probes_per_hop: int = 2,
) -> Dict[int, List["HopResult"]]:
    """
    Run TCP SYN traceroute simultaneously on several ports.
    Firewalls often block one port but pass another — comparing paths
    reveals where filtering begins and which path goes through.
    Returns {port: [HopResult, ...]}
    """
    if not SCAPY_AVAILABLE:
        return {}
    if ports is None:
        ports = [80, 443, 8080, 8443]

    results: Dict[int, List[HopResult]] = {}
    for port in ports:
        results[port] = tcp_syn_traceroute(
            target_ip,
            dest_port=port,
            max_hops=max_hops,
            timeout=timeout,
            probes_per_hop=probes_per_hop,
        )
    return results


# ── UDP traceroute ────────────────────────────────────────────────────────────

def udp_traceroute_scapy(
    target_ip: str,
    dest_port: int = 33434,
    max_hops: int = 30,
    timeout: float = 2.0,
) -> List["HopResult"]:
    """
    UDP-based traceroute (classic style, like unix traceroute).
    Uses incrementing dest ports starting at dest_port.
    Receives ICMP port-unreachable at the target to confirm arrival.
    """
    if not SCAPY_AVAILABLE:
        return []

    results: List[HopResult] = []

    for ttl in range(1, max_hops + 1):
        hop = HopResult(ttl)
        pkt = IP(dst=target_ip, ttl=ttl) / UDP(sport=int(RandShort()),
                                                 dport=dest_port + ttl)
        t0 = time.time()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        rtt = (time.time() - t0) * 1000

        if reply is None:
            hop.hop_type = "timeout"
        else:
            hop.ip = reply.src
            hop.rtt_ms = rtt
            hop.hostname = reverse_dns(hop.ip) if not is_private_ip(hop.ip) else ""

            if reply.haslayer(ICMP):
                icmp = reply.getlayer(ICMP)
                hop.icmp_type = icmp.type
                hop.icmp_code = icmp.code
                if icmp.type == 11:
                    hop.hop_type = "transit"
                elif icmp.type == 3 and icmp.code == 3:
                    hop.hop_type = "target"   # port unreachable = arrived
                    hop.notes.append("UDP port-unreachable (target)")
                elif icmp.type == 3:
                    sig = FIREWALL_SIGNATURES.get((3, icmp.code))
                    hop.hop_type = "firewall"
                    hop.notes.append(sig[1] if sig else f"ICMP-3/{icmp.code}")
                else:
                    hop.hop_type = "transit"

        results.append(hop)
        if hop.hop_type == "target":
            break

    return results


# ── Merge multi-port results ──────────────────────────────────────────────────

def merge_traceroute_results(
    port_results: Dict[int, List["HopResult"]],
) -> List[Dict]:
    """
    Align hop results from multiple ports by TTL.
    Returns list of dicts: {ttl, per_port: {port: HopResult}}
    Useful for spotting where paths diverge or where firewall cuts off a port.
    """
    if not port_results:
        return []
    max_ttl = max((h.ttl for hops in port_results.values() for h in hops), default=0)
    merged = []
    for ttl in range(1, max_ttl + 1):
        row: Dict[str, Any] = {"ttl": ttl, "per_port": {}}
        for port, hops in port_results.items():
            match = next((h for h in hops if h.ttl == ttl), None)
            row["per_port"][port] = match
        merged.append(row)
    return merged


# ── TCP SYN Traceroute (scapy) ────────────────────────────────────────────────

class HopResult:
    def __init__(self, ttl: int):
        self.ttl       = ttl
        self.ip        = None
        self.rtt_ms    = None
        self.hostname  = None
        self.hop_type  = "transit"      # transit | firewall | target | timeout
        self.icmp_type = None
        self.icmp_code = None
        self.notes: List[str] = []

    def __str__(self) -> str:
        ip_str = self.ip or "*"
        rtt_str = f"{self.rtt_ms:.1f} ms" if self.rtt_ms is not None else "timeout"
        host_str = f" ({self.hostname})" if self.hostname else ""
        flags = f"  [{', '.join(self.notes)}]" if self.notes else ""
        colour = {
            "transit":  "white",
            "firewall": "yellow",
            "target":   "green",
            "timeout":  "red",
        }.get(self.hop_type, "white")
        return _c(
            f"  {self.ttl:>3}.  {ip_str:<18}{host_str:<35} {rtt_str:<12}{flags}",
            colour,
        )


def tcp_syn_traceroute(
    target_ip: str,
    dest_port: int = 443,
    max_hops: int = 30,
    timeout: float = 2.0,
    probes_per_hop: int = 3,
) -> List[HopResult]:
    """
    Send TCP SYN packets with increasing TTL to trace the path.
    Works when ICMP is blocked because routers still send ICMP TTL-exceeded
    in response to any IP packet.
    """
    if not SCAPY_AVAILABLE:
        return []

    results: List[HopResult] = []

    for ttl in range(1, max_hops + 1):
        hop = HopResult(ttl)
        best_rtt = None

        for _ in range(probes_per_hop):
            sport = int(RandShort())
            pkt = IP(dst=target_ip, ttl=ttl) / TCP(sport=sport, dport=dest_port, flags="S")
            t0 = time.time()
            reply = sr1(pkt, timeout=timeout, verbose=0)
            rtt = (time.time() - t0) * 1000

            if reply is None:
                continue

            if best_rtt is None or rtt < best_rtt:
                best_rtt = rtt

            reply_ip = reply.src
            hop.ip = reply_ip
            hop.rtt_ms = best_rtt

            # Classify the reply
            if reply.haslayer(ICMP):
                icmp = reply.getlayer(ICMP)
                hop.icmp_type = icmp.type
                hop.icmp_code = icmp.code

                if icmp.type == 11:  # TTL exceeded — normal transit
                    hop.hop_type = "transit"
                elif icmp.type == 3:  # Destination unreachable
                    hop.hop_type = "firewall"
                    code_msgs = {
                        0: "net unreachable",
                        1: "host unreachable",
                        2: "protocol unreachable",
                        3: "port unreachable",
                        9: "net admin prohibited",
                        10: "host admin prohibited",
                        13: "admin prohibited (firewall)",
                    }
                    hop.notes.append(
                        f"ICMP-3/{icmp.code}: {code_msgs.get(icmp.code, 'unreachable')}"
                    )

            elif reply.haslayer(TCP):
                tcp_layer = reply.getlayer(TCP)
                if tcp_layer.flags & 0x12:  # SYN-ACK — port open, we've arrived
                    hop.hop_type = "target"
                    hop.notes.append("SYN-ACK (port open)")
                elif tcp_layer.flags & 0x14:  # RST-ACK
                    hop.hop_type = "target"
                    hop.notes.append("RST (port closed/filtered by host)")
                elif tcp_layer.flags & 0x04:  # RST
                    hop.hop_type = "firewall"
                    hop.notes.append("RST (firewall reset)")

            break  # got a reply; no need for more probes this TTL

        if hop.ip is None:
            hop.hop_type = "timeout"

        # PTR lookup (non-blocking best-effort)
        if hop.ip and not is_private_ip(hop.ip):
            hop.hostname = reverse_dns(hop.ip)

        results.append(hop)

        if hop.hop_type == "target":
            break

    return results


def socket_traceroute(
    target_ip: str,
    dest_port: int = 443,
    max_hops: int = 30,
    timeout: float = 2.0,
) -> List[HopResult]:
    """
    Raw-socket UDP/ICMP traceroute fallback (no scapy).
    Uses ICMP echo; less reliable through firewalls than TCP SYN.
    Requires elevated privileges.
    """
    results: List[HopResult] = []
    ICMP_ECHO_REQUEST = 8

    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout)
    except PermissionError:
        return []

    for ttl in range(1, max_hops + 1):
        hop = HopResult(ttl)

        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            send_sock.settimeout(timeout)

            send_sock.sendto(b"", (target_ip, dest_port))
            t0 = time.time()

            try:
                data, addr = recv_sock.recvfrom(512)
                hop.rtt_ms = (time.time() - t0) * 1000
                hop.ip = addr[0]
                hop.hostname = reverse_dns(hop.ip)
                hop.hop_type = "target" if addr[0] == target_ip else "transit"
            except socket.timeout:
                hop.hop_type = "timeout"
        except Exception:
            hop.hop_type = "timeout"
        finally:
            try:
                send_sock.close()
            except Exception:
                pass

        results.append(hop)
        if hop.hop_type == "target":
            break

    recv_sock.close()
    return results


def run_system_traceroute(target_ip: str, max_hops: int = 30) -> List[str]:
    """Fall back to system tracert/traceroute and return raw lines."""
    import subprocess
    if sys.platform == "win32":
        cmd = ["tracert", "-h", str(max_hops), "-w", "2000", target_ip]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", "2", target_ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout.splitlines()
    except Exception as e:
        return [f"System traceroute failed: {e}"]


# ── Port scan ─────────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "HTTP-dev",
    27017: "MongoDB",
}


def quick_port_scan(
    target_ip: str, ports: Optional[List[int]] = None, timeout: float = 1.5
) -> Dict[int, str]:
    """Return dict of {port: "open"/"closed"} for given ports."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            if result == 0:
                open_ports[port] = COMMON_PORTS.get(port, "unknown")
        except Exception:
            pass
    return open_ports


# ── DNS enumeration ───────────────────────────────────────────────────────────

def dns_info(host: str) -> Dict[str, Any]:
    info_dict: Dict[str, Any] = {}

    # A records
    try:
        ips = [r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET)]
        info_dict["A"] = list(dict.fromkeys(ips))
    except Exception:
        info_dict["A"] = []

    # AAAA records
    try:
        ipv6 = [r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET6)]
        info_dict["AAAA"] = list(dict.fromkeys(ipv6))
    except Exception:
        info_dict["AAAA"] = []

    if DNS_AVAILABLE:
        for rtype in ("MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(host, rtype)
                info_dict[rtype] = [str(r) for r in answers]
            except Exception:
                pass
    return info_dict


# ── Main mapper ───────────────────────────────────────────────────────────────

class NetworkMapper:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.scheme, self.host, self.port, self.path = parse_url(args.url)
        self.target_ips: List[str] = []
        self.primary_ip: str = ""
        # Collected data for diagram / JSON export
        self._hops: List[HopResult] = []
        self._waf_detected: List[str] = []
        self._open_ports: Dict[int, str] = {}
        self._http_status: int = 0
        self._tls_data: Optional[Dict] = None
        self._dns_records: Dict[str, Any] = {}
        self._proxy_chain: List[Dict[str, str]] = []
        self._port_results: Dict[int, List[HopResult]] = {}
        self._udp_hops: List[HopResult] = []
        self._allowed_ports: List[int] = []
        self._filtered_ports: List[int] = []

    def run(self) -> None:
        self._print_banner()
        self._resolve()
        if not self.primary_ip:
            print(_c("  [!] Cannot continue without a resolved IP.", "red"))
            return
        if not self.args.no_http:
            self._http_analysis()
        if not self.args.no_traceroute:
            self._traceroute()
        if getattr(self.args, "penetrate", False):
            self._firewall_penetration()
        if self.args.port_scan:
            self._port_scan()
        if not self.args.no_tls and self.scheme == "https":
            self._tls_info()
        self._dns_info()
        if getattr(self.args, "mermaid", False) or getattr(self.args, "mermaid_file", None):
            self._output_mermaid()
        print()

    # ── Banner ────────────────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        print()
        print(_c("═" * 70, "cyan"))
        print(_c("  NetworkMapper — WAF/Firewall Path Analyser", "bold"))
        print(_c("═" * 70, "cyan"))
        info("Target URL", self.args.url)
        info("Scheme",     self.scheme.upper())
        info("Host",       self.host)
        info("Port",       str(self.port))
        info("Path",       self.path)

    # ── DNS / Resolution ──────────────────────────────────────────────────────

    def _resolve(self) -> None:
        header("DNS Resolution")
        self.target_ips = resolve_host(self.host)
        if not self.target_ips:
            return
        self.primary_ip = self.target_ips[0]
        for ip in self.target_ips:
            flag = " (private)" if is_private_ip(ip) else ""
            info("Resolved IP", ip + flag, "green")
        if len(self.target_ips) > 1:
            info("Note", "Multiple IPs — possible CDN/load-balancer", "yellow")

    # ── HTTP / WAF analysis ───────────────────────────────────────────────────

    def _http_analysis(self) -> None:
        header("HTTP Layer Analysis")
        if not REQUESTS_AVAILABLE:
            print(_c("  [!] 'requests' library not installed. Skipping HTTP analysis.", "yellow"))
            return

        resp_headers, cookies, body, status, redirects = detect_waf_by_probe(
            self.scheme, self.host, self.port, self.path,
            timeout=self.args.timeout,
        )

        if status == 0:
            print(_c(f"  [!] HTTP request failed: {redirects}", "red"))
            return

        info("HTTP Status", str(status), "green" if status < 400 else "yellow")

        if redirects:
            info("Redirects", redirects, "yellow")

        # Key response headers
        interesting = [
            "Server", "X-Powered-By", "Via", "X-Cache", "Age",
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "Access-Control-Allow-Origin",
        ]
        print()
        print(_c("  Response Headers:", "cyan"))
        shown = set()
        for h in interesting:
            if h.lower() in {k.lower(): v for k, v in resp_headers.items()}:
                val = next(v for k, v in resp_headers.items() if k.lower() == h.lower())
                info(f"    {h}", val[:80])
                shown.add(h.lower())
        # Any extra headers we haven't shown
        for k, v in resp_headers.items():
            if k.lower() not in shown and any(
                x in k.lower() for x in ["waf", "cdn", "cf-", "x-amz", "akamai", "fastly", "incap"]
            ):
                info(f"    {k}", v[:80], "yellow")

        # Cookies
        if cookies:
            print()
            print(_c("  Cookies:", "cyan"))
            for name, val in list(cookies.items())[:10]:
                info(f"    {name}", val[:60])

        # Application-layer proxy chain
        proxy_chain = extract_proxy_chain(resp_headers)
        self._proxy_chain = proxy_chain
        if proxy_chain:
            print()
            print(_c("  Application-layer Proxy Chain (from response headers):", "bold"))
            print(_c("  (These are hops the application itself reports — may reveal", "yellow"))
            print(_c("   internal infrastructure hidden behind the firewall)", "yellow"))
            for i, entry in enumerate(proxy_chain):
                display_ip   = entry["ip"] or "?"
                display_host = f"  ({entry['hostname']})" if entry["hostname"] else ""
                src = entry["source"]
                print(
                    f"    {_c(str(i+1), 'cyan')}. "
                    f"{_c(display_ip, 'green')}{display_host}  "
                    f"{_c('[' + src + ']', 'yellow')}"
                )

        # WAF detection
        print()
        detected = detect_waf(resp_headers, cookies, body, status)
        self._waf_detected = detected
        self._http_status  = status
        if detected:
            print(_c("  Detected WAF / CDN / Infrastructure:", "bold"))
            for d in detected:
                colour = "red" if any(
                    x in d for x in ["WAF", "Firewall", "ModSecurity", "ASM", "Imperva", "F5"]
                ) else "yellow"
                print(f"    {_c('►', 'green')} {_c(d, colour)}")
        else:
            print(_c("  No known WAF/CDN signatures detected in HTTP response.", "white"))
            print(_c("  (WAF may still be present but not fingerprinted this way.)", "yellow"))

    # ── Traceroute ────────────────────────────────────────────────────────────

    def _traceroute(self) -> None:
        header(f"Network Path  ({self.primary_ip}:{self.port})")

        if SCAPY_AVAILABLE:
            print(
                _c(
                    f"  TCP SYN traceroute on port {self.port} "
                    f"(max {self.args.max_hops} hops) …",
                    "cyan",
                )
            )
            hops = tcp_syn_traceroute(
                self.primary_ip,
                dest_port=self.port,
                max_hops=self.args.max_hops,
                timeout=self.args.timeout,
                probes_per_hop=self.args.probes,
            )

            if hops:
                self._hops = hops
                print()
                print(
                    _c(
                        f"  {'TTL':>3}   {'IP':<18}{'Hostname':<35} {'RTT':<12} Notes",
                        "cyan",
                    )
                )
                print(_c("  " + "─" * 66, "cyan"))
                for hop in hops:
                    print(hop)

                # Summarise findings
                timeouts     = sum(1 for h in hops if h.hop_type == "timeout")
                fw_hops      = [h for h in hops if h.hop_type == "firewall"]
                target_found = any(h.hop_type == "target" for h in hops)

                print()
                info("Total hops",       str(len(hops)))
                info("Timeouts",         str(timeouts), "yellow" if timeouts else "white")
                info("Firewall signals", str(len(fw_hops)), "red" if fw_hops else "green")
                info("Target reached",   "Yes" if target_found else "No",
                     "green" if target_found else "red")

                if timeouts > 3:
                    print(
                        _c(
                            "\n  [!] Multiple timeouts detected — ICMP TTL-exceeded may be "
                            "filtered by upstream firewalls.",
                            "yellow",
                        )
                    )
                if fw_hops:
                    print(_c("\n  [!] Possible firewall hops:", "red"))
                    for h in fw_hops:
                        print(f"      TTL {h.ttl}: {h.ip}  {', '.join(h.notes)}")
            else:
                print(_c("  [!] No hops returned — need Administrator/root privileges?", "red"))
                self._fallback_traceroute()

        elif self._check_raw_sock_privileges():
            print(_c("  Scapy not found; trying raw-socket ICMP traceroute …", "yellow"))
            hops = socket_traceroute(
                self.primary_ip, dest_port=self.port, max_hops=self.args.max_hops,
                timeout=self.args.timeout,
            )
            if hops:
                for hop in hops:
                    print(hop)
            else:
                self._fallback_traceroute()
        else:
            self._fallback_traceroute()

    # ── Firewall penetration analysis ─────────────────────────────────────────

    def _firewall_penetration(self) -> None:
        """
        Advanced mode: try to map past firewalls by:
         1. Probing which ports the firewall allows (open vs filtered)
         2. Running TCP SYN traceroute on EACH allowed port
         3. Running UDP traceroute (different ACL path)
         4. Comparing paths to pinpoint where filtering occurs
         5. Fingerprinting each firewall hop
        """
        header("Firewall Penetration Analysis")

        # ── 1. Port allowlist discovery ──────────────────────────────────────
        print(_c("  [1/4] Probing allowed ports through firewall …", "cyan"))
        allowed, filtered = discover_allowed_ports(
            self.primary_ip, timeout=self.args.timeout
        )
        self._allowed_ports  = allowed
        self._filtered_ports = filtered

        if allowed:
            print(_c("  Ports with responses (firewall passes these):", "green"))
            for p in allowed:
                svc = COMMON_PORTS.get(p, PROBE_PORTS and "unknown" or "")
                print(f"    {_c(str(p), 'green')}/tcp  ({svc}) — reachable")
        if filtered:
            print(_c("  Ports with no reply (firewall silently drops):", "yellow"))
            for p in filtered[:12]:   # cap output
                print(f"    {_c(str(p), 'yellow')}/tcp  — filtered / dropped")

        # ── 2. Multi-port TCP SYN traceroute ─────────────────────────────────
        if not SCAPY_AVAILABLE:
            print(_c("\n  [!] Scapy unavailable — skipping multi-port traceroute.", "red"))
            print(_c("      pip install scapy  (run as Administrator)", "yellow"))
        else:
            # Pick ports to probe: prefer ports we know the firewall allows,
            # plus a few "hopefully allowed" ones not in the open list.
            probe_ports = list(dict.fromkeys(
                allowed[:4] + [80, 443, 8080, 8443]
            ))[:6]
            if self.port not in probe_ports:
                probe_ports.insert(0, self.port)
            probe_ports = probe_ports[:6]

            print(
                _c(
                    f"\n  [2/4] Multi-port TCP SYN traceroute on ports "
                    f"{probe_ports} …",
                    "cyan",
                )
            )
            self._port_results = multi_port_traceroute(
                self.primary_ip,
                ports=probe_ports,
                max_hops=self.args.max_hops,
                timeout=self.args.timeout,
                probes_per_hop=2,
            )
            self._print_multiport_table(probe_ports)

            # ── 3. UDP traceroute ─────────────────────────────────────────────
            print(_c("\n  [3/4] UDP traceroute (classic protocol path) …", "cyan"))
            self._udp_hops = udp_traceroute_scapy(
                self.primary_ip,
                max_hops=self.args.max_hops,
                timeout=self.args.timeout,
            )
            if self._udp_hops:
                print()
                print(
                    _c(f"  {'TTL':>3}   {'IP':<18}{'Hostname':<30} {'RTT':<10} Notes", "cyan")
                )
                print(_c("  " + "─" * 60, "cyan"))
                for hop in self._udp_hops:
                    print(hop)
            else:
                print(_c("  No UDP replies — all UDP may be filtered.", "yellow"))

        # ── 4. Firewall hop fingerprinting ───────────────────────────────────
        print(_c("\n  [4/4] Firewall hop fingerprinting …", "cyan"))
        all_hops = self._hops + self._udp_hops
        fw_findings: List[Tuple[HopResult, str, str]] = []
        for hop in all_hops:
            result = fingerprint_firewall_hop(hop)
            if result:
                fw_type, desc = result
                fw_findings.append((hop, fw_type, desc))

        if fw_findings:
            print()
            for hop, fw_type, desc in fw_findings:
                ip_str = hop.ip or "unknown"
                print(
                    f"  TTL {_c(str(hop.ttl), 'cyan'):>3}: "
                    f"{_c(ip_str, 'yellow'):<20} "
                    f"{_c(fw_type, 'red')} — {desc}"
                )
        else:
            print(_c("  No ICMP firewall signals detected in recorded hops.", "white"))

        # ── Silence analysis ─────────────────────────────────────────────────
        self._analyse_silence_blocks()

    def _print_multiport_table(self, ports: List[int]) -> None:
        """Print aligned table of hop IPs for each port side-by-side."""
        merged = merge_traceroute_results(self._port_results)
        if not merged:
            return

        col_w = 20
        header_row = f"  {'TTL':>3}  " + "".join(f":{p:<{col_w-1}}" for p in ports)
        print()
        print(_c(header_row, "cyan"))
        print(_c("  " + "─" * (5 + col_w * len(ports)), "cyan"))

        for row in merged:
            ttl = row["ttl"]
            cells = []
            types_this_row = set()
            for port in ports:
                hop: Optional[HopResult] = row["per_port"].get(port)
                if hop is None:
                    cells.append("—" + " " * (col_w - 1))
                elif hop.hop_type == "timeout":
                    cells.append(_c("*" + " " * (col_w - 1), "red"))
                    types_this_row.add("timeout")
                else:
                    ip_str = (hop.ip or "?")[:col_w - 1]
                    colour = {
                        "target":   "green",
                        "firewall": "red",
                        "transit":  "white",
                    }.get(hop.hop_type, "white")
                    cells.append(_c(ip_str.ljust(col_w), colour))
                    types_this_row.add(hop.hop_type)

            # Highlight rows where ports diverge (different IPs or one times out)
            ips_this_row = set()
            for port in ports:
                hop = row["per_port"].get(port)
                if hop and hop.ip:
                    ips_this_row.add(hop.ip)

            diverge_flag = ""
            if len(ips_this_row) > 1:
                diverge_flag = _c("  ← path diverges", "magenta")
            elif "timeout" in types_this_row and types_this_row != {"timeout"}:
                diverge_flag = _c("  ← firewall blocks some ports here", "yellow")
            elif types_this_row == {"timeout"}:
                diverge_flag = _c("  ← all ports filtered", "red")

            print(f"  {ttl:>3}  " + "".join(cells) + diverge_flag)

        print()
        print(_c("  Legend:", "cyan"))
        print("    " + _c("*", "red")       + " = timeout (filtered)   "
              + _c("IP", "green")   + " = target   "
              + _c("IP", "white")   + " = transit   "
              + _c("← diverges", "magenta") + " = ECMP or different path")

    def _analyse_silence_blocks(self) -> None:
        """Report on blocks of consecutive timeouts in the primary trace."""
        if not self._hops:
            return

        target_reached = any(h.hop_type == "target" for h in self._hops)
        in_block = False
        block_start = 0

        for i, hop in enumerate(self._hops):
            if hop.hop_type == "timeout" and not in_block:
                in_block = True
                block_start = hop.ttl
            elif hop.hop_type != "timeout" and in_block:
                in_block = False
                msg = classify_silence(block_start, hop.ttl, target_reached)
                print(_c(f"\n  [!] TTL {block_start}–{hop.ttl - 1}: {msg}", "yellow"))

        if in_block:
            last_ttl = self._hops[-1].ttl
            msg = classify_silence(block_start, last_ttl, target_reached)
            print(_c(f"\n  [!] TTL {block_start}–{last_ttl}: {msg}", "yellow"))

    def _fallback_traceroute(self) -> None:
        print(_c("  Falling back to system tracert/traceroute …", "yellow"))
        lines = run_system_traceroute(self.primary_ip, self.args.max_hops)
        for line in lines:
            print("  " + line)

    @staticmethod
    def _check_raw_sock_privileges() -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            return True
        except PermissionError:
            return False

    # ── Port scan ─────────────────────────────────────────────────────────────

    def _port_scan(self) -> None:
        header("Port Scan (common ports)")
        print(_c("  Scanning common ports …", "cyan"))
        open_ports = quick_port_scan(self.primary_ip, timeout=self.args.timeout)
        self._open_ports = open_ports
        if open_ports:
            for port, service in sorted(open_ports.items()):
                colour = "green" if port in (80, 443, 22) else "yellow"
                info(f"  {port}/tcp", f"OPEN  ({service})", colour)
        else:
            print(_c("  No common ports open (or all filtered).", "yellow"))

    # ── TLS ───────────────────────────────────────────────────────────────────

    def _tls_info(self) -> None:
        header("TLS Certificate")
        tls = get_tls_cert(self.host, self.port, timeout=self.args.timeout)
        self._tls_data = tls
        if tls:
            for line in format_cert_info(tls):
                label, _, value = line.partition(":")
                info(label.strip(), value.strip())
        else:
            print(_c("  Could not retrieve TLS certificate.", "yellow"))

    # ── DNS info ──────────────────────────────────────────────────────────────

    def _dns_info(self) -> None:
        header("DNS Records")
        records = dns_info(self.host)
        self._dns_records = records
        for rtype, values in records.items():
            if values:
                for v in values:
                    info(f"  {rtype}", v)

    # ── Mermaid diagram ───────────────────────────────────────────────────────

    def _build_mermaid(self) -> str:
        """
        Generate a Mermaid flowchart representing:
          Internet → hop nodes → WAF/CDN layer → target application
        Node shapes / colours reflect hop type:
          transit  = rectangle (default)
          firewall = hexagon + red fill
          timeout  = dashed / grey
          target   = stadium (rounded) + green fill
        WAF/CDN nodes sit between the last transit hop and the target.
        """

        def safe_id(text: str) -> str:
            """Strip chars unsafe for Mermaid node IDs."""
            return re.sub(r"[^a-zA-Z0-9_]", "_", text)

        lines: List[str] = ["flowchart TD"]
        lines.append("")
        lines.append("    %% ── Styles ───────────────────────────────────")
        lines.append("    classDef transit  fill:#2d3748,stroke:#63b3ed,color:#e2e8f0")
        lines.append("    classDef firewall fill:#742a2a,stroke:#fc8181,color:#fff8f8")
        lines.append("    classDef timeout  fill:#1a202c,stroke:#718096,color:#718096,stroke-dasharray:4 4")
        lines.append("    classDef target   fill:#1c4532,stroke:#68d391,color:#c6f6d5")
        lines.append("    classDef waf      fill:#322659,stroke:#b794f4,color:#e9d8fd")
        lines.append("    classDef cdn      fill:#1a365d,stroke:#63b3ed,color:#bee3f8")
        lines.append("    classDef internet fill:#1a202c,stroke:#4a5568,color:#a0aec0")
        lines.append("")
        lines.append("    %% ── Nodes ───────────────────────────────────")

        # Internet source node
        lines.append('    INTERNET(["🌐 Internet / Client"])')
        lines.append("    class INTERNET internet")
        lines.append("")

        prev_id = "INTERNET"

        # Traceroute hops
        if self._hops:
            for hop in self._hops:
                ip_label = hop.ip or "* timeout *"
                host_label = hop.hostname or ""
                rtt_label  = f"{hop.rtt_ms:.0f}ms" if hop.rtt_ms else ""
                notes_str  = ", ".join(hop.notes)

                node_id = f"HOP{hop.ttl}"

                if hop.hop_type == "timeout":
                    label = f"TTL {hop.ttl}: * timeout *"
                    lines.append(f'    {node_id}["{label}"]')
                    lines.append(f"    class {node_id} timeout")
                elif hop.hop_type == "firewall":
                    extra = f"\\n{notes_str}" if notes_str else ""
                    label = f"TTL {hop.ttl}: {ip_label}\\n{host_label}{extra}"
                    lines.append(f'    {node_id}{{{{"🔥 {label}"}}}}')
                    lines.append(f"    class {node_id} firewall")
                elif hop.hop_type == "target":
                    # Target drawn later; skip here
                    continue
                else:
                    rtt_part = f" [{rtt_label}]" if rtt_label else ""
                    host_part = f"\\n{host_label}" if host_label else ""
                    label = f"TTL {hop.ttl}: {ip_label}{rtt_part}{host_part}"
                    lines.append(f'    {node_id}["{label}"]')
                    lines.append(f"    class {node_id} transit")

                lines.append(f"    {prev_id} --> {node_id}")
                prev_id = node_id

        # WAF / CDN layer (between path and target)
        if self._waf_detected:
            lines.append("")
            lines.append("    %% ── WAF / CDN Layer ─────────────────────────")
            for i, waf_name in enumerate(self._waf_detected):
                waf_id = f"WAF_{i}_{safe_id(waf_name)}"
                is_waf = any(
                    x in waf_name
                    for x in ["WAF", "ModSecurity", "ASM", "Imperva", "F5", "Barracuda",
                               "Sucuri", "Reblaze", "Wordfence", "Palo", "Forti"]
                )
                shape_open  = "{{" if is_waf else "["
                shape_close = "}}" if is_waf else "]"
                icon = "🛡️" if is_waf else "☁️"
                label = f"{icon} {waf_name}"
                lines.append(f'    {waf_id}{shape_open}"{label}"{shape_close}')
                lines.append(f"    class {waf_id} {'waf' if is_waf else 'cdn'}")
                lines.append(f"    {prev_id} --> {waf_id}")
                prev_id = waf_id
            lines.append("")

        # Target application node
        lines.append("    %% ── Target Application ──────────────────────")
        port_services = ", ".join(
            f"{p}/{s}" for p, s in sorted(self._open_ports.items())
        ) if self._open_ports else f"{self.scheme.upper()}:{self.port}"

        tls_tag = ""
        if self._tls_data:
            cert = self._tls_data.get("cert", {})
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "")
            tls_tag = f"\\nTLS: {cn}" if cn else f"\\nTLS: {self._tls_data.get('tls_version', '')}"

        target_label = (
            f"🎯 {self.host}\\n{self.primary_ip}\\n{port_services}{tls_tag}"
        )
        target_node_id = f"TARGET_{safe_id(self.host)}"
        lines.append(f'    {target_node_id}(["{target_label}"])')
        lines.append(f"    class {target_node_id} target")
        lines.append(f"    {prev_id} --> {target_node_id}")

        # Application-layer proxy chain (from X-Forwarded-For / Via etc.)
        # Shown as a separate subgraph connected to the target to indicate
        # these are hops reported by the application, not network-layer hops.
        if self._proxy_chain:
            lines.append("")
            lines.append("    %% ── Application-layer Proxy Chain ───────────")
            lines.append("    subgraph APP_CHAIN [App-layer Proxy Chain]")
            lines.append("    direction LR")
            chain_ids = []
            for i, entry in enumerate(self._proxy_chain):
                nid = f"PROXY_{i}_{safe_id(entry.get('ip') or entry.get('hostname', str(i)))}"
                ip_str   = entry.get("ip") or "?"
                host_str = entry.get("hostname", "")
                src_str  = entry.get("source", "")
                label = f"{ip_str}"
                if host_str and host_str != ip_str:
                    label += f"\\n{host_str}"
                label += f"\\n[{src_str}]"
                lines.append(f'        {nid}["{label}"]')
                lines.append(f"        class {nid} cdn")
                chain_ids.append(nid)
            lines.append("    end")
            # Connect chain to target
            if chain_ids:
                lines.append(f"    {target_node_id} -.->|app sees| {chain_ids[0]}")
                for j in range(len(chain_ids) - 1):
                    lines.append(f"    {chain_ids[j]} --> {chain_ids[j+1]}")

        # Subgraph: DNS / load balancing
        a_records = self._dns_records.get("A", [])
        if len(a_records) > 1:
            lines.append("")
            lines.append("    %% ── DNS / Load Balancing ─────────────────────")
            lines.append("    subgraph DNS_LB [DNS — Multiple A Records]")
            for ip in a_records:
                nid = f"DNS_{safe_id(ip)}"
                lines.append(f'        {nid}["{ip}"]')
            lines.append("    end")

        # Multi-port path comparison subgraph (--penetrate mode)
        if self._port_results:
            lines.append("")
            lines.append("    %% ── Multi-port Path Comparison ──────────────")
            lines.append("    subgraph MULTIPORT [Multi-port Traceroute Comparison]")
            lines.append("    direction LR")
            for port, hops in self._port_results.items():
                if not hops:
                    continue
                prev_mp = None
                for hop in hops:
                    nid = f"MP_{port}_TTL{hop.ttl}"
                    ip_str = hop.ip or "*"
                    rtt_str = f" {hop.rtt_ms:.0f}ms" if hop.rtt_ms else ""
                    label = f":{port} TTL{hop.ttl}\\n{ip_str}{rtt_str}"
                    if hop.hop_type == "timeout":
                        lines.append(f'        {nid}["{label}"]')
                        lines.append(f"        class {nid} timeout")
                    elif hop.hop_type == "firewall":
                        lines.append(f'        {nid}{{{{"{label}"}}}}')
                        lines.append(f"        class {nid} firewall")
                    elif hop.hop_type == "target":
                        lines.append(f'        {nid}(["{label}"])')
                        lines.append(f"        class {nid} target")
                    else:
                        lines.append(f'        {nid}["{label}"]')
                        lines.append(f"        class {nid} transit")
                    if prev_mp:
                        lines.append(f"        {prev_mp} --> {nid}")
                    prev_mp = nid
            lines.append("    end")

        return "\n".join(lines)

    def _output_mermaid(self) -> None:
        diagram = self._build_mermaid()

        mermaid_file = getattr(self.args, "mermaid_file", None)
        show_inline  = getattr(self.args, "mermaid", False)

        if show_inline:
            header("Mermaid Diagram")
            print()
            print("```mermaid")
            print(diagram)
            print("```")
            print()
            print(_c(
                "  Paste the block above into https://mermaid.live to visualise.",
                "cyan",
            ))

        if mermaid_file:
            with open(mermaid_file, "w", encoding="utf-8") as f:
                f.write(diagram + "\n")
            print(_c(f"\n  Mermaid diagram saved to {mermaid_file}", "cyan"))


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Map network path from URL to application, detecting WAFs and firewalls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python networkmapper.py https://example.com
  python networkmapper.py https://example.com --max-hops 20 --port 80
  python networkmapper.py https://example.com --penetrate
  python networkmapper.py https://example.com --penetrate -o results.json --mermaid-file map.mmd
  python networkmapper.py https://example.com --no-traceroute --port-scan
  python networkmapper.py https://example.com --mermaid
  python networkmapper.py https://example.com --mermaid-file diagram.mmd
  python networkmapper.py https://example.com -o results.json --mermaid-file map.mmd
  python networkmapper.py 10.0.0.1 --port 8080 --no-tls

Notes:
  TCP SYN traceroute and --penetrate require Administrator (Windows) or root (Linux/macOS).
  Install scapy for best results:  pip install scapy
  Full install:  pip install scapy requests dnspython colorama
  Mermaid diagrams can be pasted into https://mermaid.live to render.
  --penetrate runs multi-port + UDP traceroutes, port allowlist discovery, and
  firewall fingerprinting to find paths that pass through the firewall.
""",
    )
    p.add_argument("url", help="Target URL or host (e.g. https://example.com or 10.0.0.1)")
    p.add_argument(
        "--port", "-p", type=int, default=None,
        help="Override destination port (default: 443 for https, 80 for http)",
    )
    p.add_argument("--max-hops", "-m", type=int, default=30, help="Max TTL hops (default: 30)")
    p.add_argument("--timeout", "-t", type=float, default=2.0, help="Per-probe timeout seconds (default: 2.0)")
    p.add_argument("--probes", type=int, default=3, help="Probes per hop (default: 3)")
    p.add_argument("--no-traceroute", action="store_true", help="Skip traceroute")
    p.add_argument("--no-http",       action="store_true", help="Skip HTTP/WAF analysis")
    p.add_argument("--no-tls",        action="store_true", help="Skip TLS certificate check")
    p.add_argument("--port-scan",     action="store_true", help="Scan common ports at target")
    p.add_argument(
        "--penetrate", action="store_true",
        help=(
            "Firewall penetration mode: probe allowed ports, run multi-port TCP SYN "
            "traceroute and UDP traceroute on all of them, compare paths to find where "
            "filtering occurs, and fingerprint firewall devices."
        ),
    )
    p.add_argument(
        "--output", "-o", metavar="FILE",
        help="Save JSON summary to file",
    )
    p.add_argument(
        "--mermaid", action="store_true",
        help="Print Mermaid flowchart diagram to stdout after scanning",
    )
    p.add_argument(
        "--mermaid-file", metavar="FILE",
        help="Save Mermaid diagram to a .mmd or .md file",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Port override
    if args.port:
        _, host, default_port, path = parse_url(args.url)
        # Patch: rebuild URL-port from flag
        scheme = "https" if args.port == 443 else "http"
        args._port_override = args.port

    mapper = NetworkMapper(args)
    # Apply port override after parsing
    if args.port:
        mapper.port = args.port

    mapper.run()

    # JSON output
    if args.output:
        def serialise_hops(hops):
            return [
                {
                    "ttl":      h.ttl,
                    "ip":       h.ip,
                    "hostname": h.hostname,
                    "rtt_ms":   round(h.rtt_ms, 2) if h.rtt_ms else None,
                    "type":     h.hop_type,
                    "notes":    h.notes,
                }
                for h in hops
            ]

        data = {
            "target":         args.url,
            "host":           mapper.host,
            "primary_ip":     mapper.primary_ip,
            "all_ips":        mapper.target_ips,
            "scheme":         mapper.scheme,
            "port":           mapper.port,
            "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
            "http_status":    mapper._http_status,
            "waf_detected":   mapper._waf_detected,
            "proxy_chain":    mapper._proxy_chain,
            "open_ports":     {str(p): s for p, s in mapper._open_ports.items()},
            "dns_records":    mapper._dns_records,
            "hops":           serialise_hops(mapper._hops),
            "udp_hops":       serialise_hops(mapper._udp_hops),
            "allowed_ports":  mapper._allowed_ports,
            "filtered_ports": mapper._filtered_ports,
            "multi_port_hops": {
                str(port): serialise_hops(hops)
                for port, hops in mapper._port_results.items()
            },
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(_c(f"\n  Results saved to {args.output}", "cyan"))


if __name__ == "__main__":
    main()
