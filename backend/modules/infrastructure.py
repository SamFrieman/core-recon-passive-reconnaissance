"""
CoreRecon Infrastructure Intelligence Module
Gathers IP, geolocation, ASN, reverse DNS, CDN/hosting provider classification.
All sources are passive and publicly accessible.
"""
import socket
import re
from typing import Dict, Any

import requests

from backend.core.logger import get_logger
from backend.core.errors import SoftFailError

log = get_logger("corerecon.infrastructure")

REQUEST_TIMEOUT = 8

# ---------------------------------------------------------------------------
# CDN / Cloud Provider fingerprinting
# Based on ASN numbers and reverse DNS patterns — fully passive.
# ---------------------------------------------------------------------------

CDN_ASN_MAP = {
    "13335": "Cloudflare",
    "209242": "Cloudflare",
    "54113": "Fastly",
    "16625": "Akamai",
    "20940": "Akamai",
    "16509": "Amazon CloudFront (AWS)",
    "14618": "Amazon (AWS)",
    "15169": "Google Cloud / GCP",
    "396982": "Google Cloud / GCP",
    "8075": "Microsoft Azure",
    "32934": "Facebook/Meta",
    "60068": "CDN77",
    "22822": "Limelight Networks",
    "23286": "HedgeStone / CDN",
    "36183": "Incapsula / Imperva",
    "19551": "Incapsula / Imperva",
    "55967": "BelugaCDN",
    "394536": "StackPath CDN",
}

CDN_RDNS_PATTERNS = [
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"fastly", re.I), "Fastly"),
    (re.compile(r"akamai", re.I), "Akamai"),
    (re.compile(r"cloudfront\.net", re.I), "Amazon CloudFront (AWS)"),
    (re.compile(r"amazonaws\.com", re.I), "Amazon (AWS)"),
    (re.compile(r"googleusercontent|googleplex", re.I), "Google Cloud / GCP"),
    (re.compile(r"msedge\.net|azureedge|azure", re.I), "Microsoft Azure"),
    (re.compile(r"incapdns|imperva", re.I), "Imperva / Incapsula"),
    (re.compile(r"stackpath|highwinds", re.I), "StackPath CDN"),
]

CLOUD_PROVIDER_ASN = {
    "Amazon (AWS)", "Amazon CloudFront (AWS)",
    "Google Cloud / GCP", "Microsoft Azure",
}


def _detect_cdn(asn_number: str, reverse_dns: str) -> Dict[str, Any]:
    """
    Attempt to classify the hosting provider from ASN and rDNS.
    Returns structured CDN/hosting info.
    """
    asn_clean = re.sub(r"[^0-9]", "", asn_number or "")

    # Check ASN map first
    if asn_clean in CDN_ASN_MAP:
        provider = CDN_ASN_MAP[asn_clean]
        return {
            "detected": True,
            "provider": provider,
            "is_cloud": provider in CLOUD_PROVIDER_ASN,
            "detection_method": "asn",
        }

    # Check reverse DNS patterns
    if reverse_dns and reverse_dns != "No PTR record":
        for pattern, provider in CDN_RDNS_PATTERNS:
            if pattern.search(reverse_dns):
                return {
                    "detected": True,
                    "provider": provider,
                    "is_cloud": provider in CLOUD_PROVIDER_ASN,
                    "detection_method": "rdns",
                }

    return {"detected": False, "provider": None, "is_cloud": False, "detection_method": None}


def _resolve_all_ips(domain: str) -> list:
    """Resolve all A records (multi-IP detection)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except Exception:
        try:
            return [socket.gethostbyname(domain)]
        except Exception:
            return []


def _resolve_ipv6(domain: str) -> list:
    """Resolve AAAA records for IPv6 presence detection."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "AAAA")
        return [str(r) for r in answers]
    except Exception:
        return []


def get_infrastructure_info(domain: str) -> Dict[str, Any]:
    """
    Primary infrastructure intelligence gathering.
    Returns all current v1 fields plus:
    - all_ips (multi-A record)
    - ipv6_addresses
    - cdn (CDN/cloud provider detection)
    """
    # Primary IP resolution
    all_ips = _resolve_all_ips(domain)
    ipv6_addresses = _resolve_ipv6(domain)

    if not all_ips:
        log.info("Infrastructure: DNS resolution failed", extra={"domain": domain})
        return {
            "ip": "Resolution Failed",
            "all_ips": [],
            "ipv6_addresses": ipv6_addresses,
            "status": "OFFLINE",
            "error": "DNS resolution failed — domain may not exist or be unreachable",
            "cdn": {"detected": False, "provider": None, "is_cloud": False},
        }

    ip = all_ips[0]

    # Geolocation and ISP via ip-api.com (free, no key required)
    geo_data = {}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,city,regionName,isp,as,org,lat,lon",
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            geo_data = resp.json()
            if geo_data.get("status") != "success":
                log.warning("ip-api returned non-success", extra={"domain": domain, "msg": geo_data.get("message")})
                geo_data = {}
    except requests.RequestException as e:
        log.warning("ip-api.com request failed", extra={"domain": domain, "error": str(e)})

    # ASN lookup via hackertarget (free, no key)
    asn_info = {}
    try:
        asn_resp = requests.get(
            f"https://api.hackertarget.com/aslookup/?q={ip}",
            timeout=REQUEST_TIMEOUT,
        )
        if asn_resp.status_code == 200 and "error" not in asn_resp.text.lower():
            parts = asn_resp.text.strip().split(",")
            if len(parts) >= 2:
                asn_info = {
                    "number": parts[0].strip().replace('"', ''),
                    "organization": parts[1].strip().replace('"', '') if len(parts) > 1 else "Unknown",
                }
    except requests.RequestException as e:
        log.warning("hackertarget ASN lookup failed", extra={"domain": domain, "error": str(e)})

    # Fallback ASN from ip-api if hackertarget failed
    if not asn_info and geo_data.get("as"):
        as_string = geo_data["as"]  # e.g., "AS15169 Google LLC"
        parts = as_string.split(" ", 1)
        asn_info = {
            "number": parts[0] if parts else "Unknown",
            "organization": parts[1] if len(parts) > 1 else geo_data.get("org", "Unknown"),
        }

    # Reverse DNS
    reverse_dns = "No PTR record"
    try:
        reverse_dns = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        pass

    # CDN / hosting provider detection
    asn_number = asn_info.get("number", "")
    cdn_info = _detect_cdn(asn_number, reverse_dns)

    location = {
        "city": geo_data.get("city", "Unknown"),
        "region": geo_data.get("regionName", "Unknown"),
        "country": geo_data.get("country", "Unknown"),
        "coordinates": f"{geo_data.get('lat', 0)}, {geo_data.get('lon', 0)}",
    } if geo_data else {
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "coordinates": "0, 0",
    }

    result = {
        # --- v1 fields preserved exactly ---
        "ip": ip,
        "status": "ONLINE",
        "reverse_dns": reverse_dns,
        "asn": asn_info,
        "provider": geo_data.get("isp", "Unknown"),
        "organization": geo_data.get("org", "Unknown"),
        "location": location,
        # --- v2 additions ---
        "all_ips": all_ips,
        "ipv6_addresses": ipv6_addresses,
        "multi_ip": len(all_ips) > 1,
        "cdn": cdn_info,
    }

    log.info(
        "Infrastructure intel gathered",
        extra={"domain": domain, "ip": ip, "cdn_detected": cdn_info["detected"]},
    )
    return result
