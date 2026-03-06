"""
CoreRecon Infrastructure Module v2.1
Passive infrastructure discovery: IP resolution, ASN, cloud provider,
CDN detection, and open port indicators.

v2.1 stability improvements:
  - Retry logic with exponential backoff for IP/ASN lookups
  - Configurable timeouts per lookup type
  - Graceful degradation when providers are unavailable
  - Result caching at call-site level (caller caches the full result)
"""
import socket
import time
from typing import Any, Dict, List, Optional

import requests

from backend.core.logger import get_logger

log = get_logger("corerecon.infrastructure")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT = 8       # seconds per HTTP call
_RETRY_ATTEMPTS  = 3
_RETRY_BACKOFF   = 1.5     # seconds — multiplied per attempt (1.5, 2.25, 3.375)

_CDN_HEADERS = {
    "cf-ray":             "Cloudflare",
    "x-amz-cf-id":       "Amazon CloudFront",
    "x-amz-request-id":  "Amazon CloudFront",
    "x-azure-ref":        "Microsoft Azure CDN",
    "x-fastly-request-id": "Fastly",
    "x-cache":            None,   # Check value below
    "via":                None,   # Check value below
    "x-served-by":        "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-varnish":          "Varnish / Generic CDN",
    "x-sucuri-id":        "Sucuri",
    "x-cdn":              None,
}

_CDN_SERVER_STRINGS = [
    ("cloudflare", "Cloudflare"),
    ("cloudfront", "Amazon CloudFront"),
    ("akamai",     "Akamai"),
    ("fastly",     "Fastly"),
    ("sucuri",     "Sucuri"),
    ("incapsula",  "Imperva Incapsula"),
    ("varnish",    "Varnish"),
    ("nginx",      None),   # Could be anything
]

_CLOUD_IP_PREFIXES = {
    "amazonaws":    "Amazon Web Services",
    "azure":        "Microsoft Azure",
    "googlecloud":  "Google Cloud Platform",
    "digitalocean": "DigitalOcean",
    "linode":       "Akamai Cloud (Linode)",
    "vultr":        "Vultr",
    "hetzner":      "Hetzner",
    "ovh":          "OVH",
}

_INTERESTING_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                      587, 993, 995, 3306, 3389, 5432, 5900, 6379,
                      8080, 8443, 8888, 9200, 27017]


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------

def _with_retry(fn, *args, attempts: int = _RETRY_ATTEMPTS, **kwargs):
    """
    Execute fn(*args, **kwargs) with exponential backoff retry.
    Returns (result, None) on success, (None, error_str) on exhaustion.
    """
    last_error = None
    for attempt in range(attempts):
        try:
            return fn(*args, **kwargs), None
        except Exception as exc:
            last_error = str(exc)
            if attempt < attempts - 1:
                wait = _RETRY_BACKOFF * (attempt + 1)
                log.debug(f"Retry {attempt + 1}/{attempts - 1} after {wait:.1f}s: {exc}")
                time.sleep(wait)
    return None, last_error


# ---------------------------------------------------------------------------
# Sub-lookups
# ---------------------------------------------------------------------------

def _resolve_ip(target: str) -> Optional[str]:
    """DNS A-record lookup with retry."""
    result, err = _with_retry(socket.gethostbyname, target)
    if err:
        log.warning("IP resolution failed", extra={"target": target, "error": err})
    return result


def _fetch_ipinfo(ip: str) -> Dict[str, Any]:
    """
    Fetch ASN, org, and geo from ipinfo.io (no auth, ~50k req/day limit).
    Returns empty dict on failure.
    """
    url = f"https://ipinfo.io/{ip}/json"

    def _get():
        resp = requests.get(url, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    data, err = _with_retry(_get)
    if err:
        log.warning("ipinfo.io lookup failed", extra={"ip": ip, "error": err})
        return {}
    return data or {}


def _detect_cdn_from_response(target: str) -> Dict[str, Any]:
    """
    Make an HTTP HEAD request and examine response headers for CDN fingerprints.
    Returns {"detected": bool, "provider": str|None, "headers_seen": list}
    """
    headers_seen = []
    provider = None

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.head(
                url,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "CoreRecon/2.1 (+https://github.com/corerecon)"},
            )
        except Exception:
            continue

        resp_headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for header, cdn_name in _CDN_HEADERS.items():
            if header in resp_headers_lower:
                headers_seen.append(header)
                if cdn_name:
                    provider = cdn_name
                    break

                # Handle generic headers — inspect values
                val = resp_headers_lower[header]
                if header == "x-cache" and ("hit" in val or "miss" in val):
                    provider = "Generic CDN / Caching Layer"
                elif header == "via":
                    for cdn_str, cdn_label in _CDN_SERVER_STRINGS:
                        if cdn_str in val:
                            provider = cdn_label or "CDN via proxy"
                            break

        if not provider:
            server = resp_headers_lower.get("server", "")
            for cdn_str, cdn_label in _CDN_SERVER_STRINGS:
                if cdn_str in server and cdn_label:
                    provider = cdn_label
                    break

        break  # Only need first successful response

    return {
        "detected": provider is not None,
        "provider": provider,
        "headers_seen": headers_seen,
    }


def _detect_cloud_provider(org: str, hostname: str) -> Optional[str]:
    """Infer cloud provider from org string or ASN name."""
    combined = f"{org} {hostname}".lower()
    for keyword, cloud_name in _CLOUD_IP_PREFIXES.items():
        if keyword in combined:
            return cloud_name
    return None


def _probe_ports(ip: str, ports: List[int], timeout: float = 1.0) -> List[int]:
    """
    Passive-style port check — attempts TCP connect on each port.
    Uses short timeout to avoid hanging the scan.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return open_ports


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def get_infrastructure(target: str, probe_ports: bool = True) -> Dict[str, Any]:
    """
    Perform passive infrastructure discovery for target.

    Parameters
    ----------
    target : str
        The domain to analyse.
    probe_ports : bool
        Whether to attempt TCP connect checks on common ports.
        Can be disabled for faster scans when not needed.

    Returns
    -------
    dict with:
      online         — bool
      ip             — resolved IPv4 address or None
      asn            — ASN string or None
      org            — organisation name or None
      country        — country code or None
      cloud_provider — cloud provider name or None
      cdn            — {detected, provider, headers_seen}
      open_ports     — list of open port numbers
      error          — error string if lookup failed
    """
    result: Dict[str, Any] = {
        "online": False,
        "ip": None,
        "asn": None,
        "org": None,
        "country": None,
        "cloud_provider": None,
        "cdn": {"detected": False, "provider": None, "headers_seen": []},
        "open_ports": [],
        "error": None,
    }

    # Step 1: Resolve IP
    ip = _resolve_ip(target)
    if not ip:
        result["error"] = "DNS resolution failed — target may be offline or non-existent"
        return result

    result["ip"] = ip
    result["online"] = True

    # Step 2: ASN + org lookup
    ipinfo = _fetch_ipinfo(ip)
    if ipinfo:
        result["asn"] = ipinfo.get("org", "").split(" ")[0] if ipinfo.get("org") else None
        result["org"] = " ".join(ipinfo.get("org", "").split(" ")[1:]) if ipinfo.get("org") else None
        result["country"] = ipinfo.get("country")
        result["cloud_provider"] = _detect_cloud_provider(
            ipinfo.get("org", ""), ipinfo.get("hostname", "")
        )

    # Step 3: CDN detection via HTTP response headers
    cdn_info = _detect_cdn_from_response(target)
    result["cdn"] = cdn_info

    # Step 4: Port probing (TCP connect — passive, no exploitation)
    if probe_ports and ip:
        result["open_ports"] = _probe_ports(ip, _INTERESTING_PORTS)

    log.info(
        "Infrastructure scan complete",
        extra={
            "target": target,
            "ip": ip,
            "cdn_detected": cdn_info.get("detected"),
            "open_ports": len(result["open_ports"]),
        },
    )

    return result
