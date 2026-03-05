"""
CoreRecon WHOIS Intelligence Module
Preserves v1 response structure exactly.
"""
import concurrent.futures
from datetime import datetime
from typing import Dict, Any

import whois

from backend.core.logger import get_logger
log = get_logger("corerecon.whois")


def _safe_date(val) -> str:
    """Normalize WHOIS date fields — may be list, datetime, or string."""
    if val is None:
        return "Unknown"
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    return str(val)


def _safe_str(val) -> str:
    """Normalize string fields that may be lists or None."""
    if val is None:
        return "Private/Redacted"
    if isinstance(val, list):
        return ", ".join(str(v) for v in val if v)
    return str(val)


def get_whois_data(domain: str) -> Dict[str, Any]:
    """
    WHOIS registration data lookup.
    Wrapped in a thread with a 15-second timeout to prevent
    hanging on unresponsive WHOIS servers.
    """
    _TIMEOUT = 15

    def _fetch():
        return whois.whois(domain)

    # Run whois in a thread so we can enforce a timeout
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_fetch)
            try:
                w = future.result(timeout=_TIMEOUT)
            except concurrent.futures.TimeoutError:
                log.warning("WHOIS timed out", extra={"domain": domain})
                return {
                    "registrar": "Timeout",
                    "creation_date": "Unknown",
                    "expiration_date": "Unknown",
                    "updated_date": "Unknown",
                    "status": "Unknown",
                    "name_servers": [],
                    "organization": "Timeout",
                    "registrant_country": "Unknown",
                    "dnssec": "Unknown",
                    "note": "WHOIS lookup timed out after 15s — WHOIS server unresponsive or rate limiting.",
                }
    except Exception as e:
        log.warning("WHOIS lookup failed", extra={"domain": domain, "error": str(e)})
        return {
            "registrar": "Private/Redacted",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "updated_date": "Unknown",
            "status": "Unknown",
            "name_servers": [],
            "organization": "Private/Redacted",
            "registrant_country": "Unknown",
            "dnssec": "Unknown",
            "note": f"WHOIS lookup failed — possible privacy protection or unsupported TLD. Error: {str(e)[:100]}",
        }

    # Normal parsing path (same as before)
    try:
        if not w or not w.domain_name:
            return {
                "registrar": "Private/Redacted",
                "creation_date": "Unknown",
                "expiration_date": "Unknown",
                "updated_date": "Unknown",
                "status": "Unknown",
                "name_servers": [],
                "organization": "Private/Redacted",
                "registrant_country": "Unknown",
                "dnssec": "Unknown",
                "note": "WHOIS data unavailable or privacy-protected",
            }

        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = sorted(set(ns.lower() for ns in name_servers if ns))
        elif name_servers:
            name_servers = [name_servers.lower()]
        else:
            name_servers = []

        status = w.status
        if isinstance(status, list):
            status = ", ".join(status)
        elif not status:
            status = "Unknown"

        result = {
            "registrar": _safe_str(w.registrar),
            "creation_date": _safe_date(w.creation_date),
            "expiration_date": _safe_date(w.expiration_date),
            "updated_date": _safe_date(w.updated_date),
            "status": status,
            "name_servers": name_servers,
            "organization": _safe_str(w.org),
            "registrant_country": _safe_str(w.country),
            "dnssec": _safe_str(w.dnssec),
        }

        log.info("WHOIS data retrieved", extra={"domain": domain, "registrar": result["registrar"]})
        return result

    except Exception as e:
        log.warning("WHOIS parse failed", extra={"domain": domain, "error": str(e)})
        return {
            "registrar": "Private/Redacted",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "updated_date": "Unknown",
            "status": "Unknown",
            "name_servers": [],
            "organization": "Private/Redacted",
            "registrant_country": "Unknown",
            "dnssec": "Unknown",
            "note": f"WHOIS parse failed: {str(e)[:100]}",
        }
