"""
CoreRecon v2.0 — Input Normalization
Accepts domains, URLs, IPs. Returns a NormalizedTarget dataclass.

v2.2.1: sanitize_input() now delegates to backend.core.sanitizer
        for full multi-layer validation before normalization proceeds.
"""
import re
import ipaddress
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import tldextract

from backend.core.errors import HardFailError
from backend.core.sanitizer import sanitize_target, SanitizationError


@dataclass
class NormalizedTarget:
    target: str              # Clean hostname or IP used for all module calls
    registered_domain: str   # eTLD+1 (e.g. "example.com") — used for WHOIS/subdomains
    original_input: str      # Raw string as the user typed it
    input_type: str          # "domain" | "ipv4" | "ipv6" | "url"


def sanitize_input(raw: str) -> str:
    """
    Public wrapper used by the report endpoint and any other caller
    that needs sanitization without full normalization.

    Delegates to the central sanitizer module.
    Raises ValueError (for backwards compatibility) on failure.
    """
    try:
        return sanitize_target(raw)
    except SanitizationError as e:
        raise ValueError(e.reason)


def normalize_target(raw: str) -> NormalizedTarget:
    """
    Parse and normalize any user-supplied target string into a NormalizedTarget.
    Runs full sanitization before any parsing.
    Raises HardFailError on inputs that cannot be resolved to a valid target.
    """
    original = raw.strip() if isinstance(raw, str) else ""

    if not original:
        raise HardFailError("Target cannot be empty")

    # --- Full multi-layer sanitization first ---
    try:
        cleaned = sanitize_target(original)
    except SanitizationError as e:
        raise HardFailError(e.reason)

    # --- Check for IPv4 ---
    try:
        ipaddress.IPv4Address(cleaned)
        return NormalizedTarget(
            target=cleaned,
            registered_domain=cleaned,
            original_input=original,
            input_type="ipv4",
        )
    except ValueError:
        pass

    # --- Check for IPv6 (strip brackets if present) ---
    ipv6_candidate = cleaned.strip("[]")
    try:
        ipaddress.IPv6Address(ipv6_candidate)
        return NormalizedTarget(
            target=ipv6_candidate,
            registered_domain=ipv6_candidate,
            original_input=original,
            input_type="ipv6",
        )
    except ValueError:
        pass

    # --- URL: extract the hostname ---
    if cleaned.lower().startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        host = parsed.hostname or ""
        if not host:
            raise HardFailError(f"Could not extract hostname from URL: {cleaned}")
        cleaned = host
        input_type = "url"
    else:
        input_type = "domain"

    # --- Strip www. prefix ---
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]

    # --- Use tldextract to validate and extract registered domain ---
    extracted = tldextract.extract(cleaned)

    if extracted.registered_domain:
        target = extracted.registered_domain
        if extracted.subdomain:
            target = f"{extracted.subdomain}.{extracted.registered_domain}"
    elif extracted.domain:
        # Single-label hostname (intranet, localhost, etc.) — allow with warning
        target = extracted.domain
    else:
        raise HardFailError(f"Cannot parse '{cleaned}' as a valid domain or IP address")

    if not target:
        raise HardFailError(f"Empty target after normalization of '{original}'")

    return NormalizedTarget(
        target=target,
        registered_domain=extracted.registered_domain or target,
        original_input=original,
        input_type=input_type,
    )
