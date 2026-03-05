"""
CoreRecon v2.0 — Input Normalization
Accepts domains, URLs, IPs. Returns a NormalizedTarget dataclass.
"""
import re
import ipaddress
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import tldextract

from backend.core.errors import HardFailError


@dataclass
class NormalizedTarget:
    target: str              # Clean hostname or IP used for all module calls
    registered_domain: str   # eTLD+1 (e.g. "example.com") — used for WHOIS/subdomains
    original_input: str      # Raw string as the user typed it
    input_type: str          # "domain" | "ipv4" | "ipv6" | "url"


def sanitize_input(raw: str) -> str:
    """
    Strip XSS / injection patterns. Returns cleaned string or raises ValueError.
    Used by the report endpoint which doesn't go through normalize_target.
    """
    if not raw or not raw.strip():
        raise ValueError("Input cannot be empty")

    cleaned = raw.strip()

    # XSS patterns
    xss = [r"<[^>]*>", r"javascript:", r"on\w+\s*=", r"<iframe", r"<object", r"<embed"]
    for pat in xss:
        if re.search(pat, cleaned, re.IGNORECASE):
            raise ValueError("Invalid characters detected in input")

    # SQL injection patterns
    sql = [
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b",
        r"(--|;|/\*|\*/)",
        r"('|\"|`)",
    ]
    for pat in sql:
        if re.search(pat, cleaned, re.IGNORECASE):
            raise ValueError("Invalid input format")

    # Strip to safe charset
    cleaned = re.sub(r"[^\w.\-:/\[\]]", "", cleaned)

    if len(cleaned) > 255:
        raise ValueError("Input too long (max 255 characters)")

    return cleaned


def normalize_target(raw: str) -> NormalizedTarget:
    """
    Parse and normalize any user-supplied target string into a NormalizedTarget.
    Raises HardFailError on inputs that cannot be resolved to a valid target.
    """
    original = raw.strip()

    if not original:
        raise HardFailError("Target cannot be empty")

    # --- Sanitize first ---
    try:
        cleaned = sanitize_input(original)
    except ValueError as e:
        raise HardFailError(str(e))

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
    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        host = parsed.hostname or ""
        if not host:
            raise HardFailError(f"Could not extract hostname from URL: {cleaned}")
        cleaned = host
        input_type = "url"
    else:
        input_type = "domain"

    # --- Strip www. prefix for cleaner target (modules add it back if needed) ---
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]

    # --- Use tldextract to validate and extract registered domain ---
    extracted = tldextract.extract(cleaned)

    # registered_domain = domain label + TLD suffix, e.g. "example.com"
    # extracted.domain alone would be just "example" — that was the bug.
    if extracted.registered_domain:
        # Use the full registered domain (eTLD+1) as the target
        target = extracted.registered_domain

        # If there's a subdomain component, keep it for the target
        # e.g. "sub.example.com" → target="sub.example.com", registered_domain="example.com"
        if extracted.subdomain:
            target = f"{extracted.subdomain}.{extracted.registered_domain}"
    elif extracted.domain:
        # Fallback: single-label hostname (intranet, localhost, etc.)
        # Warn but allow — some environments use these
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
