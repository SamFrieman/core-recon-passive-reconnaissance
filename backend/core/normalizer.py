"""
CoreRecon Input Normalizer
Properly extracts scannable targets from any URL, domain, or IP input.
Fixes the v1.0 bug where paths from URLs survived normalization.
"""
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

from backend.core.errors import HardFailError

# Regex patterns for IPv4 and IPv6 detection
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^\[?([0-9a-fA-F:]+)\]?$")

# Characters safe in domain names
_SAFE_CHARS_RE = re.compile(r"[^a-zA-Z0-9.\-_]")


@dataclass
class NormalizedTarget:
    target: str            # clean domain or IP for all network operations
    registered_domain: str # base domain for subdomain enumeration (e.g., example.co.uk)
    input_type: str        # 'domain', 'ipv4', 'ipv6', 'url'
    original_input: str    # unchanged for response transparency


def normalize_target(raw_input: str) -> NormalizedTarget:
    """
    Convert any user-supplied input into a NormalizedTarget.

    Handles:
    - Plain domains: example.com → example.com
    - URLs with paths: https://example.com/path?q=1 → example.com
    - Subdomains: sub.example.co.uk → sub.example.co.uk
    - IPv4: 1.2.3.4 → 1.2.3.4
    - IPv6: [::1] or 2001:db8::1 → 2001:db8::1
    - Ports: example.com:8080 → example.com
    - www prefix: preserved (www.example.com stays as-is for SSL/header checks)
    """
    if not raw_input or not raw_input.strip():
        raise HardFailError("Input cannot be empty", code="EMPTY_INPUT")

    original = raw_input.strip()

    # Enforce max length
    if len(original) > 255:
        raise HardFailError("Input exceeds maximum length of 255 characters", code="INPUT_TOO_LONG")

    # Strip common dangerous characters (XSS, injection prevention)
    if re.search(r"[<>\"'`;]", original):
        raise HardFailError("Input contains invalid characters", code="INVALID_CHARS")

    working = original.lower()

    # Strip protocol prefix for further parsing
    if "://" in working:
        parsed = urlparse(working if "://" in working else "https://" + working)
        working = parsed.hostname or working
    else:
        # Handle bare paths like example.com/path
        working = working.split("/")[0]

    # Strip port numbers
    if ":" in working and not working.startswith("["):
        # Could be IPv6 or host:port
        parts = working.rsplit(":", 1)
        if parts[-1].isdigit():
            working = parts[0]

    # Strip surrounding brackets from IPv6
    working = working.strip("[]")

    if not working:
        raise HardFailError("Could not extract a valid target from input", code="PARSE_FAILED")

    # Detect IPv4
    if _IPV4_RE.match(working):
        return NormalizedTarget(
            target=working,
            registered_domain=working,
            input_type="ipv4",
            original_input=original,
        )

    # Detect IPv6
    if _IPV6_RE.match(working) and ":" in working:
        return NormalizedTarget(
            target=working,
            registered_domain=working,
            input_type="ipv6",
            original_input=original,
        )

    # Domain — use tldextract to get the registered domain
    if _TLDEXTRACT_AVAILABLE:
        extracted = tldextract.extract(working)
        if extracted.domain and extracted.suffix:
            registered = f"{extracted.domain}.{extracted.suffix}"
            # Use the full subdomain+domain if a subdomain was given
            if extracted.subdomain:
                full_domain = f"{extracted.subdomain}.{registered}"
            else:
                full_domain = registered
        else:
            # Fallback: treat full string as domain
            full_domain = working
            registered = working
    else:
        # Fallback without tldextract
        full_domain = working
        parts = working.split(".")
        registered = ".".join(parts[-2:]) if len(parts) >= 2 else working

    # Final sanity check — domain characters only
    if _SAFE_CHARS_RE.search(full_domain):
        raise HardFailError(
            f"Domain contains invalid characters after normalization: {full_domain}",
            code="INVALID_DOMAIN",
        )

    return NormalizedTarget(
        target=full_domain,
        registered_domain=registered,
        input_type="domain",
        original_input=original,
    )


def sanitize_input(user_input: str) -> str:
    """
    Legacy-compatible sanitizer. Returns the cleaned target string.
    Used by the report endpoint which operates on already-stored domain strings.
    """
    if not user_input:
        raise ValueError("Input cannot be empty")

    cleaned = re.sub(r"[<>\"\';`]", "", user_input.strip())
    cleaned = re.sub(r"\s+", "", cleaned)

    if len(cleaned) > 255:
        raise ValueError("Input too long (max 255 characters)")

    return cleaned
