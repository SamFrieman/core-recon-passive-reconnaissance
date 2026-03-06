"""
CoreRecon Subdomain Discovery Module v2.1
Passive subdomain enumeration using certificate transparency logs,
DNS brute-force via HackerTarget, and web archive records.

v2.1 stability improvements:
  - Retry logic with backoff for all external API calls
  - Rate-limit detection (HTTP 429) with automatic pause-and-retry
  - Deduplication across all sources
  - Risk classification of discovered subdomains
"""
import time
from typing import Any, Dict, List, Set

import requests

from backend.core.logger import get_logger

log = get_logger("corerecon.subdomains")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT   = 12    # seconds
_RETRY_ATTEMPTS    = 3
_RETRY_BACKOFF     = 2.0   # seconds
_RATE_LIMIT_PAUSE  = 8.0   # seconds to wait on HTTP 429

_HIGH_RISK_KEYWORDS = {
    "admin", "administrator", "manage", "management", "portal", "control",
    "internal", "intranet", "corp", "corporate", "private", "secure",
    "vpn", "remote", "bastion", "jump", "gateway",
    "dev", "develop", "development", "staging", "stage", "stg",
    "test", "testing", "qa", "uat", "sit", "preprod", "sandbox",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "jenkins", "jira", "confluence", "gitlab", "github", "ci", "cd",
    "build", "deploy", "teamcity", "bamboo", "sonar",
    "backup", "bak", "archive", "ftp", "sftp", "files",
    "monitor", "grafana", "kibana", "prometheus", "splunk",
    "api", "graphql", "rest",
    "auth", "login", "sso", "oauth", "identity",
}


# ---------------------------------------------------------------------------
# Retry + rate-limit helper
# ---------------------------------------------------------------------------

def _fetch_with_retry(url: str, params: Dict = None, attempts: int = _RETRY_ATTEMPTS) -> requests.Response:
    """
    GET url with retry and rate-limit handling.
    Raises last exception if all attempts fail.
    """
    headers = {"User-Agent": "CoreRecon/2.1 (+https://github.com/corerecon)"}
    last_exc = None

    for attempt in range(attempts):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=_REQUEST_TIMEOUT)

            if resp.status_code == 429:
                # Rate limited — pause and retry
                log.warning(
                    "Rate limit hit, pausing",
                    extra={"url": url, "attempt": attempt + 1, "pause": _RATE_LIMIT_PAUSE},
                )
                time.sleep(_RATE_LIMIT_PAUSE)
                continue

            return resp

        except Exception as exc:
            last_exc = exc
            if attempt < attempts - 1:
                wait = _RETRY_BACKOFF * (attempt + 1)
                log.debug(f"Request failed (attempt {attempt + 1}), retrying in {wait:.1f}s: {exc}")
                time.sleep(wait)

    if last_exc:
        raise last_exc
    raise RuntimeError(f"All {attempts} attempts exhausted for {url}")


# ---------------------------------------------------------------------------
# Source functions
# ---------------------------------------------------------------------------

def _from_crtsh(target: str) -> Set[str]:
    """
    Query crt.sh certificate transparency log.
    Returns set of discovered subdomains.
    """
    subdomains: Set[str] = set()
    url = "https://crt.sh/"

    try:
        resp = _fetch_with_retry(url, params={"q": f"%.{target}", "output": "json"})
        if resp.status_code != 200:
            log.warning("crt.sh returned non-200", extra={"status": resp.status_code})
            return subdomains

        for entry in resp.json():
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line and target in line and not line.startswith("*"):
                    subdomains.add(line.lower())

    except Exception as exc:
        log.warning("crt.sh query failed", extra={"target": target, "error": str(exc)})

    return subdomains


def _from_hackertarget(target: str) -> Set[str]:
    """
    Query HackerTarget DNS brute-force API.
    Free tier: 100 lookups/day.
    """
    subdomains: Set[str] = set()
    url = "https://api.hackertarget.com/hostsearch/"

    try:
        resp = _fetch_with_retry(url, params={"q": target})
        if resp.status_code != 200:
            return subdomains

        text = resp.text.strip()
        if "error" in text.lower() or "API count" in text:
            log.warning("HackerTarget rate limit or error", extra={"response": text[:100]})
            return subdomains

        for line in text.splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lower()
                if sub and target in sub:
                    subdomains.add(sub)

    except Exception as exc:
        log.warning("HackerTarget query failed", extra={"target": target, "error": str(exc)})

    return subdomains


def _from_dnsdumpster(target: str) -> Set[str]:
    """
    Query DNSDumpster via their public API endpoint.
    Falls back gracefully on failure.
    """
    subdomains: Set[str] = set()

    try:
        # DNSDumpster requires a CSRF token from the landing page first
        session = requests.Session()
        session.headers["User-Agent"] = "CoreRecon/2.1 (+https://github.com/corerecon)"

        landing = session.get("https://dnsdumpster.com/", timeout=_REQUEST_TIMEOUT)
        csrf = landing.cookies.get("csrftoken", "")

        resp = session.post(
            "https://dnsdumpster.com/",
            data={"csrfmiddlewaretoken": csrf, "targetip": target, "user": "free"},
            headers={"Referer": "https://dnsdumpster.com/"},
            timeout=_REQUEST_TIMEOUT,
        )

        # Parse subdomains from HTML (basic extraction)
        import re
        pattern = re.compile(rf"([a-zA-Z0-9\-\.]+\.{re.escape(target)})")
        for match in pattern.finditer(resp.text):
            sub = match.group(1).lower().strip(".")
            if sub != target:
                subdomains.add(sub)

    except Exception as exc:
        log.debug("DNSDumpster query failed (non-critical)", extra={"error": str(exc)})

    return subdomains


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

def _classify_risk(hostname: str) -> str:
    """Classify a subdomain as HIGH or MEDIUM risk based on keyword presence."""
    hostname_lower = hostname.lower()
    parts = hostname_lower.replace("-", ".").replace("_", ".").split(".")
    for part in parts:
        if part in _HIGH_RISK_KEYWORDS:
            return "HIGH"
    return "MEDIUM"


def _build_risk_classified(subdomains: Set[str]) -> List[Dict[str, str]]:
    """Return list of {subdomain, risk_level} sorted HIGH-first."""
    classified = [
        {"subdomain": sub, "risk_level": _classify_risk(sub)}
        for sub in subdomains
    ]
    classified.sort(key=lambda x: (0 if x["risk_level"] == "HIGH" else 1, x["subdomain"]))
    return classified


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def discover_subdomains(target: str) -> Dict[str, Any]:
    """
    Enumerate subdomains for target using passive sources.

    Returns
    -------
    dict with:
      total_found         — int
      sources             — list of sources that returned data
      subdomains          — sorted list of all unique hostnames found
      risk_classified     — list of {subdomain, risk_level} sorted HIGH-first
      high_risk_subdomains — list of HIGH-risk records only (for correlations)
    """
    all_subs: Set[str] = set()
    sources_hit: List[str] = []

    # crt.sh — most reliable, query first
    crt_subs = _from_crtsh(target)
    if crt_subs:
        sources_hit.append("crt.sh")
        all_subs.update(crt_subs)
        log.debug(f"crt.sh returned {len(crt_subs)} results")

    # HackerTarget — good coverage of common subdomains
    ht_subs = _from_hackertarget(target)
    if ht_subs:
        sources_hit.append("hackertarget")
        all_subs.update(ht_subs)
        log.debug(f"HackerTarget returned {len(ht_subs)} results")

    # DNSDumpster — supplementary
    dd_subs = _from_dnsdumpster(target)
    if dd_subs:
        sources_hit.append("dnsdumpster")
        all_subs.update(dd_subs)
        log.debug(f"DNSDumpster returned {len(dd_subs)} results")

    # Clean and deduplicate — remove wildcards, empty strings, the root itself
    cleaned: Set[str] = set()
    for sub in all_subs:
        sub = sub.strip().lower().lstrip("*.")
        if sub and sub != target and sub.endswith(f".{target}") or sub == target:
            cleaned.add(sub)

    # Also keep subdomains that match without leading dot
    final_subs: Set[str] = {
        s for s in all_subs
        if s and s != target and target in s and not s.startswith("*")
    }

    risk_classified = _build_risk_classified(final_subs)
    high_risk = [r for r in risk_classified if r["risk_level"] == "HIGH"]

    log.info(
        "Subdomain discovery complete",
        extra={
            "target": target,
            "total": len(final_subs),
            "high_risk": len(high_risk),
            "sources": sources_hit,
        },
    )

    return {
        "total_found": len(final_subs),
        "sources": sources_hit,
        "subdomains": sorted(final_subs),
        "risk_classified": risk_classified,
        "high_risk_subdomains": high_risk,
    }
