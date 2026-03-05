"""
CoreRecon Passive Subdomain Enumeration Module
Sources: crt.sh (Certificate Transparency) + HackerTarget host search
Preserves v1 output structure exactly. Adds risk classification per subdomain.
"""
import re
from typing import Dict, Any, List, Set

import requests

from backend.core.logger import get_logger
from backend.core.errors import SoftFailError

log = get_logger("corerecon.subdomains")

TIMEOUT_CRTSH = 15
TIMEOUT_HACKERTARGET = 10

# Subdomain naming patterns that indicate elevated risk
HIGH_RISK_PATTERNS = [
    (re.compile(r"^(dev|develop|development|staging|stage|stg|uat|qa|test|testing|sandbox|demo)\.", re.I), "Development/Staging environment"),
    (re.compile(r"^(admin|administrator|manage|management|portal|control|panel|cp|cpanel|webmin)\.", re.I), "Admin interface"),
    (re.compile(r"^(vpn|remote|rdp|ssh|bastion|jump|gateway|access)\.", re.I), "Remote access endpoint"),
    (re.compile(r"^(api|api-dev|api-staging|api-test|graphql|rest|soap)\.", re.I), "API endpoint"),
    (re.compile(r"^(mail|smtp|imap|pop|webmail|mx|email|exchange)\.", re.I), "Mail infrastructure"),
    (re.compile(r"^(internal|intranet|corp|corporate|private|local|lan)\.", re.I), "Internal/private resource"),
    (re.compile(r"^(backup|bak|archive|old|legacy|deprecated|v1|v2)\.", re.I), "Legacy/backup resource"),
    (re.compile(r"^(jenkins|jira|confluence|gitlab|github|bitbucket|sonar|nexus|artifactory)\.", re.I), "DevOps tooling"),
    (re.compile(r"^(db|database|mysql|postgres|mongo|redis|elastic|kibana|grafana|prometheus)\.", re.I), "Database/monitoring"),
    (re.compile(r"^(ftp|sftp|uploads|files|cdn|assets|static|media|images)\.", re.I), "File/asset server"),
]

MEDIUM_RISK_PATTERNS = [
    (re.compile(r"^(blog|forum|community|support|help|docs|documentation)\.", re.I), "Content/support endpoint"),
    (re.compile(r"^(shop|store|ecommerce|checkout|payment|pay|cart)\.", re.I), "Ecommerce endpoint"),
    (re.compile(r"^(auth|login|sso|oauth|id|identity|account)\.", re.I), "Authentication endpoint"),
]


def _classify_subdomain_risk(subdomain: str) -> Dict[str, Any]:
    """
    Assess risk level of a subdomain based on naming patterns.
    Returns risk level and reason.
    """
    for pattern, reason in HIGH_RISK_PATTERNS:
        if pattern.match(subdomain):
            return {"level": "HIGH", "reason": reason}
    for pattern, reason in MEDIUM_RISK_PATTERNS:
        if pattern.match(subdomain):
            return {"level": "MEDIUM", "reason": reason}
    return {"level": "LOW", "reason": "Standard subdomain"}


def _query_crtsh(domain: str) -> Set[str]:
    """Query crt.sh Certificate Transparency logs."""
    subdomains: Set[str] = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=TIMEOUT_CRTSH,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            log.warning("crt.sh returned non-200", extra={"domain": domain, "status": resp.status_code})
            return subdomains

        entries = resp.json()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                # Filter wildcards and off-domain entries
                if "*" in name:
                    continue
                if domain in name:
                    subdomains.add(name)

    except requests.Timeout:
        log.warning("crt.sh timed out", extra={"domain": domain})
    except Exception as e:
        log.warning("crt.sh query failed", extra={"domain": domain, "error": str(e)})

    return subdomains


def _query_hackertarget(domain: str) -> Set[str]:
    """Query HackerTarget passive DNS host search."""
    subdomains: Set[str] = set()
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=TIMEOUT_HACKERTARGET,
        )
        if resp.status_code != 200:
            return subdomains

        text = resp.text.strip()
        if not text or "error" in text.lower() or "API count" in text:
            log.warning("HackerTarget hostsearch rate limited or errored", extra={"domain": domain})
            return subdomains

        for line in text.splitlines():
            parts = line.split(",")
            if parts and domain in parts[0]:
                subdomains.add(parts[0].strip().lower())

    except requests.Timeout:
        log.warning("HackerTarget hostsearch timed out", extra={"domain": domain})
    except Exception as e:
        log.warning("HackerTarget hostsearch failed", extra={"domain": domain, "error": str(e)})

    return subdomains


def get_subdomains_passive(domain: str) -> Dict[str, Any]:
    """
    Aggregate passive subdomain discovery from crt.sh and HackerTarget.

    Preserves v1 response structure exactly:
      count, subdomains (list, capped at 50), sources, note

    Adds v2 enrichments:
      high_risk_subdomains — list of subdomains with HIGH risk classification
      risk_classified — full list with risk level per subdomain (top 50 only)
    """
    all_subdomains: Set[str] = set()
    sources_used: List[str] = []

    # Source 1: crt.sh
    crtsh_results = _query_crtsh(domain)
    if crtsh_results:
        all_subdomains.update(crtsh_results)
        sources_used.append("crt.sh")
        log.info("crt.sh results", extra={"domain": domain, "count": len(crtsh_results)})

    # Source 2: HackerTarget
    ht_results = _query_hackertarget(domain)
    if ht_results:
        all_subdomains.update(ht_results)
        if "HackerTarget" not in sources_used:
            sources_used.append("HackerTarget")
        log.info("HackerTarget results", extra={"domain": domain, "count": len(ht_results)})

    sorted_subdomains = sorted(all_subdomains)
    total_count = len(sorted_subdomains)
    display_list = sorted_subdomains[:50]  # v1 cap preserved

    # Build note string (v1 behavior preserved)
    if total_count > 50:
        note = f"Showing 50 of {total_count} discovered subdomains"
    elif total_count == 0:
        note = "No subdomains discovered from passive sources"
    else:
        note = f"All {total_count} discovered subdomains shown"

    # v2: risk classification
    high_risk: List[Dict[str, str]] = []
    risk_classified: List[Dict[str, Any]] = []

    for sub in display_list:
        risk = _classify_subdomain_risk(sub)
        entry = {"subdomain": sub, "risk_level": risk["level"], "risk_reason": risk["reason"]}
        risk_classified.append(entry)
        if risk["level"] == "HIGH":
            high_risk.append(entry)

    log.info(
        "Subdomain enumeration complete",
        extra={"domain": domain, "total": total_count, "high_risk": len(high_risk), "sources": sources_used},
    )

    return {
        # --- v1 fields preserved exactly ---
        "count": total_count,
        "subdomains": display_list,
        "sources": sources_used if sources_used else ["No data returned"],
        "note": note,
        # --- v2 additions ---
        "high_risk_subdomains": high_risk,
        "risk_classified": risk_classified,
        "high_risk_count": len(high_risk),
    }
