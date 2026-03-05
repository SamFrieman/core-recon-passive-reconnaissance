"""
CoreRecon Technology Stack Detection Module
Uses Wappalyzer for fingerprinting — same library as v1.
Preserves output structure exactly: category → [{name, version}]
"""
from typing import Dict, Any

import requests
from Wappalyzer import Wappalyzer, WebPage

from backend.core.logger import get_logger

log = get_logger("corerecon.technology")

TIMEOUT = 15

# Technologies known to be end-of-life or actively concerning when version-exposed
# Populated conservatively — only clear EOL cases
EOL_INDICATORS = {
    "jquery": {"eol_below": "3.0.0", "note": "jQuery below 3.x has known XSS vulnerabilities"},
    "php": {"eol_below": "8.1", "note": "PHP versions below 8.1 are end-of-life"},
    "wordpress": {"eol_below": "6.0", "note": "WordPress below 6.0 — update strongly recommended"},
    "bootstrap": {"eol_below": "4.0.0", "note": "Bootstrap 3.x and below no longer receive security fixes"},
    "angularjs": {"eol_below": "99.0.0", "note": "AngularJS (1.x) reached end-of-life December 2021"},
    "python": {"eol_below": "3.8", "note": "Python below 3.8 is end-of-life"},
    "drupal": {"eol_below": "9.0", "note": "Drupal 8.x and below are end-of-life"},
}


def _compare_versions(version: str, threshold: str) -> bool:
    """
    Simple version comparison: returns True if version < threshold.
    Handles major.minor.patch — non-numeric versions return False.
    """
    try:
        v_parts = [int(x) for x in version.split(".")[:3]]
        t_parts = [int(x) for x in threshold.split(".")[:3]]
        # Pad shorter list
        while len(v_parts) < 3:
            v_parts.append(0)
        while len(t_parts) < 3:
            t_parts.append(0)
        return v_parts < t_parts
    except (ValueError, AttributeError):
        return False


def _check_eol(tech_name: str, version: str) -> Dict[str, Any]:
    """Check if a detected technology version is EOL."""
    if not version or version == "Undetected":
        return {"is_eol": False, "eol_note": None}

    key = tech_name.lower()
    if key in EOL_INDICATORS:
        indicator = EOL_INDICATORS[key]
        if _compare_versions(version, indicator["eol_below"]):
            return {"is_eol": True, "eol_note": indicator["note"]}

    return {"is_eol": False, "eol_note": None}


def get_technology_stack(domain: str) -> Dict[str, Any]:
    """
    Fingerprint technology stack via Wappalyzer.

    Preserves v1 output structure exactly:
      { "Category Name": [{"name": str, "version": str}] }

    Adds v2 enrichment per technology entry:
      eol_risk (bool), eol_note (str|None)
    These are additive fields within each technology entry.
    """
    wappalyzer = Wappalyzer.latest()

    for proto in ("https", "http"):
        try:
            url = f"{proto}://{domain}"
            webpage = WebPage.new_from_url(url, timeout=TIMEOUT)
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
            break
        except Exception as e:
            if proto == "https":
                log.warning("Wappalyzer HTTPS failed, trying HTTP", extra={"domain": domain, "error": str(e)})
                continue
            log.warning("Wappalyzer failed on both protocols", extra={"domain": domain, "error": str(e)})
            return {
                "error": f"Technology detection failed: {str(e)[:100]}",
                "note": "Wappalyzer could not fetch and analyze the target page",
            }

    # Restructure into category-grouped output (v1 format)
    categorized: Dict[str, list] = {}

    for tech_name, tech_data in technologies.items():
        version = tech_data.get("version", "") or "Undetected"
        categories = tech_data.get("categories", ["Miscellaneous"])

        # v2 EOL check
        eol_info = _check_eol(tech_name, version)

        entry = {
            # v1 fields
            "name": tech_name,
            "version": version,
            # v2 additions
            "eol_risk": eol_info["is_eol"],
            "eol_note": eol_info["eol_note"],
        }

        for category in categories:
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(entry)

    # Sort categories alphabetically (v1 behavior)
    result = dict(sorted(categorized.items()))

    log.info(
        "Technology stack analyzed",
        extra={
            "domain": domain,
            "categories": len(result),
            "technologies": sum(len(v) for v in result.values()),
        },
    )
    return result
