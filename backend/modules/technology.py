"""
CoreRecon Technology Stack Detection Module
Uses Wappalyzer for fingerprinting — same library as v1.
Preserves output structure exactly: category → [{name, version}]
"""
import re
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

def _extract_versions_from_response(headers: dict, html: str) -> Dict[str, str]:
    """
    Supplemental version extraction from HTTP response headers and HTML.
    Catches common cases where Wappalyzer fingerprints lack version regex.
    Returns a dict of {tech_name_lowercase: version_string}.
    """
    found: Dict[str, str] = {}

    # WordPress — meta generator tag
    wp = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([0-9][0-9.]+)',
        html, re.I
    )
    if wp:
        found["wordpress"] = wp.group(1)

    # jQuery — script src filename
    jq = re.search(
        r'jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js',
        html, re.I
    )
    if jq:
        found["jquery"] = jq.group(1)

    # Bootstrap — link/script src filename
    bs = re.search(
        r'bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.(?:css|js)',
        html, re.I
    )
    if bs:
        found["bootstrap"] = bs.group(1)

    # PHP — X-Powered-By header
    php = re.search(r'PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)', headers.get("X-Powered-By", ""), re.I)
    if php:
        found["php"] = php.group(1)

    # Drupal — meta generator tag
    drupal = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s+([0-9][0-9.]+)',
        html, re.I
    )
    if drupal:
        found["drupal"] = drupal.group(1)

    # Nginx — Server header
    nginx = re.search(r'nginx/([0-9]+\.[0-9]+\.[0-9]+)', headers.get("Server", ""), re.I)
    if nginx:
        found["nginx"] = nginx.group(1)

    # Apache — Server header
    apache = re.search(r'Apache/([0-9]+\.[0-9]+\.[0-9]+)', headers.get("Server", ""), re.I)
    if apache:
        found["apache"] = apache.group(1)

    # Python (Flask/Django) — X-Powered-By or Server
    py = re.search(r'Python/([0-9]+\.[0-9]+)', headers.get("X-Powered-By", "") + headers.get("Server", ""), re.I)
    if py:
        found["python"] = py.group(1)

    return found

def get_technology_stack(domain: str) -> Dict[str, Any]:
    """
    Fingerprint technology stack via Wappalyzer, supplemented with
    direct header/HTML version extraction for common cases.
    """
    wappalyzer = Wappalyzer.latest(update=False)

    response_obj = None
    technologies = {}

    for proto in ("https", "http"):
        try:
            url = f"{proto}://{domain}"
            webpage = WebPage.new_from_url(url, timeout=TIMEOUT)
            response_obj = webpage
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

    # Extract supplemental versions from raw response
    supplemental = {}
    if response_obj is not None:
        try:
            headers = dict(response_obj.headers) if response_obj.headers else {}
            html = response_obj.html or ""
            supplemental = _extract_versions_from_response(headers, html)
        except Exception as e:
            log.warning("Supplemental version extraction failed", extra={"domain": domain, "error": str(e)})

    # Restructure into category-grouped output
    categorized: Dict[str, list] = {}

    for tech_name, tech_data in technologies.items():
        version = tech_data.get("version", "") or ""

        # If Wappalyzer didn't find a version, check supplemental extraction
        if not version and tech_name.lower() in supplemental:
            version = supplemental[tech_name.lower()]

        version = version if version else "Undetected"
        categories = tech_data.get("categories", ["Miscellaneous"])

        eol_info = _check_eol(tech_name, version)

        entry = {
            "name": tech_name,
            "version": version,
            "eol_risk": eol_info["is_eol"],
            "eol_note": eol_info["eol_note"],
        }

        for category in categories:
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(entry)

    result = dict(sorted(categorized.items()))

    log.info(
        "Technology stack analyzed",
        extra={
            "domain": domain,
            "categories": len(result),
            "technologies": sum(len(v) for v in result.values()),
            "supplemental_versions": len(supplemental),
        },
    )
    return result
