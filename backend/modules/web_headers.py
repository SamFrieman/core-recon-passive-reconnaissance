"""
CoreRecon HTTP Fingerprinting & Security Headers Module
Preserves all v1 fields under 'fingerprint' key.
Adds: CSP policy analysis, HSTS max-age, cookie security flags, header grade.
"""
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import requests

from backend.core.logger import get_logger

log = get_logger("corerecon.web_headers")

REQUEST_TIMEOUT = 12
MAX_REDIRECTS = 10

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _parse_hsts(hsts_value: str) -> Dict[str, Any]:
    """
    Parse HSTS header into structured fields.
    Example: max-age=31536000; includeSubDomains; preload
    """
    if not hsts_value or hsts_value == "MISSING":
        return {"present": False, "max_age": None, "include_subdomains": False, "preload": False}

    max_age = None
    ma_match = re.search(r"max-age=(\d+)", hsts_value, re.I)
    if ma_match:
        max_age = int(ma_match.group(1))

    return {
        "present": True,
        "max_age": max_age,
        "max_age_days": round(max_age / 86400) if max_age else None,
        "include_subdomains": "includesubdomains" in hsts_value.lower(),
        "preload": "preload" in hsts_value.lower(),
        "strength": (
            "STRONG" if max_age and max_age >= 31536000 else
            "MODERATE" if max_age and max_age >= 2592000 else
            "WEAK"
        ),
    }


def _analyze_csp(csp_value: str) -> Dict[str, Any]:
    """
    Analyze Content-Security-Policy for common weaknesses.
    """
    if not csp_value or csp_value == "MISSING":
        return {
            "present": False,
            "has_unsafe_inline": False,
            "has_unsafe_eval": False,
            "has_wildcard_src": False,
            "allows_http_sources": False,
            "risk": "HIGH",
            "note": "No CSP found — XSS and injection attacks are unrestricted",
        }

    lower = csp_value.lower()
    has_unsafe_inline = "'unsafe-inline'" in lower
    has_unsafe_eval = "'unsafe-eval'" in lower
    has_wildcard = re.search(r"(default-src|script-src|style-src)\s+[^;]*\*", lower) is not None
    allows_http = "http://" in lower

    issues = []
    if has_unsafe_inline:
        issues.append("'unsafe-inline' permits inline script execution")
    if has_unsafe_eval:
        issues.append("'unsafe-eval' permits eval() and dynamic code execution")
    if has_wildcard:
        issues.append("Wildcard (*) in source directive weakens policy")
    if allows_http:
        issues.append("HTTP sources allowed — mixed content risk")

    risk = "LOW" if not issues else ("MEDIUM" if len(issues) == 1 else "HIGH")

    return {
        "present": True,
        "has_unsafe_inline": has_unsafe_inline,
        "has_unsafe_eval": has_unsafe_eval,
        "has_wildcard_src": has_wildcard,
        "allows_http_sources": allows_http,
        "issues": issues,
        "risk": risk,
        "note": "; ".join(issues) if issues else "CSP policy appears reasonably configured",
    }


def _analyze_cookies(cookies: requests.cookies.RequestsCookieJar) -> Dict[str, Any]:
    """
    Inspect cookies for security flags: HttpOnly, Secure, SameSite.
    """
    total = len(cookies)
    if total == 0:
        return {"count": 0, "insecure_cookies": [], "analysis": None}

    insecure = []
    for cookie in cookies:
        issues = []
        if not cookie.secure:
            issues.append("Missing Secure flag")
        # requests doesn't directly expose HttpOnly/SameSite but we can inspect _rest
        rest = getattr(cookie, "_rest", {}) or {}
        if not rest.get("HttpOnly") and not rest.get("httponly"):
            issues.append("Missing HttpOnly flag")
        samesite = rest.get("SameSite") or rest.get("samesite")
        if not samesite:
            issues.append("Missing SameSite attribute")
        elif samesite.lower() == "none" and not cookie.secure:
            issues.append("SameSite=None without Secure flag")

        if issues:
            insecure.append({"name": cookie.name, "issues": issues})

    return {
        "count": total,
        "insecure_cookies": insecure,
        "insecure_count": len(insecure),
        "all_secure": len(insecure) == 0,
    }


def _score_header_grade(headers: Dict[str, str], hsts_analysis: Dict, csp_analysis: Dict) -> str:
    """
    Simple A-F header security grade. Informational only.
    """
    score = 100
    if headers.get("Strict-Transport-Security", "MISSING") == "MISSING":
        score -= 25
    elif hsts_analysis.get("strength") == "WEAK":
        score -= 10
    if headers.get("Content-Security-Policy", "MISSING") == "MISSING":
        score -= 25
    elif csp_analysis.get("risk") == "HIGH":
        score -= 15
    if headers.get("X-Frame-Options", "MISSING") == "MISSING":
        score -= 15
    if headers.get("X-Content-Type-Options", "MISSING") == "MISSING":
        score -= 10
    if headers.get("Referrer-Policy", "MISSING") == "MISSING":
        score -= 10
    if headers.get("Permissions-Policy", "MISSING") == "MISSING":
        score -= 10
    if headers.get("X-XSS-Protection", "MISSING") == "MISSING":
        score -= 5

    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


def get_security_headers(domain: str) -> Dict[str, Any]:
    """
    HTTP fingerprinting: server identity, protocol, headers, cookies, redirects.

    Preserves v1 response structure exactly (all fields under 'fingerprint').
    Adds v2 enrichments:
      fingerprint.hsts_analysis, fingerprint.csp_analysis,
      fingerprint.cookie_analysis, fingerprint.header_grade
    """
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    response: Optional[requests.Response] = None
    protocol_used = "HTTPS"
    redirect_chain: List[str] = []
    error_context = None

    # Try HTTPS first, fall back to HTTP
    for proto in ("https", "http"):
        try:
            url = f"{proto}://{domain}"
            resp = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; CoreRecon/2.0)"},
                verify=False,  # passive check — we just want headers
            )
            response = resp
            protocol_used = proto.upper()
            # Capture redirect chain
            redirect_chain = [r.url for r in resp.history] + [resp.url]
            if len(redirect_chain) == 1:
                redirect_chain = []  # No redirects — cleaner output
            break
        except requests.TooManyRedirects:
            error_context = "Too many redirects"
            break
        except requests.ConnectionError:
            if proto == "https":
                protocol_used = "HTTP"
                continue
            error_context = "Connection refused on both HTTPS and HTTP"
            break
        except requests.Timeout:
            error_context = f"{proto.upper()} request timed out"
            if proto == "https":
                continue
            break
        except Exception as e:
            error_context = str(e)
            if proto == "https":
                continue
            break

    if response is None:
        log.warning("HTTP fingerprinting failed", extra={"domain": domain, "reason": error_context})
        return {
            "server": "Unreachable",
            "powered_by": "Unknown",
            "protocol": "Unknown",
            "status_code": None,
            "security": {h: "MISSING" for h in SECURITY_HEADERS},
            "cookies": 0,
            "redirect_chain": [],
            "error": error_context or "Could not connect to domain",
            "hsts_analysis": _parse_hsts(""),
            "csp_analysis": _analyze_csp(""),
            "cookie_analysis": {"count": 0, "insecure_cookies": []},
            "header_grade": "F",
        }

    headers = response.headers
    security_headers: Dict[str, str] = {}
    for h in SECURITY_HEADERS:
        security_headers[h] = headers.get(h, "MISSING")

    # v2 enrichments
    hsts_analysis = _parse_hsts(security_headers["Strict-Transport-Security"])
    csp_analysis = _analyze_csp(security_headers["Content-Security-Policy"])
    cookie_analysis = _analyze_cookies(response.cookies)
    header_grade = _score_header_grade(security_headers, hsts_analysis, csp_analysis)

    result = {
        # --- v1 fields preserved exactly ---
        "server": headers.get("Server", "Not disclosed"),
        "powered_by": headers.get("X-Powered-By", "Not disclosed"),
        "protocol": protocol_used,
        "status_code": response.status_code,
        "security": security_headers,
        "cookies": len(response.cookies),
        "redirect_chain": redirect_chain,
        # --- v2 additions ---
        "hsts_analysis": hsts_analysis,
        "csp_analysis": csp_analysis,
        "cookie_analysis": cookie_analysis,
        "header_grade": header_grade,
    }

    log.info(
        "HTTP fingerprint gathered",
        extra={"domain": domain, "protocol": protocol_used, "grade": header_grade, "status": response.status_code},
    )
    return result
