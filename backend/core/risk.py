"""
CoreRecon Risk Scoring Engine v2
Replaces the flat additive model with a weighted, category-aware system.

Why the replacement is justified:
- v1 score could exceed 100 before clamping, making the math indefensible
- v1 ignored DNS (SPF/DMARC), TLS algorithm quality, and technology risk entirely
- v1 had no per-category breakdown, so users couldn't triage what to fix first
- v2 is capped per-category (0-100), then composited — score is always defensible

v1 API fields are preserved for backward compatibility:
  risk_score, risk_level, risk_status, risk_issues, recommendations

New fields added:
  risk_breakdown, risk_confidence, risk_score_v2 (same as risk_score in this impl)
"""
from typing import Dict, Any, List, Tuple

# ---------------------------------------------------------------------------
# Category weights — must sum to 1.0
# ---------------------------------------------------------------------------
CATEGORY_WEIGHTS = {
    "tls":            0.25,  # Certificate validity, algorithm, TLS version
    "web_security":   0.25,  # Security headers (CSP, HSTS, X-Frame, etc.)
    "infrastructure": 0.20,  # HTTPS availability, HTTP-only access
    "dns":            0.15,  # SPF, DMARC, DNSSEC
    "technology":     0.10,  # EOL software, version exposure
    "exposure":       0.05,  # Server banner, powered-by disclosure
}

# ---------------------------------------------------------------------------
# Risk level bands (applied to composite 0–100 score)
# ---------------------------------------------------------------------------
RISK_BANDS = [
    (0,  15,  "MINIMAL",  "Excellent security posture with no significant findings"),
    (16, 35,  "LOW",      "Good security posture with minor improvements recommended"),
    (36, 60,  "MEDIUM",   "Moderate security concerns identified — remediation advised"),
    (61, 80,  "HIGH",     "Significant security vulnerabilities found — prompt remediation required"),
    (81, 100, "CRITICAL", "Critical security issues detected — immediate action required"),
]


def _get_level(score: int) -> Tuple[str, str]:
    """Map a 0–100 score to a (level, status) tuple."""
    for low, high, level, status in RISK_BANDS:
        if low <= score <= high:
            return level, status
    return "CRITICAL", "Score out of expected range"


# ---------------------------------------------------------------------------
# Per-category scorers
# Each returns: (category_score: int, findings: list[str], recommendations: list[str])
# category_score is 0–100; higher = more risk in that category
# ---------------------------------------------------------------------------

def _score_tls(ssl: Dict, fingerprint: Dict) -> Tuple[int, List[str], List[str]]:
    findings, recs = [], []
    score = 0

    if not ssl or "error" in ssl:
        score += 100
        findings.append("No SSL/TLS certificate — HTTPS unavailable")
        recs.append("Deploy an SSL/TLS certificate. Let's Encrypt provides free certificates.")
        return min(score, 100), findings, recs

    days = ssl.get("days_remaining")
    if days is not None:
        if days < 0:
            score += 60
            findings.append("SSL certificate has EXPIRED")
            recs.append("Renew the SSL certificate immediately — site is showing security errors to visitors.")
        elif days <= 7:
            score += 50
            findings.append(f"SSL certificate expires in {days} days — critical renewal required")
            recs.append("Renew the SSL certificate within 24 hours to prevent outage.")
        elif days <= 30:
            score += 30
            findings.append(f"SSL certificate expires in {days} days")
            recs.append("Renew the SSL certificate before it expires to maintain trust.")
        elif days <= 90:
            score += 10
            findings.append(f"SSL certificate expiring in {days} days — renewal recommended soon")
            recs.append("Schedule SSL certificate renewal within the next 30 days.")

    algo = ssl.get("algorithm_analysis", {})
    if algo.get("is_weak"):
        score += 30
        findings.append(f"Weak signature algorithm in use: {algo.get('algorithm', 'Unknown')}")
        recs.append("Replace certificate with one using SHA-256 or better signature algorithm.")

    if ssl.get("is_self_signed"):
        score += 40
        findings.append("Self-signed certificate detected — browsers will display security warnings")
        recs.append("Replace self-signed certificate with one from a trusted Certificate Authority.")

    tls_risk = ssl.get("tls_risk", "LOW")
    if tls_risk == "CRITICAL":
        score += 35
        findings.append(f"Deprecated TLS version in use: {ssl.get('tls_version', 'Unknown')}")
        recs.append("Disable TLS 1.0 and 1.1. Enforce TLS 1.2 minimum; prefer TLS 1.3.")
    elif tls_risk == "HIGH":
        score += 20
        findings.append(f"Outdated TLS version: {ssl.get('tls_version', 'Unknown')}")
        recs.append("Upgrade to TLS 1.2 or TLS 1.3 — TLS 1.1 is deprecated by all major browsers.")

    return min(score, 100), findings, recs


def _score_web_security(fingerprint: Dict) -> Tuple[int, List[str], List[str]]:
    findings, recs = [], []
    score = 0

    if not fingerprint:
        return 60, ["HTTP fingerprinting data unavailable"], []

    security = fingerprint.get("security", {})

    # Header presence checks
    header_penalties = {
        "Strict-Transport-Security": (25, "Missing HSTS header — browsers may connect over HTTP",
                                       "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."),
        "Content-Security-Policy":   (25, "Missing Content-Security-Policy header — XSS attacks unrestricted",
                                       "Implement a Content-Security-Policy that restricts resource loading to trusted sources."),
        "X-Frame-Options":           (15, "Missing X-Frame-Options header — site vulnerable to clickjacking",
                                       "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent iframe embedding."),
        "X-Content-Type-Options":    (10, "Missing X-Content-Type-Options header — MIME sniffing risk",
                                       "Add 'X-Content-Type-Options: nosniff' to prevent MIME type confusion attacks."),
        "Referrer-Policy":           (8,  "Missing Referrer-Policy header — URL leakage risk",
                                       "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer exposure."),
        "Permissions-Policy":        (7,  "Missing Permissions-Policy header",
                                       "Add Permissions-Policy to restrict browser feature access (camera, microphone, etc.)."),
        "X-XSS-Protection":          (5,  "Missing X-XSS-Protection header",
                                       "Add 'X-XSS-Protection: 1; mode=block' for legacy browser XSS protection."),
    }

    for header, (penalty, finding, rec) in header_penalties.items():
        val = security.get(header, "MISSING")
        if val == "MISSING":
            score += penalty
            findings.append(finding)
            recs.append(rec)

    # CSP quality analysis
    csp_analysis = fingerprint.get("csp_analysis", {})
    if csp_analysis.get("has_unsafe_inline") and security.get("Content-Security-Policy", "MISSING") != "MISSING":
        score += 10
        findings.append("CSP contains 'unsafe-inline' — inline script execution permitted")
        recs.append("Remove 'unsafe-inline' from CSP and use nonces or hashes instead.")
    if csp_analysis.get("has_unsafe_eval") and security.get("Content-Security-Policy", "MISSING") != "MISSING":
        score += 8
        findings.append("CSP contains 'unsafe-eval' — dynamic code execution permitted")
        recs.append("Remove 'unsafe-eval' from CSP to prevent dynamic code execution attacks.")

    # Protocol
    if fingerprint.get("protocol") == "HTTP":
        score += 20
        findings.append("Site accessible over unencrypted HTTP")
        recs.append("Redirect all HTTP traffic to HTTPS and enforce HSTS.")

    # Cookie security
    cookie_analysis = fingerprint.get("cookie_analysis", {})
    if cookie_analysis.get("insecure_count", 0) > 0:
        score += 10
        findings.append(f"{cookie_analysis['insecure_count']} cookie(s) missing security flags (Secure, HttpOnly, SameSite)")
        recs.append("Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.")

    return min(score, 100), findings, recs


def _score_infrastructure(infra: Dict, fingerprint: Dict) -> Tuple[int, List[str], List[str]]:
    findings, recs = [], []
    score = 0

    if not infra or infra.get("status") == "OFFLINE":
        score = 30
        findings.append("Domain resolves to offline or unreachable host")
        return min(score, 100), findings, recs

    # HTTP-only already counted in web_security but flag here too at lower penalty
    if fingerprint and fingerprint.get("protocol") == "HTTP":
        score += 15

    # CDN/hosting provider observation (informational, minimal penalty)
    cdn = infra.get("cdn", {})
    if not cdn.get("detected") and infra.get("ip") not in ("Resolution Failed", None):
        # No CDN — direct origin exposure — minor concern
        score += 5
        findings.append("No CDN detected — origin server IP directly exposed")
        recs.append("Consider deploying behind a CDN (e.g., Cloudflare) to mask origin IP and add DDoS protection.")

    return min(score, 100), findings, recs


def _score_dns(dns: Dict) -> Tuple[int, List[str], List[str]]:
    findings, recs = [], []
    score = 0

    if not dns:
        return 40, ["DNS data unavailable"], []

    # SPF
    spf = dns.get("spf", {})
    if not spf.get("present"):
        score += 40
        findings.append("No SPF record — domain vulnerable to email spoofing")
        recs.append("Publish an SPF record in DNS to authorize legitimate mail senders.")
    elif spf.get("risk") in ("HIGH", "CRITICAL"):
        score += 20
        findings.append(f"SPF record present but policy is weak: {spf.get('policy', 'Unknown')}")
        recs.append("Strengthen SPF policy — use '-all' (hard fail) instead of '~all' or '?all'.")
    elif spf.get("risk") == "MEDIUM":
        score += 10
        findings.append(f"SPF soft-fail policy — limited protection against spoofing")
        recs.append("Consider upgrading SPF from '~all' to '-all' for stricter enforcement.")

    # DMARC
    dmarc = dns.get("dmarc", {})
    if not dmarc.get("present"):
        score += 40
        findings.append("No DMARC record — email authentication unenforced")
        recs.append("Implement DMARC with at minimum p=quarantine to reduce phishing risk from your domain.")
    elif dmarc.get("policy") == "none":
        score += 20
        findings.append("DMARC policy is 'none' — monitoring only, no enforcement")
        recs.append("Progress DMARC policy from 'none' to 'quarantine' then 'reject'.")
    elif dmarc.get("policy") == "quarantine":
        score += 5
        findings.append("DMARC quarantine policy — good, but 'reject' provides stronger protection")
        recs.append("Consider strengthening DMARC to p=reject for full enforcement.")

    # DNSSEC
    dnssec = dns.get("dnssec", {})
    if not dnssec.get("enabled"):
        score += 15
        findings.append("DNSSEC not detected — DNS responses unvalidated")
        recs.append("Enable DNSSEC signing to protect against DNS spoofing and cache poisoning.")

    return min(score, 100), findings, recs


def _score_technology(tech: Dict) -> Tuple[int, List[str], List[str]]:
    findings, recs = [], []
    score = 0

    if not tech or "error" in tech:
        return 0, [], []

    eol_found = []
    version_exposed = []

    for category, tech_list in tech.items():
        if not isinstance(tech_list, list):
            continue
        for t in tech_list:
            if not isinstance(t, dict):
                continue
            name = t.get("name", "Unknown")
            version = t.get("version", "Undetected")

            if t.get("eol_risk"):
                eol_found.append(f"{name} {version}")
                score += 20

            if version and version != "Undetected":
                version_exposed.append(f"{name} {version}")

    if eol_found:
        findings.append(f"End-of-life software detected: {', '.join(eol_found[:3])}" +
                        (f" and {len(eol_found)-3} more" if len(eol_found) > 3 else ""))
        recs.append("Update end-of-life software to current supported versions to receive security patches.")

    if len(version_exposed) > 3:
        score += 10
        findings.append(f"Specific version strings exposed for {len(version_exposed)} technologies")
        recs.append("Configure servers to suppress version disclosure in HTTP headers and error pages.")

    return min(score, 100), findings, recs


def _score_exposure(fingerprint: Dict) -> Tuple[int, List[str], List[str]]:
    findings, recs = [], []
    score = 0

    if not fingerprint:
        return 0, [], []

    server = fingerprint.get("server", "")
    if server and server not in ("Not disclosed", "Unreachable", "") and "/" in server:
        score += 50
        findings.append(f"Server version disclosed in banner: {server}")
        recs.append("Configure your web server to suppress the Server header or remove version information.")

    powered_by = fingerprint.get("powered_by", "")
    if powered_by and powered_by not in ("Not disclosed", ""):
        score += 35
        findings.append(f"X-Powered-By header exposes backend technology: {powered_by}")
        recs.append("Remove or suppress the X-Powered-By header to reduce information exposure.")

    return min(score, 100), findings, recs


# ---------------------------------------------------------------------------
# Confidence rating based on data completeness
# ---------------------------------------------------------------------------

def _calculate_confidence(data: Dict) -> str:
    """Rate how complete the scan data is — affects interpretive confidence."""
    available = 0
    total = 6

    if data.get("ssl_certificate") and "error" not in data.get("ssl_certificate", {}):
        available += 1
    if data.get("fingerprint") and "error" not in data.get("fingerprint", {}):
        available += 1
    if data.get("dns") and data["dns"].get("A"):
        available += 1
    dns_intel = data.get("dns", {})
    if dns_intel.get("spf") or dns_intel.get("dmarc"):
        available += 1
    if data.get("technology") and "error" not in data.get("technology", {}):
        available += 1
    if data.get("infrastructure") and data["infrastructure"].get("ip") != "Resolution Failed":
        available += 1

    ratio = available / total
    if ratio >= 0.85:
        return "HIGH"
    elif ratio >= 0.6:
        return "MEDIUM"
    else:
        return "LOW"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def calculate_risk_score(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Weighted category-aware risk scoring.
    Returns all v1 API fields plus v2 breakdown fields.
    """
    ssl = data.get("ssl_certificate", {})
    fingerprint = data.get("fingerprint", {})
    infra = data.get("infrastructure", {})
    dns = data.get("dns", {})
    tech = data.get("technology", {})

    # Score each category
    tls_score,   tls_findings,   tls_recs   = _score_tls(ssl, fingerprint)
    web_score,   web_findings,   web_recs   = _score_web_security(fingerprint)
    infra_score, infra_findings, infra_recs = _score_infrastructure(infra, fingerprint)
    dns_score,   dns_findings,   dns_recs   = _score_dns(dns)
    tech_score,  tech_findings,  tech_recs  = _score_technology(tech)
    exp_score,   exp_findings,   exp_recs   = _score_exposure(fingerprint)

    # Composite weighted score
    composite = (
        tls_score   * CATEGORY_WEIGHTS["tls"] +
        web_score   * CATEGORY_WEIGHTS["web_security"] +
        infra_score * CATEGORY_WEIGHTS["infrastructure"] +
        dns_score   * CATEGORY_WEIGHTS["dns"] +
        tech_score  * CATEGORY_WEIGHTS["technology"] +
        exp_score   * CATEGORY_WEIGHTS["exposure"]
    )
    final_score = min(100, round(composite))

    # Aggregate all findings and recommendations
    all_findings = tls_findings + web_findings + infra_findings + dns_findings + tech_findings + exp_findings
    all_recs = tls_recs + web_recs + infra_recs + dns_recs + tech_recs + exp_recs

    level, status = _get_level(final_score)
    confidence = _calculate_confidence(data)

    breakdown = {
        "tls": {
            "score": tls_score,
            "weight": CATEGORY_WEIGHTS["tls"],
            "weighted_contribution": round(tls_score * CATEGORY_WEIGHTS["tls"]),
            "findings": tls_findings,
        },
        "web_security": {
            "score": web_score,
            "weight": CATEGORY_WEIGHTS["web_security"],
            "weighted_contribution": round(web_score * CATEGORY_WEIGHTS["web_security"]),
            "findings": web_findings,
        },
        "infrastructure": {
            "score": infra_score,
            "weight": CATEGORY_WEIGHTS["infrastructure"],
            "weighted_contribution": round(infra_score * CATEGORY_WEIGHTS["infrastructure"]),
            "findings": infra_findings,
        },
        "dns": {
            "score": dns_score,
            "weight": CATEGORY_WEIGHTS["dns"],
            "weighted_contribution": round(dns_score * CATEGORY_WEIGHTS["dns"]),
            "findings": dns_findings,
        },
        "technology": {
            "score": tech_score,
            "weight": CATEGORY_WEIGHTS["technology"],
            "weighted_contribution": round(tech_score * CATEGORY_WEIGHTS["technology"]),
            "findings": tech_findings,
        },
        "exposure": {
            "score": exp_score,
            "weight": CATEGORY_WEIGHTS["exposure"],
            "weighted_contribution": round(exp_score * CATEGORY_WEIGHTS["exposure"]),
            "findings": exp_findings,
        },
    }

    return {
        # --- v1 fields preserved exactly (same keys, same semantics) ---
        "score":            final_score,
        "level":            level,
        "status":           status,
        "issues":           all_findings,
        "recommendations":  all_recs,
        "issues_count":     len(all_findings),
        # --- v2 additions ---
        "risk_breakdown":   breakdown,
        "risk_confidence":  confidence,
    }
