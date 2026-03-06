"""
CoreRecon Risk Engine v2.1
Computes a 0–100 security risk score from cross-module scan data.

v2.1 calibration changes vs v2.0:
  - Category weights: TLS 25%, Web Security 25%, Infrastructure 15%,
    DNS 15%, Technology 10%, Exposure 10%
  - DNSSEC penalty reduced 15 → 10 pts (less critical than email auth)
  - Compound SPF+DMARC absence penalty added (-8 pts bonus for having both)
  - Self-signed cert penalty now exempts dev/staging subdomains
  - Subdomain exposure count incorporated into exposure score
  - Technology EOL signals weighted higher when high-risk subdomains present
"""
from typing import Any, Dict, List, Optional

from backend.core.logger import get_logger

log = get_logger("corerecon.risk")


# ---------------------------------------------------------------------------
# Category weights (must sum to 1.0)
# ---------------------------------------------------------------------------
_WEIGHTS = {
    "tls":            0.25,
    "web_security":   0.25,
    "infrastructure": 0.15,
    "dns":            0.15,
    "technology":     0.10,
    "exposure":       0.10,
}


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _score_tls(ssl: Dict[str, Any]) -> float:
    """Score TLS posture. Higher score = better security."""
    if not ssl or ssl.get("error"):
        # No TLS data — assume worst case
        return 20.0

    score = 100.0

    # TLS version risk
    tls_risk = ssl.get("tls_risk", "UNKNOWN")
    version_penalties = {
        "CRITICAL": -50,   # SSLv2/SSLv3/TLS 1.0
        "HIGH":     -35,   # TLS 1.1
        "MEDIUM":   -15,   # TLS 1.2 with weak ciphers
        "LOW":        0,   # TLS 1.2+ good
        "UNKNOWN":  -10,
    }
    score += version_penalties.get(tls_risk, -10)

    # Certificate validity
    if ssl.get("cert_expired"):
        score -= 30
    elif ssl.get("cert_expiry_warning"):
        score -= 10

    # Self-signed certificate on a non-dev/staging asset
    if ssl.get("self_signed") and not ssl.get("is_dev_environment", False):
        score -= 20
    elif ssl.get("self_signed"):
        score -= 5   # Expected on dev environments, minor concern

    # Weak cipher suites
    if ssl.get("weak_ciphers"):
        score -= 15

    # Perfect Forward Secrecy
    if ssl.get("pfs") is False:
        score -= 10

    return _clamp(score)


def _score_web_security(fingerprint: Dict[str, Any]) -> float:
    """Score HTTP security headers and web posture."""
    if not fingerprint:
        return 40.0

    score = 100.0

    # Security header grade (A–F)
    grade_penalties = {
        "A+": 0, "A": 0, "B": -10, "C": -20,
        "D": -35, "F": -50, "?": -20,
    }
    grade = fingerprint.get("header_grade", "?")
    score += grade_penalties.get(grade, -20)

    # HSTS
    if not fingerprint.get("hsts"):
        score -= 15

    # Content Security Policy
    if not fingerprint.get("csp"):
        score -= 10

    # X-Frame-Options
    if not fingerprint.get("x_frame_options"):
        score -= 5

    # X-Content-Type-Options
    if not fingerprint.get("x_content_type_options"):
        score -= 5

    # Running over plain HTTP (no redirect to HTTPS)
    if fingerprint.get("protocol") == "HTTP":
        score -= 25

    return _clamp(score)


def _score_infrastructure(infrastructure: Dict[str, Any]) -> float:
    """Score infrastructure exposure posture."""
    if not infrastructure:
        return 60.0

    score = 100.0

    if not infrastructure.get("online", True):
        return 100.0   # Offline — no exposure

    # CDN protection adds points
    cdn = infrastructure.get("cdn", {})
    if cdn.get("detected"):
        score += 10   # CDN hides origin, adds DDoS protection
    else:
        score -= 10   # Direct origin exposure

    # Open non-standard ports
    open_ports = infrastructure.get("open_ports", [])
    risky_ports = {21, 23, 25, 110, 143, 445, 3306, 3389, 5432, 5900, 6379, 27017}
    risky_open = [p for p in open_ports if p in risky_ports]
    score -= len(risky_open) * 8

    # Cloud provider (reduces self-managed risk)
    if infrastructure.get("cloud_provider"):
        score += 5

    return _clamp(score)


def _score_dns(dns: Dict[str, Any]) -> float:
    """Score DNS security configuration."""
    if not dns:
        return 40.0

    score = 100.0

    # SPF
    spf = dns.get("spf", {})
    if not spf.get("present"):
        score -= 20
    elif spf.get("policy") in ("+all", "?all"):
        score -= 15   # Overly permissive

    # DMARC
    dmarc = dns.get("dmarc", {})
    if not dmarc.get("present"):
        score -= 25
    elif dmarc.get("policy") == "none":
        score -= 15

    # Compound penalty: both SPF and DMARC absent (worst case for email security)
    if not spf.get("present") and not dmarc.get("present"):
        score -= 8   # Extra penalty on top of the individual deductions

    # DNSSEC (v2.1: reduced from 15 to 10 — less critical than email auth)
    if not dns.get("dnssec"):
        score -= 10

    # MX records without SPF is specifically bad
    if dns.get("mx") and not spf.get("present"):
        score -= 5

    # CAA record (certificate authority authorisation)
    if not dns.get("caa"):
        score -= 5

    return _clamp(score)


def _score_technology(
    technology: Dict[str, Any],
    high_risk_subdomain_count: int = 0,
) -> float:
    """
    Score technology stack security.
    EOL risks are weighted higher when sensitive subdomains are present.
    """
    if not technology or not isinstance(technology, dict):
        return 80.0

    score = 100.0
    eol_count = 0
    outdated_count = 0

    for category, items in technology.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("eol_risk"):
                eol_count += 1
            elif item.get("outdated"):
                outdated_count += 1

    # Base penalties
    score -= eol_count * 20
    score -= outdated_count * 8

    # Amplify EOL penalty when high-risk subdomains are reachable
    # Rationale: EOL software on domains with admin/dev/db subdomains = much larger blast radius
    if eol_count > 0 and high_risk_subdomain_count > 0:
        amplifier = min(high_risk_subdomain_count, 5)  # Cap amplification at 5 subdomains
        score -= eol_count * amplifier * 3

    return _clamp(score)


def _score_exposure(
    subdomains: Dict[str, Any],
    exposed_assets: Optional[List[Dict]] = None,
) -> float:
    """Score exposure based on subdomain risk profile and detected exposed assets."""
    score = 100.0

    # High-risk subdomains
    high_risk = subdomains.get("high_risk_subdomains", [])
    hr_count = len(high_risk)
    if hr_count > 0:
        score -= min(hr_count * 8, 40)   # Up to -40 for many high-risk subs

    # Exposed assets from Phase 3 module
    if exposed_assets:
        sev_penalties = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
        for asset in exposed_assets:
            score -= sev_penalties.get(asset.get("severity", "LOW"), 2)

    # Total subdomain count (attack surface breadth)
    total_subs = subdomains.get("total_found", 0)
    if total_subs > 50:
        score -= 10
    elif total_subs > 20:
        score -= 5

    return _clamp(score)


# ---------------------------------------------------------------------------
# Risk issue generator (produces the `risk_issues` list in API response)
# ---------------------------------------------------------------------------

def _build_risk_issues(
    ssl: Dict,
    fingerprint: Dict,
    dns: Dict,
    infrastructure: Dict,
    technology: Dict,
    subdomains: Dict,
    exposed_assets: Optional[List[Dict]],
) -> List[Dict[str, str]]:
    """
    Generate a prioritised list of specific risk findings.
    Each finding: {issue, severity, category}
    """
    issues: List[Dict[str, str]] = []

    def add(issue: str, severity: str, category: str) -> None:
        issues.append({"issue": issue, "severity": severity, "category": category})

    # --- TLS ---
    if ssl and not ssl.get("error"):
        tls_risk = ssl.get("tls_risk", "")
        if tls_risk == "CRITICAL":
            add(f"Critically weak TLS in use ({ssl.get('tls_version', 'unknown')}) — vulnerable to protocol downgrade attacks", "CRITICAL", "tls")
        elif tls_risk == "HIGH":
            add(f"Deprecated TLS version ({ssl.get('tls_version', 'unknown')}) — should upgrade to TLS 1.3", "HIGH", "tls")
        if ssl.get("cert_expired"):
            add("TLS certificate is expired — browsers will present security warnings", "HIGH", "tls")
        elif ssl.get("cert_expiry_warning"):
            add(f"TLS certificate expires soon ({ssl.get('cert_days_remaining', '?')} days remaining)", "MEDIUM", "tls")
        if ssl.get("self_signed") and not ssl.get("is_dev_environment"):
            add("Self-signed TLS certificate in use on production asset — no trusted CA validation", "HIGH", "tls")
        if ssl.get("weak_ciphers"):
            add("Weak TLS cipher suites detected — susceptible to cipher-downgrade attacks", "MEDIUM", "tls")
        if ssl.get("pfs") is False:
            add("Perfect Forward Secrecy (PFS) not supported — past traffic decryptable if key is compromised", "MEDIUM", "tls")
    elif not ssl or ssl.get("error"):
        add("Unable to retrieve TLS certificate — HTTPS may not be configured", "HIGH", "tls")

    # --- Web Security ---
    if fingerprint:
        grade = fingerprint.get("header_grade", "?")
        if grade in ("D", "F"):
            add(f"Poor security header posture (grade {grade}) — missing critical browser protection headers", "HIGH", "web_security")
        elif grade == "C":
            add(f"Weak security header posture (grade {grade}) — several important headers missing", "MEDIUM", "web_security")
        if not fingerprint.get("hsts"):
            add("HSTS (HTTP Strict Transport Security) not configured — allows HTTP downgrade attacks", "HIGH", "web_security")
        if not fingerprint.get("csp"):
            add("Content Security Policy (CSP) not configured — XSS attack surface is unrestricted", "MEDIUM", "web_security")
        if fingerprint.get("protocol") == "HTTP":
            add("Site accessible over unencrypted HTTP — all traffic is observable in transit", "HIGH", "web_security")

    # --- DNS ---
    if dns:
        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        if not spf.get("present") and not dmarc.get("present"):
            add(f"No SPF or DMARC records — domain can be freely spoofed in phishing attacks", "CRITICAL", "dns")
        elif not dmarc.get("present"):
            add("SPF configured but DMARC absent — email spoofing partially mitigated but From-header still spoofable", "HIGH", "dns")
        elif dmarc.get("policy") == "none":
            add("DMARC policy is 'none' (monitor-only) — no email spoofing enforcement active", "MEDIUM", "dns")
        if not dns.get("dnssec"):
            add("DNSSEC not enabled — DNS responses are not cryptographically authenticated", "MEDIUM", "dns")
        if not dns.get("caa"):
            add("No CAA record — any certificate authority can issue certificates for this domain", "LOW", "dns")

    # --- Infrastructure ---
    if infrastructure:
        cdn = infrastructure.get("cdn", {})
        if not cdn.get("detected") and infrastructure.get("online"):
            ip = infrastructure.get("ip", "unknown")
            add(f"No CDN detected — origin server IP ({ip}) is directly exposed to the internet", "MEDIUM", "infrastructure")
        risky_ports = {21: "FTP", 23: "Telnet", 25: "SMTP", 445: "SMB",
                       3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                       5900: "VNC", 6379: "Redis", 27017: "MongoDB"}
        for port, service in risky_ports.items():
            if port in infrastructure.get("open_ports", []):
                add(f"Port {port} ({service}) is open — verify if internet exposure is intentional", "HIGH", "infrastructure")

    # --- Technology ---
    if technology and isinstance(technology, dict):
        high_risk_count = len(subdomains.get("high_risk_subdomains", []))
        for category, items in technology.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = item.get("name", "Unknown")
                version = item.get("version", "")
                label = f"{name} {version}".strip()
                if item.get("eol_risk"):
                    sev = "CRITICAL" if high_risk_count > 0 else "HIGH"
                    add(f"{label} has reached end-of-life and no longer receives security patches", sev, "technology")
                elif item.get("outdated"):
                    add(f"{label} is outdated — security patches available but not applied", "MEDIUM", "technology")

    # --- Exposure ---
    if exposed_assets:
        for asset in exposed_assets[:5]:  # Top 5 only to avoid noise
            if asset.get("severity") in ("CRITICAL", "HIGH"):
                add(
                    f"{asset['hostname']} — {asset['risk_reason']}",
                    asset["severity"],
                    "exposure",
                )

    # Sort by severity
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    issues.sort(key=lambda x: _order.get(x.get("severity", "LOW"), 3))

    return issues


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_risk_score(
    ssl: Optional[Dict] = None,
    fingerprint: Optional[Dict] = None,
    dns: Optional[Dict] = None,
    infrastructure: Optional[Dict] = None,
    technology: Optional[Dict] = None,
    subdomains: Optional[Dict] = None,
    exposed_assets: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Compute the overall risk score and risk issue list.

    Returns
    -------
    dict with:
      score           — 0 (critical risk) to 100 (best posture), int
      grade           — A / B / C / D / F
      category_scores — per-category breakdown
      risk_issues     — prioritised list of specific findings
    """
    ssl = ssl or {}
    fingerprint = fingerprint or {}
    dns = dns or {}
    infrastructure = infrastructure or {}
    technology = technology or {}
    subdomains = subdomains or {}
    exposed_assets = exposed_assets or []

    high_risk_sub_count = len(subdomains.get("high_risk_subdomains", []))

    # Per-category scores
    cat_scores = {
        "tls":            _score_tls(ssl),
        "web_security":   _score_web_security(fingerprint),
        "infrastructure": _score_infrastructure(infrastructure),
        "dns":            _score_dns(dns),
        "technology":     _score_technology(technology, high_risk_sub_count),
        "exposure":       _score_exposure(subdomains, exposed_assets),
    }

    # Weighted aggregate
    weighted = sum(cat_scores[cat] * weight for cat, weight in _WEIGHTS.items())
    final_score = round(_clamp(weighted))

    # Letter grade
    if final_score >= 90:
        grade = "A"
    elif final_score >= 75:
        grade = "B"
    elif final_score >= 60:
        grade = "C"
    elif final_score >= 40:
        grade = "D"
    else:
        grade = "F"

    risk_issues = _build_risk_issues(
        ssl, fingerprint, dns, infrastructure, technology, subdomains, exposed_assets
    )

    log.info(
        "Risk score calculated",
        extra={
            "score": final_score,
            "grade": grade,
            "issues": len(risk_issues),
        },
    )

    return {
        "score": final_score,
        "grade": grade,
        "category_scores": {k: round(v) for k, v in cat_scores.items()},
        "risk_issues": risk_issues,
    }
