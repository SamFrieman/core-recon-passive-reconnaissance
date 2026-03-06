"""
CoreRecon Intelligence Correlation Layer v2.1
Cross-module analysis to surface relationships between findings that individual
modules cannot see in isolation.

Each correlation includes:
  correlation_type  — machine-readable identifier
  description       — analyst-readable explanation derived from actual data
  severity          — CRITICAL / HIGH / MEDIUM / LOW
  affected_assets   — list of hostnames involved
"""
from typing import Any, Dict, List

from backend.core.logger import get_logger

log = get_logger("corerecon.correlations")


def _high_risk_subdomains(subdomains: Dict) -> List[Dict]:
    return subdomains.get("high_risk_subdomains", [])


def _sub_names(high_risk: List[Dict], limit: int = 5) -> List[str]:
    return [s["subdomain"] for s in high_risk[:limit]]


def _correlate_email_security(dns: Dict, target: str) -> List[Dict]:
    results = []
    spf = dns.get("spf", {})
    dmarc = dns.get("dmarc", {})

    if not spf.get("present") and not dmarc.get("present"):
        results.append({
            "correlation_type": "no_email_authentication",
            "description": (
                f"Neither SPF nor DMARC records are present. The domain @{target} "
                "can be freely spoofed in phishing campaigns with no technical barrier."
            ),
            "severity": "CRITICAL",
            "affected_assets": [target],
        })
    elif spf.get("present") and not dmarc.get("present"):
        results.append({
            "correlation_type": "spf_without_dmarc",
            "description": (
                "SPF is configured but DMARC is absent. SPF alone cannot prevent "
                f"From-header spoofing; without DMARC, attackers can still forge mail as @{target}."
            ),
            "severity": "HIGH",
            "affected_assets": [target],
        })
    elif dmarc.get("present") and dmarc.get("policy") == "none":
        spf_policy = spf.get("policy", "absent") if spf.get("present") else "absent"
        results.append({
            "correlation_type": "dmarc_monitor_only_no_enforcement",
            "description": (
                f"DMARC policy is 'none' (monitor-only) and SPF policy is '{spf_policy}'. "
                "Email spoofing protection is unenforced — DMARC must reach 'quarantine' "
                "or 'reject' to provide real protection."
            ),
            "severity": "MEDIUM",
            "affected_assets": [target],
        })

    return results


def _correlate_tls_subdomains(ssl: Dict, subdomains: Dict, target: str) -> List[Dict]:
    results = []
    if not ssl or ssl.get("error"):
        return results

    high_risk = _high_risk_subdomains(subdomains)

    if ssl.get("wildcard_cert") and high_risk:
        names = _sub_names(high_risk)
        results.append({
            "correlation_type": "wildcard_cert_over_high_risk_subdomains",
            "description": (
                f"A wildcard certificate is in use and {len(high_risk)} high-risk "
                f"subdomain(s) exist (e.g. {', '.join(names[:3])}). "
                "A single private-key compromise exposes all covered environments simultaneously."
            ),
            "severity": "MEDIUM",
            "affected_assets": [target] + names,
        })

    san_count = ssl.get("san_count", 0)
    if san_count > 20:
        results.append({
            "correlation_type": "large_san_count_shared_hosting_risk",
            "description": (
                f"The TLS certificate contains {san_count} Subject Alternative Names — "
                "a strong indicator of CDN-level certificate sharing or shared hosting. "
                "This domain may be co-located with unrelated third parties on the same cert."
            ),
            "severity": "LOW",
            "affected_assets": [target],
        })

    tls_risk = ssl.get("tls_risk", "LOW")
    if tls_risk in ("HIGH", "CRITICAL") and high_risk:
        names = _sub_names(high_risk)
        results.append({
            "correlation_type": "weak_tls_with_high_risk_subdomains",
            "description": (
                f"Deprecated TLS ({ssl.get('tls_version', 'unknown')}, risk: {tls_risk}) "
                f"is in use while {len(high_risk)} sensitive subdomains are exposed "
                f"(e.g. {', '.join(names[:3])}). Weak TLS on sensitive infrastructure "
                "creates a viable interception path."
            ),
            "severity": "HIGH",
            "affected_assets": [target] + names,
        })

    return results


def _correlate_technology_subdomains(technology: Dict, subdomains: Dict, target: str) -> List[Dict]:
    results = []
    if not technology or not isinstance(technology, dict):
        return results

    eol_techs = []
    for category, items in technology.items():
        if isinstance(items, list):
            for t in items:
                if isinstance(t, dict) and t.get("eol_risk"):
                    label = f"{t.get('name', 'Unknown')} {t.get('version', '')}".strip()
                    eol_techs.append(label)

    high_risk = _high_risk_subdomains(subdomains)
    if eol_techs and high_risk:
        names = _sub_names(high_risk)
        results.append({
            "correlation_type": "eol_software_on_exposed_asset",
            "description": (
                f"End-of-life software detected ({', '.join(eol_techs[:3])}) "
                f"on a domain that exposes {len(high_risk)} high-risk subdomain(s) "
                f"(e.g. {', '.join(names[:3])}). Unpatched software + exposed sensitive "
                "environments significantly expands the attack surface."
            ),
            "severity": "HIGH",
            "affected_assets": [target] + names,
        })

    return results


def _correlate_exposure_tls_headers(
    subdomains: Dict, ssl: Dict, fingerprint: Dict, target: str
) -> List[Dict]:
    results = []
    sensitive_keywords = {
        "admin", "internal", "dev", "staging", "jenkins", "db", "backup",
        "manage", "portal", "control", "intranet", "corp", "bastion", "vpn",
    }

    sensitive_subs = [
        s for s in subdomains.get("risk_classified", [])
        if s.get("risk_level") == "HIGH"
        and any(kw in s.get("subdomain", "").lower() for kw in sensitive_keywords)
    ]

    if not sensitive_subs:
        return results

    sub_names = [s["subdomain"] for s in sensitive_subs[:5]]
    ssl_risk = (ssl or {}).get("tls_risk", "UNKNOWN") if ssl and not ssl.get("error") else "UNKNOWN"
    header_grade = (fingerprint or {}).get("header_grade", "F")

    severity = None
    reason_parts = []

    if ssl_risk in ("HIGH", "CRITICAL"):
        severity = "CRITICAL" if ssl_risk == "CRITICAL" else "HIGH"
        reason_parts.append(f"TLS risk {ssl_risk}")

    if header_grade in ("D", "F"):
        severity = severity or "HIGH"
        reason_parts.append(f"header grade {header_grade}")

    if severity and reason_parts:
        results.append({
            "correlation_type": "sensitive_assets_weak_security_controls",
            "description": (
                f"{len(sensitive_subs)} sensitive infrastructure subdomain(s) are exposed "
                f"(e.g. {', '.join(sub_names[:3])}) while the root domain has weak security: "
                f"{'; '.join(reason_parts)}. Sensitive environments with poor controls "
                "are high-value, low-effort targets."
            ),
            "severity": severity,
            "affected_assets": sub_names,
        })

    return results


def _correlate_infrastructure_fragmentation(
    dns: Dict, infrastructure: Dict, target: str
) -> List[Dict]:
    results = []
    ns_provider = dns.get("ns_provider", "Unknown / Self-managed")
    cdn = infrastructure.get("cdn", {})
    cdn_provider = cdn.get("provider") if cdn.get("detected") else None

    if not cdn_provider or "Unknown" in ns_provider:
        return results

    ns_lower = ns_provider.lower()
    cdn_lower = cdn_provider.lower()
    cdn_keywords = [w for w in cdn_lower.split() if len(w) > 3]
    overlap = any(kw in ns_lower for kw in cdn_keywords)

    if not overlap:
        results.append({
            "correlation_type": "infrastructure_provider_fragmentation",
            "description": (
                f"DNS is managed by '{ns_provider}' while traffic routes through '{cdn_provider}'. "
                "Split-provider infrastructure increases operational complexity and misconfiguration "
                "risk during provider transitions or DNS propagation events."
            ),
            "severity": "LOW",
            "affected_assets": [target],
        })

    return results


def _correlate_ssl_not_enforced(ssl: Dict, fingerprint: Dict, target: str) -> List[Dict]:
    results = []
    if not ssl or ssl.get("error"):
        return results
    if not fingerprint or fingerprint.get("protocol") != "HTTP":
        return results

    results.append({
        "correlation_type": "ssl_cert_present_http_still_accessible",
        "description": (
            "A valid TLS certificate exists but the site is accessible over unencrypted HTTP. "
            "The certificate is not being enforced — HSTS is absent or misconfigured — "
            "allowing plaintext traffic interception."
        ),
        "severity": "HIGH",
        "affected_assets": [target],
    })
    return results


def _correlate_origin_exposure_with_sensitive_subs(
    infrastructure: Dict, subdomains: Dict, target: str
) -> List[Dict]:
    results = []
    cdn = infrastructure.get("cdn", {})
    if cdn.get("detected"):
        return results

    high_risk = _high_risk_subdomains(subdomains)
    if not high_risk:
        return results

    names = _sub_names(high_risk)
    ip = infrastructure.get("ip", "unknown")

    results.append({
        "correlation_type": "direct_origin_exposure_with_sensitive_subdomains",
        "description": (
            f"No CDN detected — origin IP ({ip}) is directly exposed — "
            f"and {len(high_risk)} sensitive subdomain(s) are publicly enumerable "
            f"(e.g. {', '.join(names[:3])}). Direct origin exposure combined with "
            "visible sensitive infrastructure simplifies targeted attacks."
        ),
        "severity": "MEDIUM",
        "affected_assets": [target] + names,
    })
    return results


def correlate_intelligence(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run all correlation checks across aggregated scan data.
    Returns deduplicated list of correlations sorted by severity.
    """
    target = scan_data.get("target", "unknown")
    dns = scan_data.get("dns", {}) or {}
    infrastructure = scan_data.get("infrastructure", {}) or {}
    ssl = scan_data.get("ssl_certificate", {}) or {}
    subdomains = scan_data.get("subdomains", {}) or {}
    fingerprint = scan_data.get("fingerprint", {}) or {}
    technology = scan_data.get("technology", {}) or {}

    all_correlations: List[Dict] = []

    for check_result in [
        _correlate_email_security(dns, target),
        _correlate_tls_subdomains(ssl, subdomains, target),
        _correlate_technology_subdomains(technology, subdomains, target),
        _correlate_exposure_tls_headers(subdomains, ssl, fingerprint, target),
        _correlate_infrastructure_fragmentation(dns, infrastructure, target),
        _correlate_ssl_not_enforced(ssl, fingerprint, target),
        _correlate_origin_exposure_with_sensitive_subs(infrastructure, subdomains, target),
    ]:
        all_correlations.extend(check_result)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_correlations.sort(key=lambda c: severity_order.get(c.get("severity", "LOW"), 3))

    log.info(
        "Intelligence correlation complete",
        extra={"target": target, "correlations_found": len(all_correlations)},
    )
    return all_correlations
