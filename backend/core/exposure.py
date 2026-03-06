"""
CoreRecon Exposure Intelligence Module v2.1
Enhanced detection of exposed infrastructure with confidence scoring
and granular exposure classification.

Each exposed asset record includes:
  hostname        — the detected hostname
  exposure_type   — classification of what kind of exposure this is
  risk_reason     — analyst-readable explanation
  confidence      — HIGH / MEDIUM / LOW (how certain the detection is)
  severity        — CRITICAL / HIGH / MEDIUM / LOW
"""
import re
from typing import Any, Dict, List, Optional

from backend.core.logger import get_logger

log = get_logger("corerecon.exposure")


# ---------------------------------------------------------------------------
# Exposure pattern definitions
# Each entry: (exposure_type, pattern, confidence, severity, risk_reason_template)
# ---------------------------------------------------------------------------

_EXPOSURE_PATTERNS = [
    (
        "database_interface",
        re.compile(r"(^|\.)(phpmyadmin|adminer|pgadmin|mysql|mongo-?express|redis-?commander|db|database)(\.|\.|$)", re.I),
        "HIGH",
        "CRITICAL",
        "Database management interface exposed — direct database access vector if authentication is weak or absent.",
    ),
    (
        "vpn_gateway",
        re.compile(r"(^|\.)(vpn|remote|bastion|jump|gateway|citrix|pulse|anyconnect|fortigate|sslvpn)(\.|\.|$)", re.I),
        "HIGH",
        "CRITICAL",
        "VPN or remote access gateway exposed — primary target for credential attacks and network intrusion.",
    ),
    (
        "admin_panel",
        re.compile(r"(^|\.)(admin|administrator|wp-admin|cpanel|webmin|plesk|manage|mgmt|control-panel|portal)(\.|\.|$)", re.I),
        "HIGH",
        "HIGH",
        "Administrative panel exposed — high-value target for credential brute-force and privilege escalation.",
    ),
    (
        "devops_tooling",
        re.compile(r"(^|\.)(jenkins|jira|confluence|gitlab|github|bitbucket|sonarqube|nexus|artifactory|teamcity|bamboo|circle-?ci|travis)(\.|\.|$)", re.I),
        "HIGH",
        "HIGH",
        "DevOps tooling exposed — contains source code, secrets, CI/CD pipelines and deployment credentials.",
    ),
    (
        "monitoring_dashboard",
        re.compile(r"(^|\.)(grafana|prometheus|kibana|datadog|splunk|zabbix|nagios|prtg|opsgenie|alertmanager|elk)(\.|\.|$)", re.I),
        "HIGH",
        "HIGH",
        "Monitoring dashboard exposed — leaks infrastructure topology, metrics, and alert configurations.",
    ),
    (
        "authentication_service",
        re.compile(r"(^|\.)(auth|login|sso|oauth|identity|sts|keycloak|okta|adfs|ldap|saml)(\.|\.|$)", re.I),
        "MEDIUM",
        "HIGH",
        "Authentication service exposed — central identity infrastructure is a critical attack target.",
    ),
    (
        "development_environment",
        re.compile(r"(^|\.)(dev|develop|development|sandbox|local|test|testing|qa|uat|sit|staging|stage|stg|preprod)(\.|\.|$)", re.I),
        "HIGH",
        "MEDIUM",
        "Development or staging environment publicly accessible — often holds production-equivalent data and weaker security controls.",
    ),
    (
        "backup_or_file_service",
        re.compile(r"(^|\.)(backup|bak|archive|ftp|sftp|files|uploads|storage|nas|s3|blob|share)(\.|\.|$)", re.I),
        "MEDIUM",
        "HIGH",
        "Backup or file service exposed — potential source of credential dumps, source code, and sensitive data.",
    ),
    (
        "internal_infrastructure",
        re.compile(r"(^|\.)(internal|intranet|corp|corporate|private|secure|dmz|mgmt|infra|lan)(\.|\.|$)", re.I),
        "MEDIUM",
        "HIGH",
        "Internal infrastructure subdomain publicly enumerable — indicates network segmentation boundary leakage.",
    ),
    (
        "mail_infrastructure",
        re.compile(r"(^|\.)(mail|smtp|imap|pop3|webmail|exchange|autodiscover|mx)(\.|\.|$)", re.I),
        "LOW",
        "MEDIUM",
        "Mail infrastructure exposed — enables targeted phishing, relay testing, and user enumeration.",
    ),
    (
        "api_endpoint",
        re.compile(r"(^|\.)(api|api-v\d|graphql|rest|gql|rpc|v\d)(\.|\.|$)", re.I),
        "LOW",
        "MEDIUM",
        "API endpoint exposed — API surface requires authentication review and input validation audit.",
    ),
]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _classify_exposure(hostname: str) -> Optional[Dict[str, str]]:
    """
    Test a hostname against all exposure patterns.
    Returns the first (highest-priority) match or None.
    """
    for exposure_type, pattern, confidence, severity, risk_reason in _EXPOSURE_PATTERNS:
        if pattern.search(hostname):
            return {
                "exposure_type": exposure_type,
                "confidence": confidence,
                "severity": severity,
                "risk_reason": risk_reason,
            }
    return None


def detect_exposed_assets(
    subdomains: List[str],
    target: str,
    existing_exposed: Optional[List[Dict]] = None,
) -> List[Dict[str, Any]]:
    """
    Scan all discovered subdomains for exposure patterns.

    Parameters
    ----------
    subdomains : list of str
        Fully-qualified hostnames discovered during the scan.
    target : str
        The root scan target (used to filter out the root itself).
    existing_exposed : list, optional
        Pre-existing exposed asset records from earlier modules —
        these will be merged and deduplicated.

    Returns
    -------
    list of dicts sorted by severity (CRITICAL first), then confidence.

    Each record:
      hostname      — the hostname
      exposure_type — what kind of asset this is
      risk_reason   — analyst-readable explanation
      confidence    — HIGH / MEDIUM / LOW
      severity      — CRITICAL / HIGH / MEDIUM / LOW
      source        — "pattern_match" | "inherited"
    """
    seen: set = set()
    results: List[Dict[str, Any]] = []

    # Absorb any pre-existing exposure records
    if existing_exposed:
        for record in existing_exposed:
            h = record.get("hostname", "")
            if h and h not in seen:
                seen.add(h)
                results.append({**record, "source": "inherited"})

    # Pattern-match all subdomains
    for hostname in subdomains:
        if not hostname or hostname == target or hostname in seen:
            continue

        match = _classify_exposure(hostname)
        if match:
            seen.add(hostname)
            results.append(
                {
                    "hostname": hostname,
                    "exposure_type": match["exposure_type"],
                    "risk_reason": match["risk_reason"],
                    "confidence": match["confidence"],
                    "severity": match["severity"],
                    "source": "pattern_match",
                }
            )

    # Sort: primary = severity, secondary = confidence, tertiary = hostname
    results.sort(
        key=lambda r: (
            _SEVERITY_ORDER.get(r.get("severity", "LOW"), 3),
            _CONFIDENCE_ORDER.get(r.get("confidence", "LOW"), 2),
            r.get("hostname", ""),
        )
    )

    log.info(
        "Exposure detection complete",
        extra={
            "target": target,
            "subdomains_scanned": len(subdomains),
            "exposed_assets_found": len(results),
        },
    )
    return results


def summarise_exposure(exposed_assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produce aggregate exposure statistics for use in the executive summary
    and risk engine.

    Returns dict with:
      total           — total exposed asset count
      critical_count  — assets with CRITICAL severity
      high_count      — assets with HIGH severity
      by_type         — dict mapping exposure_type → count
      highest_severity— overall highest severity found (or None)
    """
    if not exposed_assets:
        return {
            "total": 0,
            "critical_count": 0,
            "high_count": 0,
            "by_type": {},
            "highest_severity": None,
        }

    by_type: Dict[str, int] = {}
    critical = 0
    high = 0

    for asset in exposed_assets:
        sev = asset.get("severity", "LOW")
        if sev == "CRITICAL":
            critical += 1
        elif sev == "HIGH":
            high += 1
        etype = asset.get("exposure_type", "unknown")
        by_type[etype] = by_type.get(etype, 0) + 1

    # Determine highest severity
    if critical:
        highest = "CRITICAL"
    elif high:
        highest = "HIGH"
    elif any(a.get("severity") == "MEDIUM" for a in exposed_assets):
        highest = "MEDIUM"
    else:
        highest = "LOW"

    return {
        "total": len(exposed_assets),
        "critical_count": critical,
        "high_count": high,
        "by_type": by_type,
        "highest_severity": highest,
    }
