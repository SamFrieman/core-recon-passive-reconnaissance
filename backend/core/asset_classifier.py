"""
CoreRecon Asset Classification Module v2.1
Identifies and categorizes discovered subdomains by asset type.
Enables risk scoring to weight assets differently based on sensitivity.

Asset types:
  public_web, api_endpoint, authentication_portal, development_environment,
  staging_environment, vpn_gateway, mail_service, devops_tooling,
  database_service, monitoring_service, file_service, admin_panel, unknown
"""
import re
from typing import Any, Dict, List

from backend.core.logger import get_logger

log = get_logger("corerecon.asset_classifier")

# Ordered from most specific to least — first match wins
_ASSET_PATTERNS: List[tuple] = [
    ("database_service",        re.compile(r"(^|\.)(?:db|database|mysql|postgres|mongo|redis|elastic|phpmyadmin|sql)(\.|$)", re.I)),
    ("vpn_gateway",             re.compile(r"(^|\.)(?:vpn|remote|bastion|jump|gateway|citrix|pulse|rdp|ssh)(\.|$)", re.I)),
    ("admin_panel",             re.compile(r"(^|\.)(?:admin|administrator|manage|management|control|panel|cp|cpanel|webmin|wp-admin)(\.|$)", re.I)),
    ("authentication_portal",   re.compile(r"(^|\.)(?:auth|login|sso|oauth|identity|account|signin|signup|id)(\.|$)", re.I)),
    ("devops_tooling",          re.compile(r"(^|\.)(?:jenkins|jira|confluence|gitlab|github|bitbucket|sonar|nexus|artifactory|ci|cd|build|deploy|teamcity|bamboo)(\.|$)", re.I)),
    ("monitoring_service",      re.compile(r"(^|\.)(?:grafana|prometheus|nagios|zabbix|datadog|splunk|elk|kibana|monitoring|metrics|logs|apm|sentry)(\.|$)", re.I)),
    ("development_environment", re.compile(r"(^|\.)(?:dev|develop|development|sandbox|local|test|testing|qa|uat|sit)(\.|$)", re.I)),
    ("staging_environment",     re.compile(r"(^|\.)(?:staging|stage|stg|preprod|pre-prod|demo)(\.|$)", re.I)),
    ("api_endpoint",            re.compile(r"(^|\.)(?:api|api-v\d|graphql|rest|soap|gql|rpc|v\d)(\.|$)", re.I)),
    ("mail_service",            re.compile(r"(^|\.)(?:mail|smtp|imap|pop|webmail|mx|email|exchange|autodiscover)(\.|$)", re.I)),
    ("file_service",            re.compile(r"(^|\.)(?:ftp|sftp|files|uploads|backup|bak|archive|storage|nas|share)(\.|$)", re.I)),
    ("cdn_asset_server",        re.compile(r"(^|\.)(?:cdn|assets|static|media|images|img|js|css|fonts|s3|blob)(\.|$)", re.I)),
    ("public_web",              re.compile(r"(^|\.)(?:www|web|site|home|blog|forum|community|shop|store|docs|help|support)(\.|$)", re.I)),
]

# Risk weight used by the scoring engine to prioritize assets
# Higher = more security-sensitive
ASSET_RISK_WEIGHT: Dict[str, int] = {
    "database_service":        95,
    "vpn_gateway":             90,
    "admin_panel":             90,
    "devops_tooling":          85,
    "authentication_portal":   85,
    "development_environment": 80,
    "staging_environment":     75,
    "monitoring_service":      70,
    "file_service":            75,
    "api_endpoint":            70,
    "mail_service":            60,
    "cdn_asset_server":        30,
    "public_web":              20,
    "unknown":                 40,
}


def classify_asset_type(hostname: str) -> str:
    """Classify a single hostname into an asset type."""
    for asset_type, pattern in _ASSET_PATTERNS:
        if pattern.search(hostname):
            return asset_type
    return "unknown"


def classify_assets(subdomains: List[str], target: str) -> List[Dict[str, Any]]:
    """
    Classify all discovered subdomains plus the root target.

    Returns a list of asset classification records sorted by risk_weight
    descending (highest risk first) to surface critical assets immediately.

    Each record:
      hostname    — the fully qualified hostname
      asset_type  — classification string
      risk_weight — 0-100 sensitivity score
      is_root     — True if this is the scan target itself
    """
    classified: List[Dict[str, Any]] = []

    # Root target defaults to public_web unless naming suggests otherwise
    root_type = classify_asset_type(target)
    if root_type == "unknown":
        root_type = "public_web"

    classified.append({
        "hostname": target,
        "asset_type": root_type,
        "risk_weight": ASSET_RISK_WEIGHT.get(root_type, 20),
        "is_root": True,
    })

    for sub in subdomains:
        if not sub or sub == target:
            continue
        asset_type = classify_asset_type(sub)
        classified.append({
            "hostname": sub,
            "asset_type": asset_type,
            "risk_weight": ASSET_RISK_WEIGHT.get(asset_type, 40),
            "is_root": False,
        })

    # Sort highest-risk first
    classified.sort(key=lambda x: x["risk_weight"], reverse=True)

    log.info(
        "Asset classification complete",
        extra={
            "target": target,
            "total_assets": len(classified),
            "unique_types": len(set(a["asset_type"] for a in classified)),
        },
    )
    return classified
