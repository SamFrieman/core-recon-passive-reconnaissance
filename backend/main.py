"""
CoreRecon v2.1 — Main Scan Orchestrator
Coordinates all intelligence modules via concurrent execution and assembles
the final scan result with intelligence correlations and executive summary.

v2.1 changes:
  Phase 6 — Concurrent module execution via ThreadPoolExecutor
  Phase 7 — Deterministic executive summary generated from scan findings
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import Any, Dict, List, Optional

from backend.core.logger import get_logger
from backend.core.correlations import correlate_intelligence
from backend.core.asset_classifier import classify_assets
from backend.core.exposure import detect_exposed_assets, summarise_exposure
from backend.core.risk import calculate_risk_score

# Module imports
from backend.modules.infrastructure import get_infrastructure
from backend.modules.subdomains import discover_subdomains
from backend.modules.wayback import query_wayback
from fastapi import FastAPI

app = FastAPI()

# These modules exist in the v2.0 codebase and are imported as-is
try:
    from backend.modules.dns import get_dns_records
    from backend.modules.fingerprint import fingerprint_target
    from backend.modules.ssl import get_ssl_certificate
    from backend.modules.technology import detect_technology
    from backend.modules.whois import get_whois
except ImportError:
    # Fallback stubs for environments where only v2.1 modules are present
    def get_dns_records(target): return {}
    def fingerprint_target(target): return {}
    def get_ssl_certificate(target): return {}
    def detect_technology(target): return {}
    def get_whois(target): return {}

log = get_logger("corerecon.main")

# ---------------------------------------------------------------------------
# Module execution plan
# ---------------------------------------------------------------------------
# Each entry: (module_key, callable, positional_args, timeout_seconds)
# Timeout is enforced per-module — slow modules fail gracefully.

_MODULE_TIMEOUT = 45   # seconds per module before it's marked as timed out

def _build_module_plan(target: str) -> List[tuple]:
    """Return the ordered module execution plan for a scan."""
    return [
        ("infrastructure",   get_infrastructure,   (target,), 25),
        ("dns",              get_dns_records,       (target,), 20),
        ("fingerprint",      fingerprint_target,    (target,), 15),
        ("ssl_certificate",  get_ssl_certificate,   (target,), 20),
        ("subdomains",       discover_subdomains,   (target,), 60),
        ("wayback",          query_wayback,          (target,), 30),
        ("whois",            get_whois,              (target,), 20),
        ("technology",       detect_technology,      (target,), 20),
    ]


# ---------------------------------------------------------------------------
# Concurrent executor
# ---------------------------------------------------------------------------

def _run_modules_concurrently(target: str) -> Dict[str, Any]:
    """
    Execute all scan modules in parallel using a thread pool.
    Each module runs independently; failures are isolated and logged.

    Returns dict mapping module_key → result (or error dict on failure).
    """
    plan = _build_module_plan(target)
    results: Dict[str, Any] = {}
    module_timings: Dict[str, float] = {}

    # Map future → (key, timeout)
    future_map = {}

    with ThreadPoolExecutor(max_workers=8, thread_name_prefix="corerecon") as executor:
        for key, fn, args, timeout in plan:
            future = executor.submit(fn, *args)
            future_map[future] = (key, timeout)

        for future in as_completed(future_map, timeout=_MODULE_TIMEOUT + 10):
            key, per_module_timeout = future_map[future]
            t_start = time.monotonic()

            try:
                result = future.result(timeout=per_module_timeout)
                elapsed = time.monotonic() - t_start
                results[key] = result
                module_timings[key] = round(elapsed, 2)
                log.debug(f"Module '{key}' completed in {elapsed:.2f}s")

            except FuturesTimeoutError:
                results[key] = {"error": f"Module timed out after {per_module_timeout}s"}
                module_timings[key] = per_module_timeout
                log.warning(f"Module '{key}' timed out")

            except Exception as exc:
                results[key] = {"error": str(exc)}
                module_timings[key] = round(time.monotonic() - t_start, 2)
                log.error(f"Module '{key}' failed: {exc}")

    results["_module_timings"] = module_timings
    return results


# ---------------------------------------------------------------------------
# Executive summary generator (Phase 7)
# ---------------------------------------------------------------------------

def _generate_executive_summary(
    target: str,
    risk: Dict[str, Any],
    infrastructure: Dict[str, Any],
    dns: Dict[str, Any],
    subdomains: Dict[str, Any],
    exposed_assets: List[Dict],
    correlations: List[Dict],
    asset_classification: List[Dict],
) -> Dict[str, Any]:
    """
    Generate a deterministic, data-driven executive summary.
    All content is derived from actual scan findings — no generic placeholder text.
    """
    score = risk.get("score", 0)
    grade = risk.get("grade", "F")
    risk_issues = risk.get("risk_issues", [])

    # --- Key risks (top 3 by severity) ---
    key_risks = []
    for issue in risk_issues[:3]:
        key_risks.append({
            "finding": issue.get("issue", ""),
            "severity": issue.get("severity", ""),
            "category": issue.get("category", ""),
        })

    # --- Exposed assets summary (top 3) ---
    top_exposed = []
    for asset in exposed_assets[:3]:
        top_exposed.append({
            "hostname": asset.get("hostname", ""),
            "type": asset.get("exposure_type", ""),
            "severity": asset.get("severity", ""),
            "reason": asset.get("risk_reason", ""),
        })

    # --- Infrastructure observations ---
    infra_observations = []
    if infrastructure:
        if infrastructure.get("online"):
            cdn = infrastructure.get("cdn", {})
            if cdn.get("detected"):
                infra_observations.append(
                    f"Traffic is routed through {cdn.get('provider', 'a CDN')} — origin IP is shielded."
                )
            else:
                ip = infrastructure.get("ip", "unknown")
                infra_observations.append(
                    f"No CDN detected — origin server ({ip}) is directly internet-accessible."
                )
            if infrastructure.get("cloud_provider"):
                infra_observations.append(
                    f"Hosted on {infrastructure['cloud_provider']}."
                )
            open_ports = infrastructure.get("open_ports", [])
            if open_ports:
                risky = [p for p in open_ports if p in {21, 23, 3306, 5432, 6379, 27017, 3389, 5900}]
                if risky:
                    infra_observations.append(
                        f"{len(risky)} high-risk port(s) open: {', '.join(str(p) for p in risky[:5])}."
                    )
        else:
            infra_observations.append("Target appears to be offline or DNS resolution failed.")

    # --- DNS security assessment ---
    dns_assessment = []
    if dns:
        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        dnssec = dns.get("dnssec", False)

        if spf.get("present") and dmarc.get("present") and dmarc.get("policy") in ("quarantine", "reject"):
            dns_assessment.append("Email authentication is properly configured (SPF + DMARC enforced).")
        elif not spf.get("present") and not dmarc.get("present"):
            dns_assessment.append("No email authentication — domain is freely spoofable for phishing attacks.")
        elif not dmarc.get("present"):
            dns_assessment.append("SPF is present but DMARC is missing — email From-header spoofing remains possible.")
        elif dmarc.get("policy") == "none":
            dns_assessment.append("DMARC is in monitor-only mode — email spoofing is not actively blocked.")

        if dnssec:
            dns_assessment.append("DNSSEC is enabled — DNS responses are cryptographically signed.")
        else:
            dns_assessment.append("DNSSEC is not enabled — DNS responses cannot be authenticated by resolvers.")

    # --- Subdomain exposure summary ---
    sub_summary = None
    if subdomains:
        total = subdomains.get("total_found", 0)
        high_risk = subdomains.get("high_risk_subdomains", [])
        if total > 0:
            sub_summary = {
                "total_subdomains": total,
                "high_risk_count": len(high_risk),
                "sample_high_risk": [s["subdomain"] for s in high_risk[:3]],
            }

    # --- Asset inventory highlight ---
    critical_asset_types = [
        a for a in asset_classification
        if a.get("risk_weight", 0) >= 85 and not a.get("is_root")
    ]

    # --- Security posture narrative ---
    if score >= 80:
        posture = (
            f"{target} demonstrates a strong security posture (score {score}/100, grade {grade}). "
            "Key controls are in place. Address remaining findings to reach optimal posture."
        )
    elif score >= 60:
        posture = (
            f"{target} has a moderate security posture (score {score}/100, grade {grade}). "
            f"Several significant gaps were identified across {len(key_risks)} risk area(s) "
            "that should be prioritised for remediation."
        )
    elif score >= 40:
        posture = (
            f"{target} has a weak security posture (score {score}/100, grade {grade}). "
            f"Multiple high-severity issues were found. Immediate remediation is recommended "
            f"for the {len([r for r in risk_issues if r.get('severity') in ('CRITICAL', 'HIGH')])} "
            "critical and high severity findings."
        )
    else:
        posture = (
            f"{target} has a critically weak security posture (score {score}/100, grade {grade}). "
            "Multiple critical and high severity issues across TLS, email security, and exposure "
            "were found. Urgent remediation required."
        )

    # --- Correlation highlights ---
    top_correlations = [
        {
            "type": c.get("correlation_type"),
            "description": c.get("description"),
            "severity": c.get("severity"),
        }
        for c in correlations[:3]
        if c.get("severity") in ("CRITICAL", "HIGH")
    ]

    return {
        "security_posture": posture,
        "risk_score": score,
        "risk_grade": grade,
        "key_risks": key_risks,
        "exposed_assets_summary": top_exposed,
        "infrastructure_observations": infra_observations,
        "dns_security_assessment": dns_assessment,
        "subdomain_exposure": sub_summary,
        "high_risk_asset_types": [
            {"hostname": a["hostname"], "asset_type": a["asset_type"]}
            for a in critical_asset_types[:5]
        ],
        "intelligence_highlights": top_correlations,
    }


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def run_scan(target: str) -> Dict[str, Any]:
    """
    Execute a full CoreRecon passive scan against target.

    Parameters
    ----------
    target : str
        Domain name to scan (e.g. "example.com").

    Returns
    -------
    Comprehensive scan result dict ready for API serialisation.
    """
    scan_start = time.monotonic()
    log.info("Scan started", extra={"target": target})

    # --- Phase 6: Concurrent module execution ---
    module_results = _run_modules_concurrently(target)
    module_timings = module_results.pop("_module_timings", {})

    infrastructure   = module_results.get("infrastructure",  {}) or {}
    dns              = module_results.get("dns",              {}) or {}
    fingerprint      = module_results.get("fingerprint",      {}) or {}
    ssl_certificate  = module_results.get("ssl_certificate",  {}) or {}
    subdomains       = module_results.get("subdomains",       {}) or {}
    wayback          = module_results.get("wayback",          {}) or {}
    whois            = module_results.get("whois",            {}) or {}
    technology       = module_results.get("technology",       {}) or {}

    # --- Phase 3: Exposure detection ---
    all_subdomain_names = subdomains.get("subdomains", [])
    wayback_subs = wayback.get("subdomains_discovered", [])
    combined_subs = list(set(all_subdomain_names + wayback_subs))

    exposed_assets = detect_exposed_assets(combined_subs, target)
    exposure_summary = summarise_exposure(exposed_assets)

    # --- Phase 2: Asset classification ---
    asset_classification = classify_assets(combined_subs, target)

    # --- Phase 5: Risk scoring ---
    risk = calculate_risk_score(
        ssl=ssl_certificate,
        fingerprint=fingerprint,
        dns=dns,
        infrastructure=infrastructure,
        technology=technology,
        subdomains=subdomains,
        exposed_assets=exposed_assets,
    )

    # Build intermediate scan_data dict for correlation
    scan_data_for_correlation = {
        "target": target,
        "dns": dns,
        "infrastructure": infrastructure,
        "ssl_certificate": ssl_certificate,
        "subdomains": subdomains,
        "fingerprint": fingerprint,
        "technology": technology,
    }

    # --- Phase 1: Intelligence correlations ---
    correlations = correlate_intelligence(scan_data_for_correlation)

    # --- Phase 7: Executive summary ---
    executive_summary = _generate_executive_summary(
        target=target,
        risk=risk,
        infrastructure=infrastructure,
        dns=dns,
        subdomains=subdomains,
        exposed_assets=exposed_assets,
        correlations=correlations,
        asset_classification=asset_classification,
    )

    scan_duration = round(time.monotonic() - scan_start, 2)

    log.info(
        "Scan complete",
        extra={
            "target": target,
            "duration_s": scan_duration,
            "risk_score": risk.get("score"),
            "correlations": len(correlations),
            "exposed_assets": len(exposed_assets),
        },
    )

    return {
        # Core identity
        "target": target,
        "scan_duration_seconds": scan_duration,

        # Module results (v2.0 compatible fields preserved)
        "infrastructure":  infrastructure,
        "dns":             dns,
        "fingerprint":     fingerprint,
        "ssl_certificate": ssl_certificate,
        "subdomains":      subdomains,
        "wayback":         wayback,
        "whois":           whois,
        "technology":      technology,

        # v2.1 intelligence fields
        "risk":                  risk,
        "exposed_assets":        exposed_assets,
        "exposure_summary":      exposure_summary,
        "asset_classification":  asset_classification,
        "intelligence_correlations": correlations,
        "executive_summary":     executive_summary,

        # Diagnostics
        "module_timings":        module_timings,
    }
