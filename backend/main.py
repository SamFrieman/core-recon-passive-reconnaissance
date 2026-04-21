"""
CoreRecon v2.2 — Main Scan Orchestrator + API

Security hardening (v2.2.1):
  - CORS restricted to ALLOWED_ORIGINS env var (no wildcard)
  - Rate limiting via slowapi: 10/min on /recon/, 5/min on /report/
  - /api/v1/history and /api/v1/health gated behind X-Admin-Token header
  - Input validation: hard cap 253 chars, blocks injection chars
  - PDF filename sanitized
  - Internal errors not leaked to clients
"""
import io
import os
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.core.logger import get_logger
from backend.core.correlations import correlate_intelligence
from backend.core.asset_classifier import classify_assets
from backend.core.exposure import detect_exposed_assets, summarise_exposure
from backend.core.risk import calculate_risk_score
from backend.core.cache import scan_cache
from backend.core.errors import HardFailError
from backend.core.normalizer import normalize_target
from backend.core.sanitizer import sanitize_target, SanitizationError
from backend.db import init_db, save_scan, get_scan_history, get_scan_data, get_all_history
from backend.report import generate_pdf_report

log = get_logger("corerecon.main")

# ---------------------------------------------------------------------------
# Security configuration
# ---------------------------------------------------------------------------

_ADMIN_TOKEN = os.getenv("CORERECON_ADMIN_TOKEN", "")
_ALLOWED_ORIGINS_RAW = os.getenv("ALLOWED_ORIGINS", "")

if _ALLOWED_ORIGINS_RAW.strip():
    ALLOWED_ORIGINS = [o.strip() for o in _ALLOWED_ORIGINS_RAW.split(",") if o.strip()]
else:
    ALLOWED_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]
    log.warning(
        "ALLOWED_ORIGINS env var not set — defaulting to localhost only. "
        "Set ALLOWED_ORIGINS=https://yourdomain.com for production."
    )


def validate_scan_input(raw: str) -> str:
    """
    Thin wrapper: runs the full 8-layer sanitizer and converts
    SanitizationError into a FastAPI HTTPException 400.
    The safe client-facing reason is used; internal detail stays in logs.
    """
    try:
        return sanitize_target(raw)
    except SanitizationError as e:
        raise HTTPException(status_code=400, detail=e.reason)


async def require_admin(request: Request):
    """
    Dependency: enforces X-Admin-Token header.
    Returns 503 if admin token is not configured server-side.
    """
    if not _ADMIN_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Admin endpoints are not enabled on this instance"
        )
    token = request.headers.get("X-Admin-Token", "")
    if token != _ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------

def _import_module_fn(module_path: str, fn_name: str) -> Optional[Callable]:
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, fn_name)
    except (ImportError, AttributeError) as e:
        log.warning(f"Module unavailable: {module_path}.{fn_name} — {e}")
        return None


_get_infrastructure  = _import_module_fn("backend.modules.infrastructure",  "get_infrastructure")
_get_dns_records     = _import_module_fn("backend.modules.dns_intel",        "get_dns_records")
_fingerprint_target  = _import_module_fn("backend.modules.web_headers",      "get_security_headers")
_get_ssl_certificate = _import_module_fn("backend.modules.certificates",     "get_ssl_certificate")
_discover_subdomains = _import_module_fn("backend.modules.subdomains",       "discover_subdomains")
_query_wayback       = _import_module_fn("backend.modules.wayback",          "query_wayback")
_get_whois           = _import_module_fn("backend.modules.whois_intel",      "get_whois_data")
_detect_technology   = _import_module_fn("backend.modules.technology",       "get_technology_stack")


# ---------------------------------------------------------------------------
# Module Registry
# ---------------------------------------------------------------------------

@dataclass
class ModuleSpec:
    key: str
    fn: Optional[Callable]
    timeout_seconds: int
    description: str
    critical: bool = False

    def is_available(self) -> bool:
        return self.fn is not None


MODULE_REGISTRY: List[ModuleSpec] = [
    ModuleSpec("infrastructure",  _get_infrastructure,  25,  "IP resolution, ASN, CDN detection, port probing"),
    ModuleSpec("dns",             _get_dns_records,     20,  "DNS records, SPF, DMARC, DNSSEC analysis"),
    ModuleSpec("fingerprint",     _fingerprint_target,  15,  "HTTP headers, security posture, cookie analysis"),
    ModuleSpec("ssl_certificate", _get_ssl_certificate, 20,  "TLS certificate parsing and risk analysis"),
    ModuleSpec("subdomains",      _discover_subdomains, 60,  "Certificate transparency, passive subdomain discovery"),
    ModuleSpec("wayback",         _query_wayback,       30,  "Web archive history and path intelligence"),
    ModuleSpec("whois",           _get_whois,           20,  "Domain registration and registrar data"),
    ModuleSpec("technology",      _detect_technology,   20,  "Technology stack fingerprinting"),
]

MODULE_TIMEOUT_BUFFER = 15


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="CoreRecon API", version="2.2.2")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Request body size limit ──────────────────────────────────────────────────
# Prevents memory exhaustion from oversized payloads.
# CoreRecon is a GET-only API so legitimate bodies are always tiny.
# 16 KB is generous; a domain name is never more than 253 bytes.
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    max_body = 16_384  # 16 KB
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_body:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large"},
        )
    # Stream-check for chunked transfers that omit Content-Length
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_body:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
    return await call_next(request)


# ── Security response headers ────────────────────────────────────────────────
# Adds hardened headers to every API response.
# Mirrors what the scanner checks on target sites.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["Referrer-Policy"]         = "no-referrer"
    response.headers["X-XSS-Protection"]        = "0"          # modern browsers: CSP handles this
    response.headers["Permissions-Policy"]      = "geolocation=(), camera=(), microphone=()"
    response.headers["Cache-Control"]           = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    init_db()
    available = [m.key for m in MODULE_REGISTRY if m.is_available()]
    unavailable = [m.key for m in MODULE_REGISTRY if not m.is_available()]
    log.info(
        "CoreRecon startup complete",
        extra={
            "version": "2.2.2",
            "modules_available": available,
            "modules_unavailable": unavailable,
            "cors_origins": ALLOWED_ORIGINS,
            "admin_token_set": bool(_ADMIN_TOKEN),
        },
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "CoreRecon API",
        "version": "2.2.2",
        "modules": {m.key: m.is_available() for m in MODULE_REGISTRY},
    }


@app.get("/api/v1/health")
async def health(_: None = Depends(require_admin)):
    """Admin-only. Requires X-Admin-Token header."""
    return {
        "status": "healthy",
        "version": "2.2.2",
        "cache_size": len(scan_cache),
        "modules": {
            m.key: {"available": m.is_available(), "timeout": m.timeout_seconds}
            for m in MODULE_REGISTRY
        },
        "uptime": "ok",
    }


@app.get("/api/v1/recon/{domain:path}")
@limiter.limit("10/minute")
async def recon(request: Request, domain: str):
    validated = validate_scan_input(domain)

    try:
        normalized = normalize_target(validated)
        target = normalized.target
    except HardFailError as e:
        raise HTTPException(status_code=400, detail=str(e))

    cached = scan_cache.get(target)
    if cached:
        log.info("Cache hit", extra={"target": target})
        return JSONResponse(content=cached)

    try:
        result = run_scan(target)
    except HardFailError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error(f"Scan failed for {target}: {e}")
        raise HTTPException(status_code=500, detail="Scan failed. Please try again.")

    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["original_input"] = normalized.original_input
    result["input_type"] = normalized.input_type
    result["corerecon_version"] = "2.2.2"

    risk = result.get("risk", {})
    result["risk_score"] = risk.get("score", 0)
    result["risk_level"] = _score_to_level(risk.get("score", 0))
    result["risk_status"] = _risk_status_text(target, risk.get("score", 0))
    result["risk_issues"] = [i["issue"] for i in risk.get("risk_issues", [])]
    result["recommendations"] = _build_recommendations(risk.get("risk_issues", []))
    result["history_correlation"] = get_scan_history(target)

    save_scan(target, result)
    scan_cache.set(target, result)

    return JSONResponse(content=result)


@app.get("/api/v1/history")
async def history(_: None = Depends(require_admin)):
    """Admin-only. Requires X-Admin-Token header."""
    return get_all_history()


@app.get("/api/v1/report/{domain:path}")
@limiter.limit("5/minute")
async def report(request: Request, domain: str):
    validated = validate_scan_input(domain)

    try:
        normalized = normalize_target(validated)
        target = normalized.target
    except HardFailError as e:
        raise HTTPException(status_code=400, detail=str(e))

    data = scan_cache.get(target) or get_scan_data(target)

    if not data:
        try:
            data = run_scan(target)
            data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            risk = data.get("risk", {})
            data["risk_score"] = risk.get("score", 0)
            data["risk_level"] = _score_to_level(risk.get("score", 0))
            data["risk_status"] = _risk_status_text(target, risk.get("score", 0))
            data["risk_issues"] = [i["issue"] for i in risk.get("risk_issues", [])]
            data["recommendations"] = _build_recommendations(risk.get("risk_issues", []))
            save_scan(target, data)
            scan_cache.set(target, data)
        except Exception as e:
            log.error(f"Report generation failed for {target}: {e}")
            raise HTTPException(status_code=500, detail="Could not generate report")

    try:
        if "technology" in data:
            data["technology"] = _sanitize_technology_for_pdf(data["technology"])
        pdf_bytes = generate_pdf_report(data)
    except Exception as e:
        log.error(f"PDF generation failed for {target}: {e}")
        raise HTTPException(status_code=500, detail="PDF generation failed")

    safe_target = re.sub(r"[^a-zA-Z0-9_\-.]", "_", target)
    filename = f"corerecon_{safe_target}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# Concurrent executor
# ---------------------------------------------------------------------------

def _run_modules_concurrently(target: str) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, float]]:
    results: Dict[str, Any] = {}
    module_status: Dict[str, Any] = {}
    module_timings: Dict[str, float] = {}

    max_timeout = max(m.timeout_seconds for m in MODULE_REGISTRY) + MODULE_TIMEOUT_BUFFER

    with ThreadPoolExecutor(max_workers=len(MODULE_REGISTRY), thread_name_prefix="cr") as executor:
        future_map: Dict[Any, ModuleSpec] = {}

        for spec in MODULE_REGISTRY:
            if not spec.is_available():
                results[spec.key] = {"error": f"Module '{spec.key}' not available — import failed"}
                module_status[spec.key] = {"status": "UNAVAILABLE", "reason": "Import failed", "available": False}
                module_timings[spec.key] = 0
                continue
            future = executor.submit(spec.fn, target)
            future_map[future] = spec

        for future in as_completed(future_map, timeout=max_timeout):
            spec = future_map[future]
            t_start = time.monotonic()

            try:
                result = future.result(timeout=spec.timeout_seconds)
                elapsed = round(time.monotonic() - t_start, 2)
                results[spec.key] = result
                module_status[spec.key] = {"status": "OK", "reason": None, "available": True}
                module_timings[spec.key] = elapsed

            except FuturesTimeoutError:
                elapsed = round(spec.timeout_seconds, 2)
                results[spec.key] = {"error": f"Timed out after {spec.timeout_seconds}s"}
                module_status[spec.key] = {
                    "status": "TIMEOUT",
                    "reason": f"Exceeded {spec.timeout_seconds}s timeout",
                    "available": True,
                }
                module_timings[spec.key] = elapsed
                log.warning(f"Module '{spec.key}' timed out")

            except Exception as exc:
                elapsed = round(time.monotonic() - t_start, 2)
                results[spec.key] = {"error": "Module failed"}
                module_status[spec.key] = {
                    "status": "SOFT_FAIL",
                    "reason": str(exc)[:200],
                    "available": True,
                }
                module_timings[spec.key] = elapsed
                log.error(f"Module '{spec.key}' failed: {exc}")

    return results, module_status, module_timings


# ---------------------------------------------------------------------------
# Executive summary
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
    score = risk.get("score", 0)
    grade = risk.get("grade", "F")
    risk_issues = risk.get("risk_issues", [])

    key_risks = [
        {"finding": i.get("issue", ""), "severity": i.get("severity", ""), "category": i.get("category", "")}
        for i in risk_issues[:3]
    ]

    top_exposed = [
        {
            "hostname": a.get("hostname", ""),
            "type": a.get("exposure_type", ""),
            "severity": a.get("severity", ""),
            "reason": a.get("risk_reason", ""),
        }
        for a in exposed_assets[:3]
    ]

    infra_observations = []
    if infrastructure and not infrastructure.get("error"):
        cdn = infrastructure.get("cdn", {})
        if cdn.get("detected"):
            infra_observations.append(f"Traffic routed through {cdn.get('provider', 'a CDN')} — origin IP is shielded.")
        elif infrastructure.get("online"):
            infra_observations.append(f"No CDN detected — origin ({infrastructure.get('ip', 'unknown')}) is directly exposed.")
        if infrastructure.get("cloud_provider"):
            infra_observations.append(f"Hosted on {infrastructure['cloud_provider']}.")
        risky = [p for p in infrastructure.get("open_ports", []) if p in {21, 23, 3306, 5432, 6379, 27017, 3389, 5900}]
        if risky:
            infra_observations.append(f"{len(risky)} high-risk port(s) open: {', '.join(str(p) for p in risky[:5])}.")

    dns_assessment = []
    if dns:
        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        if spf.get("present") and dmarc.get("present") and dmarc.get("policy") in ("quarantine", "reject"):
            dns_assessment.append("Email authentication properly configured (SPF + DMARC enforced).")
        elif not spf.get("present") and not dmarc.get("present"):
            dns_assessment.append("No email authentication — domain freely spoofable for phishing.")
        elif not dmarc.get("present"):
            dns_assessment.append("SPF present but DMARC absent — From-header spoofing still possible.")
        elif dmarc.get("policy") == "none":
            dns_assessment.append("DMARC in monitor-only mode — email spoofing not actively blocked.")
        if dns.get("dnssec", {}).get("enabled"):
            dns_assessment.append("DNSSEC enabled — DNS responses cryptographically signed.")
        else:
            dns_assessment.append("DNSSEC not enabled — DNS responses cannot be authenticated.")

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

    critical_assets = [
        {"hostname": a["hostname"], "asset_type": a["asset_type"]}
        for a in asset_classification
        if a.get("risk_weight", 0) >= 85 and not a.get("is_root")
    ][:5]

    if score >= 80:
        posture = (f"{target} demonstrates a strong security posture (score {score}/100, grade {grade}). "
                   "Address remaining findings to reach optimal posture.")
    elif score >= 60:
        posture = (f"{target} has a moderate security posture (score {score}/100, grade {grade}). "
                   f"Several gaps across {len(key_risks)} risk area(s) should be prioritised.")
    elif score >= 40:
        posture = (f"{target} has a weak security posture (score {score}/100, grade {grade}). "
                   f"Immediate remediation recommended for "
                   f"{len([r for r in risk_issues if r.get('severity') in ('CRITICAL','HIGH')])} critical/high findings.")
    else:
        posture = (f"{target} has a critically weak security posture (score {score}/100, grade {grade}). "
                   "Urgent remediation required across TLS, email security, and exposure.")

    top_correlations = [
        {"type": c.get("correlation_type"), "description": c.get("description"), "severity": c.get("severity")}
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
        "high_risk_asset_types": critical_assets,
        "intelligence_highlights": top_correlations,
    }


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def run_scan(target: str) -> Dict[str, Any]:
    scan_start = time.monotonic()
    log.info("Scan started", extra={"target": target})

    module_results, module_status, module_timings = _run_modules_concurrently(target)

    infrastructure  = module_results.get("infrastructure",  {}) or {}
    dns             = module_results.get("dns",              {}) or {}
    fingerprint     = module_results.get("fingerprint",      {}) or {}
    ssl_certificate = module_results.get("ssl_certificate",  {}) or {}
    subdomains      = module_results.get("subdomains",       {}) or {}
    wayback         = module_results.get("wayback",          {}) or {}
    whois           = module_results.get("whois",            {}) or {}
    technology      = module_results.get("technology",       {}) or {}

    all_subdomain_names = subdomains.get("subdomains", [])
    wayback_subs = wayback.get("subdomains_discovered", [])
    combined_subs = list(set(all_subdomain_names + wayback_subs))

    exposed_assets = detect_exposed_assets(combined_subs, target)
    exposure_summary = summarise_exposure(exposed_assets)
    asset_classification = classify_assets(combined_subs, target)

    risk = calculate_risk_score(
        ssl=ssl_certificate,
        fingerprint=fingerprint,
        dns=dns,
        infrastructure=infrastructure,
        technology=technology,
        subdomains=subdomains,
        exposed_assets=exposed_assets,
    )

    correlations = correlate_intelligence({
        "target": target,
        "dns": dns,
        "infrastructure": infrastructure,
        "ssl_certificate": ssl_certificate,
        "subdomains": subdomains,
        "fingerprint": fingerprint,
        "technology": technology,
    })

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
            "module_statuses": {k: v["status"] for k, v in module_status.items()},
        },
    )

    return {
        "target": target,
        "scan_duration_seconds": scan_duration,
        "infrastructure":  infrastructure,
        "dns":             dns,
        "fingerprint":     fingerprint,
        "ssl_certificate": ssl_certificate,
        "subdomains":      subdomains,
        "wayback":         wayback,
        "whois":           whois,
        "technology":      technology,
        "risk":                      risk,
        "exposed_assets":            exposed_assets,
        "exposure_summary":          exposure_summary,
        "asset_classification":      asset_classification,
        "intelligence_correlations": correlations,
        "executive_summary":         executive_summary,
        "module_timings":  module_timings,
        "module_status":   module_status,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_to_level(score: int) -> str:
    if score >= 85: return "MINIMAL"
    if score >= 65: return "LOW"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "HIGH"
    return "CRITICAL"


def _risk_status_text(target: str, score: int) -> str:
    level = _score_to_level(score)
    return {
        "MINIMAL":  f"{target} demonstrates strong security hygiene. Few actionable findings.",
        "LOW":      f"{target} has a generally healthy posture with minor improvements recommended.",
        "MEDIUM":   f"{target} has several security gaps that should be addressed.",
        "HIGH":     f"{target} has significant vulnerabilities. Remediation strongly recommended.",
        "CRITICAL": f"{target} has critical security weaknesses requiring immediate attention.",
    }.get(level, "Assessment complete.")


def _sanitize_technology_for_pdf(technology: Any) -> dict:
    if not isinstance(technology, dict):
        return {}
    sanitized = {}
    for cat, items in technology.items():
        if not isinstance(items, list):
            continue
        clean_items = [
            i if isinstance(i, dict)
            else {"name": str(i), "version": "", "eol_risk": False, "eol_note": None}
            for i in items
        ]
        if clean_items:
            sanitized[cat] = clean_items
    return sanitized


def _build_recommendations(risk_issues: list) -> list:
    recs, seen = [], set()
    priority_map = {
        "tls":            "Upgrade TLS to 1.3 and ensure certificate validity.",
        "web_security":   "Implement HSTS, CSP, X-Frame-Options, and other security headers.",
        "dns":            "Configure SPF, DMARC (quarantine/reject), and enable DNSSEC.",
        "infrastructure": "Consider CDN placement and close unnecessary exposed ports.",
        "technology":     "Update all software to current supported versions.",
        "exposure":       "Review and restrict public access to sensitive subdomains.",
    }
    for issue in risk_issues:
        cat = issue.get("category", "")
        if cat not in seen and cat in priority_map:
            recs.append(priority_map[cat])
            seen.add(cat)
    return recs
