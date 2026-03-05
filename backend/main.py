"""
CoreRecon v2.0 — FastAPI Application Entry Point
Slim routing layer. All intelligence logic lives in backend/modules/ and backend/core/.
All v1 API endpoints preserved at identical paths.
"""
import os
import time
import warnings
from datetime import datetime

import urllib3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# Suppress SSL verification warnings for passive header checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

from backend.core.logger import get_logger
from backend.core.normalizer import normalize_target, sanitize_input
from backend.core.cache import scan_cache
from backend.core.risk import calculate_risk_score
from backend.core.errors import HardFailError, SoftFailError

from backend.modules.infrastructure import get_infrastructure_info
from backend.modules.dns_intel import get_dns_records
from backend.modules.subdomains import get_subdomains_passive
from backend.modules.web_headers import get_security_headers
from backend.modules.certificates import get_ssl_certificate
from backend.modules.whois_intel import get_whois_data
from backend.modules.wayback import get_wayback_data
from backend.modules.technology import get_technology_stack

from backend import db
from backend.report import generate_pdf_report  # PDF generator — unchanged from v1

log = get_logger("corerecon.main")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CoreRecon API",
    version="2.0.0",
    description="Passive OSINT reconnaissance intelligence platform",
)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    db.init_db()
    log.info("CoreRecon v2.0 started", extra={"version": "2.0.0"})


# ---------------------------------------------------------------------------
# Health check (new — additive)
# ---------------------------------------------------------------------------

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "ok",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "cache_size": len(scan_cache),
    }


# ---------------------------------------------------------------------------
# Primary recon endpoint — preserved at identical path
# ---------------------------------------------------------------------------

@app.get("/api/v1/recon/{domain:path}")
def recon(domain: str):
    start_time = time.monotonic()

    # --- Input normalization ---
    try:
        normalized = normalize_target(domain)
        clean_domain = normalized.target
    except HardFailError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")

    log.info("Scan initiated", extra={"domain": clean_domain, "original": normalized.original_input})

    # --- Cache check ---
    cache_key = f"scan:{clean_domain}"
    cached = scan_cache.get(cache_key)
    if cached:
        log.info("Cache hit", extra={"domain": clean_domain})
        return cached

    # --- Scan history (pre-scan) ---
    history_correlation = db.get_scan_history(clean_domain)

    # --- Module execution with per-module timing and soft-fail isolation ---
    module_timings: dict = {}
    module_status: dict = {}

    def run_module(name: str, fn, *args):
        """Execute a module, catch soft failures, record timing."""
        t0 = time.monotonic()
        try:
            result = fn(*args)
            module_timings[name] = round((time.monotonic() - t0) * 1000)
            module_status[name] = "OK"
            return result
        except HardFailError:
            raise  # Propagate — these abort the scan
        except Exception as e:
            module_timings[name] = round((time.monotonic() - t0) * 1000)
            module_status[name] = f"SOFT_FAIL: {str(e)[:80]}"
            log.warning(f"Module soft-failed: {name}", extra={"domain": clean_domain, "error": str(e)})
            return {}

    try:
        infrastructure   = run_module("infrastructure",   get_infrastructure_info,  clean_domain)
        dns              = run_module("dns",              get_dns_records,          clean_domain)
        subdomains       = run_module("subdomains",       get_subdomains_passive,   normalized.registered_domain)
        fingerprint      = run_module("fingerprint",      get_security_headers,     clean_domain)
        ssl_certificate  = run_module("ssl_certificate",  get_ssl_certificate,      clean_domain)
        whois            = run_module("whois",            get_whois_data,           normalized.registered_domain)
        wayback          = run_module("wayback",          get_wayback_data,         clean_domain)
        technology       = run_module("technology",       get_technology_stack,     clean_domain)

    except HardFailError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error("Scan failed unexpectedly", extra={"domain": clean_domain, "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Reconnaissance failed: {str(e)}")

    # --- Risk scoring ---
    scan_data_for_risk = {
        "ssl_certificate": ssl_certificate,
        "fingerprint": fingerprint,
        "infrastructure": infrastructure,
        "dns": dns,
        "technology": technology,
    }
    risk = calculate_risk_score(scan_data_for_risk)

    total_time = round((time.monotonic() - start_time) * 1000)

    # --- Assemble response (all v1 keys + v2 additions) ---
    result = {
        # v1 top-level fields — preserved exactly
        "target":             clean_domain,
        "timestamp":          datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "infrastructure":     infrastructure,
        "dns":                dns,
        "subdomains":         subdomains,
        "fingerprint":        fingerprint,
        "ssl_certificate":    ssl_certificate,
        "whois":              whois,
        "wayback":            wayback,
        "technology":         technology,
        "history_correlation": history_correlation,
        # v1 risk fields — preserved exactly
        "risk_score":         risk["score"],
        "risk_level":         risk["level"],
        "risk_status":        risk["status"],
        "risk_issues":        risk["issues"],
        "recommendations":    risk["recommendations"],
        # v2 additions
        "risk_breakdown":     risk["risk_breakdown"],
        "risk_confidence":    risk["risk_confidence"],
        "module_timings":     module_timings,
        "module_status":      module_status,
        "scan_duration_ms":   total_time,
        "corerecon_version":  "2.0.0",
    }

    # --- Persist and cache ---
    db.save_scan(clean_domain, result)
    scan_cache.set(cache_key, result)

    log.info(
        "Scan complete",
        extra={
            "domain": clean_domain,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "duration_ms": total_time,
        },
    )
    return result


# ---------------------------------------------------------------------------
# History endpoint — preserved at identical path
# ---------------------------------------------------------------------------

@app.get("/api/v1/history")
def history():
    scans = db.get_all_history(limit=50)
    return {"scans": scans}


# ---------------------------------------------------------------------------
# PDF report endpoint — preserved at identical path
# ---------------------------------------------------------------------------

@app.get("/api/v1/report/{domain:path}")
def report(domain: str):
    try:
        clean = sanitize_input(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan_data = db.get_scan_data(clean)

    # v1 fallback: try www variant, then fuzzy match
    if not scan_data:
        alt = f"www.{clean}" if not clean.startswith("www.") else clean[4:]
        scan_data = db.get_scan_data(alt)

    if not scan_data:
        raise HTTPException(
            status_code=404,
            detail=f"No scan found for '{domain}'. Run a scan first via /api/v1/recon/{domain}",
        )

    try:
        pdf_bytes = generate_pdf_report(scan_data)
    except Exception as e:
        log.error("PDF generation failed", extra={"domain": clean, "error": str(e)})
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"CoreRecon_{clean}_{timestamp}.pdf"

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
