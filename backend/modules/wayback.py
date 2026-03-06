"""
CoreRecon Wayback Machine Module v2.1
Queries the Internet Archive CDX API to discover historically indexed URLs,
exposed paths, and technology leakage from archived snapshots.

v2.1 stability improvements:
  - Tighter request timeout (8s down from default)
  - Retry logic with backoff
  - Rate-limit awareness (HTTP 429 handling)
  - Hard cap on results to prevent memory bloat on large sites
"""
import time
from collections import defaultdict
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

import requests

from backend.core.logger import get_logger

log = get_logger("corerecon.wayback")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT  = 8     # tighter than default — Wayback can hang
_RETRY_ATTEMPTS   = 2     # fewer retries — Wayback is optional intelligence
_RETRY_BACKOFF    = 2.0
_RATE_LIMIT_PAUSE = 6.0
_MAX_RESULTS      = 500   # cap CDX results to avoid processing bloat

_SENSITIVE_EXTENSIONS = {
    ".env", ".sql", ".bak", ".backup", ".tar", ".tar.gz", ".zip",
    ".gz", ".log", ".cfg", ".conf", ".config", ".yml", ".yaml",
    ".ini", ".pem", ".key", ".p12", ".pfx", ".crt",
}

_SENSITIVE_PATH_FRAGMENTS = {
    "/admin", "/administrator", "/manage", "/management", "/control",
    "/backup", "/db", "/database", "/dump", "/export",
    "/config", "/conf", "/.env", "/.git", "/api/v", "/graphql",
    "/wp-admin", "/phpmyadmin", "/jenkins", "/actuator",
    "/swagger", "/openapi", "/.well-known/security.txt",
}

_INTERESTING_MIME_TYPES = {
    "application/json", "text/xml", "application/xml",
    "application/javascript", "text/plain",
}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get_with_retry(url: str, params: Dict = None) -> requests.Response:
    """GET with retry and 429 handling. Raises on exhaustion."""
    headers = {"User-Agent": "CoreRecon/2.1 (+https://github.com/corerecon)"}
    last_exc: Exception = RuntimeError("No attempts made")

    for attempt in range(_RETRY_ATTEMPTS):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=_REQUEST_TIMEOUT)

            if resp.status_code == 429:
                log.warning("Wayback rate limit hit", extra={"pause": _RATE_LIMIT_PAUSE})
                time.sleep(_RATE_LIMIT_PAUSE)
                continue

            return resp

        except Exception as exc:
            last_exc = exc
            if attempt < _RETRY_ATTEMPTS - 1:
                time.sleep(_RETRY_BACKOFF)

    raise last_exc


# ---------------------------------------------------------------------------
# CDX query
# ---------------------------------------------------------------------------

def _query_cdx(target: str) -> List[Dict[str, str]]:
    """
    Query the Wayback CDX API for archived URLs of target.
    Returns list of {url, mime_type, status_code, timestamp}.
    """
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url":        f"*.{target}/*",
        "output":     "json",
        "fl":         "original,mimetype,statuscode,timestamp",
        "collapse":   "urlkey",
        "limit":      _MAX_RESULTS,
        "filter":     "statuscode:200",
    }

    try:
        resp = _get_with_retry(url, params=params)
        if resp.status_code != 200:
            log.warning("CDX API non-200", extra={"status": resp.status_code})
            return []

        data = resp.json()
        if len(data) < 2:
            return []   # First row is header

        headers = data[0]
        results = []
        for row in data[1:]:
            entry = dict(zip(headers, row))
            results.append(entry)

        return results

    except Exception as exc:
        log.warning("CDX query failed", extra={"target": target, "error": str(exc)})
        return []


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _is_sensitive_path(url: str) -> bool:
    """Check if a URL path looks sensitive."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        ext = "." + path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
        if ext in _SENSITIVE_EXTENSIONS:
            return True
        for fragment in _SENSITIVE_PATH_FRAGMENTS:
            if fragment in path:
                return True
    except Exception:
        pass
    return False


def _extract_insights(records: List[Dict[str, str]], target: str) -> Dict[str, Any]:
    """
    Analyse CDX records to extract actionable intelligence.
    """
    subdomains_seen: Set[str] = set()
    sensitive_paths: List[str] = []
    api_endpoints: List[str] = []
    tech_hints: List[str] = []
    path_counts: Dict[str, int] = defaultdict(int)

    for record in records:
        url = record.get("original", "")
        mime = record.get("mimetype", "")

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            path = parsed.path

            if hostname and target in hostname and hostname != target:
                subdomains_seen.add(hostname.lower())

            # Sensitive paths
            if _is_sensitive_path(url):
                normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if normalized not in sensitive_paths:
                    sensitive_paths.append(normalized)

            # API endpoints
            if "/api/" in path or "/graphql" in path or "/v1/" in path or "/v2/" in path:
                ep = f"{parsed.netloc}{path}"
                if ep not in api_endpoints:
                    api_endpoints.append(ep)

            # Technology hints from interesting MIME types on non-HTML responses
            if mime in _INTERESTING_MIME_TYPES:
                if "/graphql" in path:
                    tech_hints.append("GraphQL API")
                elif "/api/" in path and mime == "application/json":
                    tech_hints.append("REST API (JSON)")
                elif mime in ("text/xml", "application/xml"):
                    tech_hints.append("XML/SOAP service")

            # Path frequency (hot paths)
            top_path = "/" + path.strip("/").split("/")[0] if path.strip("/") else "/"
            path_counts[top_path] += 1

        except Exception:
            continue

    # Top 10 most-archived paths
    top_paths = sorted(path_counts.items(), key=lambda x: -x[1])[:10]

    return {
        "subdomains_discovered": sorted(subdomains_seen),
        "sensitive_paths": sensitive_paths[:20],
        "api_endpoints_found": list(set(api_endpoints))[:20],
        "technology_hints": list(set(tech_hints)),
        "top_archived_paths": [{"path": p, "count": c} for p, c in top_paths],
        "total_records_analysed": len(records),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def query_wayback(target: str) -> Dict[str, Any]:
    """
    Query the Wayback Machine CDX API and extract intelligence from historical
    snapshots of the target domain and its subdomains.

    Returns
    -------
    dict with:
      available                 — bool (whether any data was found)
      total_snapshots           — int
      subdomains_discovered     — list of subdomains seen in archive URLs
      sensitive_paths           — list of archived sensitive-looking paths
      api_endpoints_found       — list of archived API endpoint paths
      technology_hints          — tech indicators from archived content
      top_archived_paths        — most frequently archived paths
      total_records_analysed    — how many CDX records were processed
    """
    records = _query_cdx(target)

    if not records:
        log.info("No Wayback Machine data available", extra={"target": target})
        return {
            "available": False,
            "total_snapshots": 0,
            "subdomains_discovered": [],
            "sensitive_paths": [],
            "api_endpoints_found": [],
            "technology_hints": [],
            "top_archived_paths": [],
            "total_records_analysed": 0,
        }

    insights = _extract_insights(records, target)

    log.info(
        "Wayback Machine analysis complete",
        extra={
            "target": target,
            "records": len(records),
            "sensitive_paths": len(insights["sensitive_paths"]),
            "subdomains": len(insights["subdomains_discovered"]),
        },
    )

    return {
        "available": True,
        "total_snapshots": len(records),
        **insights,
    }
