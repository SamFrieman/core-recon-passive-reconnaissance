"""
CoreRecon Wayback Machine Archive Intelligence Module
Preserves v1 response structure exactly.
"""
from typing import Dict, Any, Optional

import requests

from backend.core.logger import get_logger

log = get_logger("corerecon.wayback")

TIMEOUT_PRIMARY = 15
TIMEOUT_CDX = 10


def _parse_timestamp(ts: str) -> str:
    """Convert YYYYMMDDHHmm to human-readable YYYY-MM-DD HH:MM."""
    if not ts or len(ts) < 12:
        return ts or "Unknown"
    try:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}"
    except Exception:
        return ts


def _get_snapshot_count(domain: str) -> Optional[int]:
    """CDX API call to get total snapshot count."""
    try:
        resp = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}&showNumPages=true",
            timeout=TIMEOUT_CDX,
        )
        if resp.status_code == 200:
            text = resp.text.strip()
            if text.isdigit():
                return int(text)
    except Exception as e:
        log.warning("CDX snapshot count failed", extra={"domain": domain, "error": str(e)})
    return None


def get_wayback_data(domain: str) -> Dict[str, Any]:
    """
    Query Wayback Machine for archive availability and snapshot metadata.
    Preserves v1 response structure exactly:
      available, archive_url, last_snapshot, last_snapshot_formatted,
      snapshot_status_code, total_snapshots
    """
    try:
        resp = requests.get(
            f"http://archive.org/wayback/available?url={domain}",
            timeout=TIMEOUT_PRIMARY,
        )

        if resp.status_code != 200:
            return {
                "available": False,
                "archive_url": None,
                "last_snapshot": None,
                "last_snapshot_formatted": "No archive found",
                "snapshot_status_code": None,
                "total_snapshots": None,
                "note": f"Wayback Machine returned status {resp.status_code}",
            }

        data = resp.json()
        closest = data.get("archived_snapshots", {}).get("closest", {})

        if not closest or not closest.get("available"):
            return {
                "available": False,
                "archive_url": None,
                "last_snapshot": None,
                "last_snapshot_formatted": "No archive found",
                "snapshot_status_code": None,
                "total_snapshots": 0,
                "note": "No archived snapshots found for this domain",
            }

        timestamp = closest.get("timestamp", "")
        archive_url = closest.get("url", "")
        status_code = closest.get("status", None)

        # Get total snapshot count via CDX
        total_snapshots = _get_snapshot_count(domain)

        result = {
            # --- v1 fields preserved exactly ---
            "available": True,
            "archive_url": archive_url,
            "last_snapshot": timestamp,
            "last_snapshot_formatted": _parse_timestamp(timestamp),
            "snapshot_status_code": int(status_code) if status_code and str(status_code).isdigit() else status_code,
            "total_snapshots": total_snapshots,
        }

        log.info(
            "Wayback data retrieved",
            extra={"domain": domain, "snapshots": total_snapshots, "last": timestamp},
        )
        return result

    except requests.Timeout:
        log.warning("Wayback Machine primary request timed out", extra={"domain": domain})
        return {
            "available": False,
            "archive_url": None,
            "last_snapshot": None,
            "last_snapshot_formatted": "Request timed out",
            "snapshot_status_code": None,
            "total_snapshots": None,
            "note": "Wayback Machine request timed out",
        }
    except Exception as e:
        log.warning("Wayback lookup failed", extra={"domain": domain, "error": str(e)})
        return {
            "available": False,
            "archive_url": None,
            "last_snapshot": None,
            "last_snapshot_formatted": "Unavailable",
            "snapshot_status_code": None,
            "total_snapshots": None,
            "note": f"Wayback Machine lookup failed: {str(e)[:100]}",
        }
