"""
CoreRecon Database Abstraction Layer
SQLite is the default and remains fully supported.
PostgreSQL is available via DATABASE_URL env var — optional, additive.

v2.2.1: All domain parameters sanitized via sanitize_db_param before
        being passed to queries. Primary defence is always parameterised
        queries (?/%s placeholders); sanitize_db_param is a secondary layer.
"""
import os
import stat
import json
import sqlite3
import ipaddress

class _JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address,
                            ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return str(obj)
        return super().default(obj)

from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.core.logger import get_logger
from backend.core.sanitizer import sanitize_db_param, SanitizationError

log = get_logger("corerecon.db")

DB_PATH = os.getenv("DB_PATH", "recon_history.db")
DATABASE_URL = os.getenv("DATABASE_URL", None)

_USE_POSTGRES = bool(DATABASE_URL and DATABASE_URL.startswith("postgresql"))


# ---------------------------------------------------------------------------
# SQLite backend (default)
# ---------------------------------------------------------------------------

@contextmanager
def _sqlite_conn():
    """Context manager for SQLite connections with WAL mode for better concurrency."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    if _USE_POSTGRES:
        _pg_init()
        return

    with _sqlite_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                domain TEXT PRIMARY KEY,
                data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                scan_count INTEGER DEFAULT 1
            )
        """)

    # Lock down the DB file to owner read/write only (chmod 600).
    # Prevents other OS users on the same host reading scan history.
    # Safe to call repeatedly — only changes mode, never fails if already set.
    try:
        os.chmod(DB_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        log.warning("Could not set DB file permissions", extra={"path": DB_PATH, "error": str(e)})

    log.info("Database initialized", extra={"backend": "sqlite", "path": DB_PATH})


def save_scan(domain: str, data: Dict[str, Any]) -> None:
    """Upsert a scan result. Increments scan_count on repeat scans."""
    # Secondary defence: sanitize before parameterised query
    try:
        domain = sanitize_db_param(domain)
    except SanitizationError as e:
        log.warning("save_scan rejected unsafe domain", extra={"reason": e.reason})
        return

    if _USE_POSTGRES:
        _pg_save_scan(domain, data)
        return

    try:
        with _sqlite_conn() as conn:
            conn.execute("""
                INSERT INTO scans (domain, data, scan_count)
                VALUES (?, ?, 1)
                ON CONFLICT(domain)
                DO UPDATE SET
                    data = excluded.data,
                    timestamp = CURRENT_TIMESTAMP,
                    scan_count = scan_count + 1
            """, (domain, json.dumps(data, cls=_JSONEncoder)))
    except sqlite3.OperationalError as e:
        log.warning("Failed to save scan to database", extra={"domain": domain, "error": str(e)})


def get_scan_history(domain: str) -> Dict[str, Any]:
    """Retrieve lightweight history metadata for a domain."""
    try:
        domain = sanitize_db_param(domain)
    except SanitizationError as e:
        log.warning("get_scan_history rejected unsafe domain", extra={"reason": e.reason})
        return {"error": "Invalid domain parameter"}

    if _USE_POSTGRES:
        return _pg_get_history(domain)

    try:
        with _sqlite_conn() as conn:
            cur = conn.execute(
                "SELECT scan_count, timestamp FROM scans WHERE domain = ?", (domain,)
            )
            row = cur.fetchone()
    except sqlite3.OperationalError as e:
        log.warning("History lookup failed", extra={"domain": domain, "error": str(e)})
        return {"error": "History unavailable"}

    if row:
        return {
            "previous_scans": row[0],
            "last_scan": row[1],
            "status": "REPEAT_TARGET" if row[0] > 1 else "FIRST_SCAN",
        }
    return {"previous_scans": 0, "status": "NEW_TARGET"}


def get_scan_data(domain: str) -> Optional[Dict[str, Any]]:
    """Retrieve full scan data blob for the report endpoint."""
    try:
        domain = sanitize_db_param(domain)
    except SanitizationError as e:
        log.warning("get_scan_data rejected unsafe domain", extra={"reason": e.reason})
        return None

    if _USE_POSTGRES:
        return _pg_get_scan_data(domain)

    try:
        with _sqlite_conn() as conn:
            cur = conn.execute("SELECT data FROM scans WHERE domain = ?", (domain,))
            row = cur.fetchone()
            if row:
                return json.loads(row[0])
    except (sqlite3.OperationalError, json.JSONDecodeError) as e:
        log.warning("Scan data retrieval failed", extra={"domain": domain, "error": str(e)})
    return None


def get_all_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent scan history for the history endpoint."""
    if _USE_POSTGRES:
        return _pg_get_all_history(limit)

    try:
        with _sqlite_conn() as conn:
            # limit is an int from our own code — no user input, safe to interpolate
            cur = conn.execute(
                "SELECT domain, timestamp, scan_count FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = cur.fetchall()
        return [
            {"domain": r[0], "last_scan": r[1], "total_scans": r[2]}
            for r in rows
        ]
    except sqlite3.OperationalError as e:
        log.warning("History list failed", extra={"error": str(e)})
        return []


# ---------------------------------------------------------------------------
# PostgreSQL backend (optional — activated when DATABASE_URL is set)
# ---------------------------------------------------------------------------

def _pg_init() -> None:
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                domain TEXT PRIMARY KEY,
                data JSONB,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                scan_count INTEGER DEFAULT 1
            )
        """)
        conn.commit()
        conn.close()
        log.info("Database initialized", extra={"backend": "postgresql"})
    except Exception as e:
        log.error("PostgreSQL init failed", extra={"error": str(e)})
        raise


def _pg_save_scan(domain: str, data: Dict[str, Any]) -> None:
    try:
        import psycopg2
        from psycopg2.extras import Json
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scans (domain, data, scan_count) VALUES (%s, %s, 1)
            ON CONFLICT (domain) DO UPDATE SET
                data = EXCLUDED.data,
                timestamp = NOW(),
                scan_count = scans.scan_count + 1
        """, (domain, Json(data)))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("PostgreSQL save failed", extra={"domain": domain, "error": str(e)})


def _pg_get_history(domain: str) -> Dict[str, Any]:
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("SELECT scan_count, timestamp FROM scans WHERE domain = %s", (domain,))
        row = cur.fetchone()
        conn.close()
        if row:
            return {
                "previous_scans": row[0],
                "last_scan": str(row[1]),
                "status": "REPEAT_TARGET" if row[0] > 1 else "FIRST_SCAN",
            }
    except Exception as e:
        log.warning("PostgreSQL history lookup failed", extra={"error": str(e)})
    return {"previous_scans": 0, "status": "NEW_TARGET"}


def _pg_get_scan_data(domain: str) -> Optional[Dict[str, Any]]:
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("SELECT data FROM scans WHERE domain = %s", (domain,))
        row = cur.fetchone()
        conn.close()
        if row:
            return row[0]
    except Exception as e:
        log.warning("PostgreSQL data retrieval failed", extra={"error": str(e)})
    return None


def _pg_get_all_history(limit: int) -> List[Dict[str, Any]]:
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute(
            "SELECT domain, timestamp, scan_count FROM scans ORDER BY timestamp DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
        conn.close()
        return [{"domain": r[0], "last_scan": str(r[1]), "total_scans": r[2]} for r in rows]
    except Exception as e:
        log.warning("PostgreSQL history list failed", extra={"error": str(e)})
        return []
