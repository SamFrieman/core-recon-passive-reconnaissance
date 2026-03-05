"""
CoreRecon In-Memory Scan Cache
Prevents repeated hammering of external APIs for the same domain.
TTL of 5 minutes — configurable via env var.
"""
import os
import time
import threading
from typing import Any, Optional

# Cache TTL in seconds — default 5 minutes
CACHE_TTL = int(os.getenv("SCAN_CACHE_TTL", "300"))
# Max number of cached domains
CACHE_MAX_SIZE = int(os.getenv("SCAN_CACHE_MAX_SIZE", "100"))


class TTLCache:
    """
    Simple thread-safe in-memory cache with per-entry TTL.
    Uses a plain dict rather than a third-party dependency.
    """

    def __init__(self, maxsize: int = CACHE_MAX_SIZE, ttl: int = CACHE_TTL):
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self.maxsize = maxsize
        self.ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            # Evict oldest entries if at capacity
            if len(self._store) >= self.maxsize and key not in self._store:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
            self._store[key] = (value, time.monotonic() + self.ttl)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# Global scan result cache instance
scan_cache = TTLCache()
