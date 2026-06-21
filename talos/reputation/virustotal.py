"""VirusTotal hash-reputation lookups (layer 3 of the identity ladder).

Free tier is 4 requests/minute, so we (a) cache every verdict on disk forever — a
binary's hash reputation doesn't change minute to minute — and (b) self-throttle to stay
under the limit. Lookups are by SHA-256 of the on-disk executable; we never upload files.
"""

from __future__ import annotations

import json
import threading
import time

import httpx

from ..config import REPUTATION_CACHE, ensure_cache_dir

_API = "https://www.virustotal.com/api/v3/files/{}"
_MIN_INTERVAL = 15.5  # seconds between calls -> ~4/min, free-tier safe
_lock = threading.Lock()
_last_call = [0.0]


class VirusTotal:
    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key
        self._cache = self._load()

    def _load(self) -> dict[str, dict]:
        if REPUTATION_CACHE.exists():
            try:
                return json.loads(REPUTATION_CACHE.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self) -> None:
        ensure_cache_dir()
        try:
            REPUTATION_CACHE.write_text(json.dumps(self._cache, indent=2))
        except OSError:
            pass

    def lookup(self, sha256: str | None) -> dict | None:
        """Return a normalized verdict dict, or None if unavailable.

        Shape: {malicious: int, suspicious: int, harmless: int, undetected: int,
                reputation: int, label: str, verdict: clean|suspicious|malicious|unknown}
        """

        if not sha256:
            return None
        if sha256 in self._cache:
            return self._cache[sha256]
        if not self.api_key:
            return None

        with _lock:
            elapsed = time.monotonic() - _last_call[0]
            if elapsed < _MIN_INTERVAL:
                time.sleep(_MIN_INTERVAL - elapsed)
            result = self._fetch(sha256)
            _last_call[0] = time.monotonic()

        if result is not None:
            self._cache[sha256] = result
            self._save()
        return result

    def _fetch(self, sha256: str) -> dict | None:
        try:
            resp = httpx.get(
                _API.format(sha256),
                headers={"x-apikey": self.api_key},
                timeout=15.0,
            )
        except httpx.HTTPError:
            return None
        if resp.status_code == 404:
            return {"verdict": "unknown", "label": "not in VirusTotal", "malicious": 0}
        if resp.status_code != 200:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        if malicious >= 1:
            verdict = "malicious"
        elif suspicious >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": int(attrs.get("reputation", 0)),
            "label": attrs.get("meaningful_name") or attrs.get("type_description") or "",
        }
