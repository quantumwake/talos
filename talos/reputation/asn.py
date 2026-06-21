"""Resolve remote IPs to an owning org/ASN so egress can be attributed.

Uses the free ip-api.com batch endpoint (no key, 15 req/s soft limit) with an on-disk
cache. Resolution is best-effort: failures just leave a connection unattributed, which
itself becomes an "unresolved-destination" flag in network.py.
"""

from __future__ import annotations

import json

import httpx

from ..config import CACHE_DIR, ensure_cache_dir, is_private_ip
from ..models import Connection

_ASN_CACHE_FILE = CACHE_DIR / "asn.json"
_BATCH_URL = "http://ip-api.com/batch"
_FIELDS = "status,message,query,as,org,isp,reverse"


def _load_cache() -> dict[str, dict]:
    if _ASN_CACHE_FILE.exists():
        try:
            return json.loads(_ASN_CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict[str, dict]) -> None:
    ensure_cache_dir()
    try:
        _ASN_CACHE_FILE.write_text(json.dumps(cache, indent=2))
    except OSError:
        pass


def resolve_connections(conns: list[Connection], timeout: float = 6.0) -> None:
    """Attach org/asn/rdns to each public-IP connection, in place."""

    cache = _load_cache()
    targets: list[str] = []
    for c in conns:
        ip = c.remote_ip
        if not ip or is_private_ip(ip):
            continue
        if ip in cache:
            _apply(c, cache[ip])
        elif ip not in targets:
            targets.append(ip)

    # ip-api batch accepts up to 100 IPs per call.
    for i in range(0, len(targets), 100):
        batch = targets[i : i + 100]
        try:
            resp = httpx.post(
                f"{_BATCH_URL}?fields={_FIELDS}",
                json=batch,
                timeout=timeout,
            )
            resp.raise_for_status()
            for row in resp.json():
                ip = row.get("query")
                if ip:
                    cache[ip] = row
        except (httpx.HTTPError, json.JSONDecodeError):
            continue

    for c in conns:
        ip = c.remote_ip
        if ip and ip in cache:
            _apply(c, cache[ip])
    _save_cache(cache)


def _apply(conn: Connection, row: dict) -> None:
    if row.get("status") != "success":
        return
    conn.asn = row.get("as") or None
    conn.org = row.get("org") or row.get("isp") or None
    rev = row.get("reverse")
    conn.rdns = rev or None
