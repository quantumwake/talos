"""Persistent scan history — so previous scans survive a backend restart, and so each
new scan can be diffed against the last (active / inactive / new processes).

Each completed scan's portal payload is written to ``~/.talos/scans/`` as JSON.
Process identity across scans is ``(pid, int(create_time))`` — create_time disambiguates
PID reuse, so we never call a recycled PID "the same process".
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from .config import CACHE_DIR, ensure_cache_dir

SCANS_DIR = CACHE_DIR / "scans"


def _key(p: dict) -> tuple:
    return (p.get("pid"), int(p.get("create_time") or 0))


def persist_scan(payload: dict, max_keep: int = 30) -> str:
    ensure_cache_dir()
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    # Millisecond id so two scans in the same second don't collide (and still sort lexically).
    ms = int((payload.get("scanned_at") or time.time()) * 1000)
    sid = f"scan-{ms}"
    payload["id"] = sid
    (SCANS_DIR / f"{sid}.json").write_text(json.dumps(payload))
    files = sorted(SCANS_DIR.glob("scan-*.json"))
    for old in files[:-max_keep]:
        old.unlink(missing_ok=True)
    return sid


def list_scans() -> list[dict]:
    """Newest-first list of {id, scanned_at, summary} for the history picker."""

    out: list[dict] = []
    if not SCANS_DIR.exists():
        return out
    for f in sorted(SCANS_DIR.glob("scan-*.json"), reverse=True):
        try:
            d = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        out.append({
            "id": d.get("id", f.stem),
            "scanned_at": d.get("scanned_at"),
            "summary": d.get("summary"),
            "diff": {k: d.get("diff", {}).get(k) for k in ("active", "new", "inactive")},
        })
    return out


def load_scan(sid: str) -> Optional[dict]:
    f = SCANS_DIR / f"{sid}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def latest_scan() -> Optional[dict]:
    scans = list_scans()
    return load_scan(scans[0]["id"]) if scans else None


def diff_against_previous(curr_payload: dict, prev: Optional[dict]) -> dict:
    """Tag each current process active/new (in place) and return the delta vs ``prev``.

    - active:   in the previous scan AND still running now
    - new:      running now, not in the previous scan
    - inactive: in the previous scan, no longer running (returned as a list)
    """

    curr = curr_payload.get("processes", [])
    if not prev:
        for p in curr:
            p["state"] = "active"
        return {"baseline": True, "previous_at": None, "active": len(curr),
                "new": 0, "inactive": 0, "inactive_list": []}

    prev_procs = prev.get("processes", [])
    prev_keys = {_key(p) for p in prev_procs}
    curr_keys = {_key(p) for p in curr}
    active = new = 0
    for p in curr:
        if _key(p) in prev_keys:
            p["state"] = "active"
            active += 1
        else:
            p["state"] = "new"
            new += 1
    inactive_list = [p for p in prev_procs if _key(p) not in curr_keys]
    return {
        "baseline": False,
        "previous_at": prev.get("scanned_at"),
        "active": active,
        "new": new,
        "inactive": len(inactive_list),
        "inactive_list": inactive_list[:500],
    }
