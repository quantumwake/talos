"""Persistent learned store — remember what we've figured out about each process.

Two jobs:
  1. **Memory.** Every analysis (curated, VirusTotal, or an LLM eval) is recorded keyed by
     the binary's SHA-256 (falling back to name|path), with first-seen / last-analyzed
     dates. So an expensive LLM verdict for, say, `fairplayd` is remembered — next scan
     shows the same description without re-asking, and without re-flagging it.
  2. **User decisions.** An explicit acknowledge / do-not-kill list. Once you tell the tool
     "I know what this is, leave it alone", that's authoritative and survives restarts.

Writes are batched: callers mutate in memory and call ``flush()`` once (the engine does
this at the end of a scan) so a 900-process scan isn't 900 file writes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .config import LEARNED_STORE, ensure_cache_dir
from .models import ProcessInfo, Verdict


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def entry_key(name: str, exe: Optional[str], sha256: Optional[str] = None) -> str:
    """Stable identity for a binary: name|path.

    We deliberately key by path, not by hash: a normal scan doesn't hash every binary
    (that's slow for ~900 processes), so a hash-based key would differ between a scan and
    an acknowledge/inspect that *did* hash. The SHA-256 is still stored as a field on the
    entry (for integrity/display) — it just isn't the lookup key.
    """

    return f"{name}|{exe or ''}"


class LearnedStore:
    def __init__(self) -> None:
        self._data: dict[str, dict] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if LEARNED_STORE.exists():
            try:
                self._data = json.loads(LEARNED_STORE.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def flush(self) -> None:
        if not self._dirty:
            return
        ensure_cache_dir()
        try:
            LEARNED_STORE.write_text(json.dumps(self._data, indent=2, sort_keys=True))
            self._dirty = False
        except OSError:
            pass

    def get(self, key: str) -> Optional[dict]:
        return self._data.get(key)

    def all(self) -> list[dict]:
        return list(self._data.values())

    # ---- record an analysis (memory) ----
    def record(self, proc: ProcessInfo, verdict: Verdict, key: str) -> None:
        sha = proc.signing.sha256 if proc.signing else None
        existing = self._data.get(key, {})
        ts = now_iso()
        entry = {
            "key": key,
            "name": proc.name,
            "exe": proc.exe,
            "sha256": sha or existing.get("sha256"),
            "description": verdict.description,
            "vendor": verdict.vendor,
            "category": verdict.category.value,
            "safe_to_kill": verdict.safe_to_kill,
            "source": verdict.source,
            "first_seen": existing.get("first_seen", ts),
            "last_analyzed": ts,
            "analyses": existing.get("analyses", 0) + 1,
            "user": existing.get("user"),  # preserve any user override
        }
        # Don't overwrite a confident prior description with a weaker "unknown".
        if verdict.source in ("heuristic", "self") and existing.get("source") not in (
            None, "heuristic", "self",
        ):
            entry["description"] = existing.get("description", entry["description"])
            entry["category"] = existing.get("category", entry["category"])
            entry["source"] = existing.get("source", entry["source"])
        self._data[key] = entry
        self._dirty = True

    # ---- user decisions (authoritative) ----
    def set_user(
        self,
        key: str,
        *,
        acknowledged: bool = True,
        do_not_kill: bool = True,
        category: Optional[str] = None,
        note: Optional[str] = None,
        name: Optional[str] = None,
        exe: Optional[str] = None,
        sha256: Optional[str] = None,
    ) -> dict:
        entry = self._data.get(key) or {
            "key": key, "name": name, "exe": exe, "sha256": sha256,
            "first_seen": now_iso(), "analyses": 0,
        }
        entry["user"] = {
            "acknowledged": acknowledged,
            "do_not_kill": do_not_kill,
            "category": category,
            "note": note,
            "set_at": now_iso(),
        }
        self._data[key] = entry
        self._dirty = True
        self.flush()
        return entry

    def clear_user(self, key: str) -> bool:
        entry = self._data.get(key)
        if entry and entry.get("user"):
            entry["user"] = None
            self._dirty = True
            self.flush()
            return True
        return False
