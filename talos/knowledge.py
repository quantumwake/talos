"""Curated known-process database: load, match, and learn.

This is layer 2 of the identity ladder — the local source of human-readable "what is
this / what's it for". LLM verdicts (layer 4) are written back here so the database
self-improves across runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

import yaml

from .config import KNOWN_PROCESSES_FILE, LLM_CACHE, ensure_cache_dir
from .models import Category


@dataclass
class KnownEntry:
    name: str
    description: str
    vendor: Optional[str] = None
    category: Category = Category.UNKNOWN
    safe_to_kill: bool = False
    name_pattern: Optional[str] = None
    path_contains: Optional[str] = None
    source: str = "known_db"


class KnowledgeBase:
    def __init__(self) -> None:
        self._exact: dict[str, KnownEntry] = {}
        self._patterns: list[KnownEntry] = []
        self._llm_cache: dict[str, dict] = {}
        self._load_curated()
        self._load_llm_cache()

    def _load_curated(self) -> None:
        if not KNOWN_PROCESSES_FILE.exists():
            return
        data = yaml.safe_load(KNOWN_PROCESSES_FILE.read_text()) or {}
        for raw in data.get("processes", []):
            entry = KnownEntry(
                name=raw["name"],
                description=raw.get("description", ""),
                vendor=raw.get("vendor"),
                category=Category(raw.get("category", "unknown")),
                safe_to_kill=bool(raw.get("safe_to_kill", False)),
                name_pattern=raw.get("name_pattern"),
                path_contains=raw.get("path_contains"),
            )
            if entry.name_pattern:
                self._patterns.append(entry)
            else:
                self._exact[entry.name] = entry

    def _load_llm_cache(self) -> None:
        if LLM_CACHE.exists():
            try:
                self._llm_cache = json.loads(LLM_CACHE.read_text())
            except (json.JSONDecodeError, OSError):
                self._llm_cache = {}

    def lookup(self, name: str, exe: Optional[str]) -> Optional[KnownEntry]:
        """Match precedence: exact name (+ path) → name_pattern substring."""

        entry = self._exact.get(name)
        if entry:
            if entry.path_contains and exe:
                if entry.path_contains in exe:
                    return entry
            else:
                return entry
        lname = name.lower()
        for pat in self._patterns:
            assert pat.name_pattern is not None
            if pat.name_pattern.lower() in lname or (
                exe and pat.name_pattern.lower() in exe.lower()
            ):
                return pat
        return None

    # ---- LLM verdict cache (keyed by binary sha256 or name|exe) ----
    def llm_key(self, name: str, exe: Optional[str], sha256: Optional[str]) -> str:
        return sha256 or f"{name}|{exe or ''}"

    def get_llm(self, key: str) -> Optional[dict]:
        return self._llm_cache.get(key)

    def put_llm(self, key: str, verdict: dict) -> None:
        self._llm_cache[key] = verdict
        ensure_cache_dir()
        try:
            LLM_CACHE.write_text(json.dumps(self._llm_cache, indent=2))
        except OSError:
            pass
