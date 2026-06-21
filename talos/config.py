"""Configuration, protected-process allowlist, and on-disk cache locations.

Everything tunable lives here so the CLI, API and tests share one source of truth.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

CACHE_DIR = Path(os.environ.get("TALOS_HOME", Path.home() / ".talos"))
REPUTATION_CACHE = CACHE_DIR / "reputation.json"
LLM_CACHE = CACHE_DIR / "llm_verdicts.json"
LEARNED_STORE = CACHE_DIR / "learned.json"
AUDIT_LOG = CACHE_DIR / "audit.log"

DATA_DIR = Path(__file__).parent / "data"
KNOWN_PROCESSES_FILE = DATA_DIR / "known_processes.yaml"

# Hardcoded last line of defence. These are NEVER killed regardless of verdict,
# flags, or --force. Matched by exact process name. The protected-by-PID rule
# (pid 0/1) is enforced separately in actions.py.
PROTECTED_NAMES: frozenset[str] = frozenset(
    {
        "kernel_task",
        "launchd",
        "logd",
        "WindowServer",
        "loginwindow",
        "SystemUIServer",
        "Dock",
        "Finder",
        "coreaudiod",
        "configd",
        "powerd",
        "hidd",
        "opendirectoryd",
        "securityd",
        "syslogd",
        "diskarbitrationd",
        "notifyd",
        "distnoted",
        "cfprefsd",
        "mds",
        "mds_stores",
        "bluetoothd",
        "WindowManager",
        "universalaccessd",
        "amfid",
        "trustd",
        "nsurlsessiond",
        "watchdogd",
        "thermalmonitord",
    }
)

# Ports we consider "normal" outbound. Anything else is worth a second look but is
# not damning on its own.
COMMON_EGRESS_PORTS: frozenset[int] = frozenset(
    {53, 80, 110, 143, 443, 465, 587, 853, 993, 995, 5223, 8080, 8443}
)

# RFC1918 / loopback / link-local are treated as "local" egress (not internet).
PRIVATE_CIDRS = ("10.", "192.168.", "127.", "::1", "fe80:", "169.254.")
for _i in range(16, 32):  # 172.16.0.0/12
    PRIVATE_CIDRS = PRIVATE_CIDRS + (f"172.{_i}.",)


@dataclass
class Settings:
    """Per-run knobs. Constructed by the CLI/API from flags."""

    use_llm: bool = False          # call Claude for unknowns (fallback only)
    use_virustotal: bool = False   # hash-reputation lookups (needs VT_API_KEY)
    collect_network: bool = True   # gather + flag per-process connections
    resolve_asn: bool = True       # remote IP -> org/ASN (needs network egress)
    # A process must score at least this confident before --auto-terminate-safe
    # will touch it.
    min_kill_confidence: float = 0.85
    # Resource thresholds that bump risk / flag "hog".
    cpu_hog_percent: float = 60.0
    mem_hog_mb: float = 1500.0
    # Risk tier cutoffs (score -> tier).
    tier_cutoffs: dict[str, int] = field(
        default_factory=lambda: {"medium": 30, "high": 55, "critical": 80}
    )
    vt_api_key: str | None = field(default_factory=lambda: os.environ.get("VT_API_KEY"))
    anthropic_api_key: str | None = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY")
    )
    # Default to the most capable model for accurate verdicts on unknown binaries.
    # Override via --llm-model (e.g. claude-haiku-4-5 for cheaper/faster fallback).
    llm_model: str = "claude-opus-4-8"
    llm_effort: str = "low"  # this is a constrained classification — low effort is plenty
    llm_web_search: bool = False  # let Claude search the web for binaries it doesn't know
    # How to reach Claude: "auto" prefers the `claude` CLI (headless mode — uses your
    # existing Claude Code login, no API key), falling back to the Anthropic API if the CLI
    # isn't installed. Force with "headless" or "api".
    llm_backend: str = "auto"


def ensure_cache_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in PRIVATE_CIDRS)
