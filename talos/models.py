"""Data models shared across the engine, CLI and API.

Plain dataclasses keep the engine dependency-light and trivially JSON-serialisable
(see ``to_dict`` helpers) so the same objects flow into the rich CLI report and the
FastAPI responses without a translation layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Category(str, Enum):
    """What kind of process this is — drives the kill posture."""

    SYSTEM_CRITICAL = "system_critical"   # never kill (launchd, kernel_task, WindowServer…)
    SYSTEM_SERVICE = "system_service"     # Apple-signed daemons; generally leave running
    TRUSTED_APP = "trusted_app"           # notarized Developer ID, known vendor
    KNOWN_SAFE_TO_KILL = "known_safe_to_kill"  # user apps/helpers safe to quit
    UNKNOWN = "unknown"                   # could not be identified — needs LLM/manual
    SUSPICIOUS = "suspicious"             # unsigned + odd behaviour/egress
    MALICIOUS = "malicious"               # flagged by reputation (VirusTotal et al.)


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(str, Enum):
    """Outcome of the local code-signature check (cheapest authoritative signal)."""

    APPLE_SYSTEM = "apple_system"             # signed by Apple, part of the OS
    DEV_ID_NOTARIZED = "dev_id_notarized"     # Developer ID + notarized by Apple
    DEV_ID = "dev_id"                         # Developer ID signed, notarization unknown
    APP_STORE = "app_store"                   # Mac App Store
    ADHOC = "adhoc"                           # ad-hoc signed (no identity)
    UNSIGNED = "unsigned"                     # no signature at all
    UNKNOWN = "unknown"                       # could not determine (e.g. no exe path)


@dataclass
class SigningInfo:
    trust: TrustLevel = TrustLevel.UNKNOWN
    authority: list[str] = field(default_factory=list)  # cert chain, leaf first
    team_id: Optional[str] = None
    developer: Optional[str] = None         # e.g. "OpenVPN Inc." from a Developer ID cert
    identifier: Optional[str] = None        # bundle/signing identifier
    notarized: bool = False
    verified: bool = False                  # passed `codesign --verify --strict` (integrity)
    sha256: Optional[str] = None            # of the on-disk executable
    signed_target: Optional[str] = None     # what we actually ran codesign against
    error: Optional[str] = None

    @property
    def trusted(self) -> bool:
        return self.trust in (
            TrustLevel.APPLE_SYSTEM,
            TrustLevel.DEV_ID_NOTARIZED,
            TrustLevel.APP_STORE,
        )


@dataclass
class Connection:
    """A single network endpoint owned by a process."""

    fd: Optional[int] = None
    family: str = ""            # AF_INET / AF_INET6 / AF_UNIX
    type: str = ""              # SOCK_STREAM / SOCK_DGRAM
    laddr: str = ""             # local "ip:port"
    raddr: str = ""             # remote "ip:port" (empty for listeners)
    status: str = ""            # ESTABLISHED, LISTEN, …
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    # Filled in by the reputation/ASN layer:
    org: Optional[str] = None
    asn: Optional[str] = None
    rdns: Optional[str] = None
    flags: list[str] = field(default_factory=list)   # why this looked weird

    @property
    def is_egress(self) -> bool:
        return bool(self.raddr) and self.status not in ("LISTEN", "NONE", "")


@dataclass
class ProcessInfo:
    pid: int
    ppid: Optional[int] = None
    name: str = ""
    exe: Optional[str] = None
    cmdline: list[str] = field(default_factory=list)
    username: Optional[str] = None
    is_root: bool = False
    cpu_percent: float = 0.0
    memory_rss: int = 0          # bytes
    memory_percent: float = 0.0
    create_time: float = 0.0
    num_threads: int = 0
    status: str = ""
    accessible: bool = True      # False when we lacked privilege to read details
    connections: list[Connection] = field(default_factory=list)
    signing: Optional[SigningInfo] = None
    bundle: dict = field(default_factory=dict)   # Info.plist metadata (name, id, version…)
    verdict: Optional["Verdict"] = None

    @property
    def memory_mb(self) -> float:
        return self.memory_rss / (1024 * 1024)


@dataclass
class Verdict:
    """The engine's judgement of a single process."""

    category: Category = Category.UNKNOWN
    description: str = ""             # plain-English "what is this / what's it for"
    vendor: Optional[str] = None
    safe_to_kill: bool = False
    confidence: float = 0.0          # 0..1
    source: str = "heuristic"        # heuristic | known_db | virustotal | llm
    risk_score: int = 0              # 0..100
    risk_tier: RiskTier = RiskTier.LOW
    reasons: list[str] = field(default_factory=list)
    egress_flags: list[str] = field(default_factory=list)
    # Persistent-memory fields (see store.py):
    acknowledged: bool = False       # user said "I know what this is — don't flag it"
    do_not_kill: bool = False         # user/learned: never offer to terminate
    analyzed_at: Optional[str] = None  # ISO date this binary was last analysed


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses/enums into JSON-friendly primitives."""

    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_dict(v) for v in obj]
    return obj
