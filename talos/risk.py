"""Risk scoring (0-100) and process grouping.

Score combines four signals: trust (signature), identity (known vs unknown), behaviour
(network egress reputation), and posture (privilege, resource hog). Every contribution
records a human-readable reason so the report can explain *why* a process scored high.

Also computes the final ``safe_to_kill`` decision, which is deliberately stricter than the
classifier's hint: a process is only auto-killable when it is clearly identified, trusted
or known-safe, not system-critical, and confident.
"""

from __future__ import annotations

from collections import defaultdict

from .config import Settings, is_private_ip
from .models import Category, ProcessInfo, RiskTier, TrustLevel, Verdict


def score_process(proc: ProcessInfo, settings: Settings) -> None:
    """Populate proc.verdict.risk_score / risk_tier / egress_flags in place."""

    v = proc.verdict
    assert v is not None
    score = 0
    reasons: list[str] = []

    # --- Identity / signature ---
    if v.category == Category.MALICIOUS:
        score += 90
        reasons.append("flagged malicious by reputation")
    elif v.category == Category.SUSPICIOUS:
        score += 55
        reasons.append("suspicious classification")
    elif v.category == Category.UNKNOWN:
        score += 30
        reasons.append("unidentified process")

    sig = proc.signing
    if sig:
        if sig.trust == TrustLevel.UNSIGNED:
            score += 25
            reasons.append("unsigned binary")
        elif sig.trust == TrustLevel.ADHOC:
            score += 15
            reasons.append("ad-hoc signed (no verified identity)")
        elif sig.trust in (TrustLevel.APPLE_SYSTEM, TrustLevel.DEV_ID_NOTARIZED):
            # Trusted provenance lowers risk — but only if integrity actually verified.
            score -= 10 if sig.verified else 0
        elif sig.trust == TrustLevel.DEV_ID:
            # Developer ID (Apple-issued cert, identified developer) — smaller credit.
            score -= 5 if sig.verified else 0

    # --- Network egress ---
    egress_flags = _score_egress(proc, reasons)
    score += egress_flags["risk"]
    v.egress_flags = egress_flags["flags"]

    # --- Posture ---
    if proc.is_root and v.category in (Category.UNKNOWN, Category.SUSPICIOUS, Category.MALICIOUS):
        score += 15
        reasons.append("runs as root")
    if proc.memory_mb >= settings.mem_hog_mb:
        score += 5
        reasons.append(f"memory hog ({proc.memory_mb:.0f} MB)")
    if proc.cpu_percent >= settings.cpu_hog_percent:
        score += 5
        reasons.append(f"high CPU ({proc.cpu_percent:.0f}%)")

    # System-critical can't be "risky to keep" — it's required.
    if v.category == Category.SYSTEM_CRITICAL:
        score = min(score, 5)

    # You've acknowledged this — it's not a finding anymore.
    if v.acknowledged or v.source == "user":
        score = min(score, 5)
        reasons.append("acknowledged — you marked this known")

    score = max(0, min(100, score))
    v.risk_score = score
    v.risk_tier = _tier(score, settings)
    v.reasons.extend(reasons)

    # --- Final safe-to-kill gate (stricter than the classifier hint) ---
    v.safe_to_kill = _decide_safe_to_kill(proc, settings)


def _score_egress(proc: ProcessInfo, reasons: list[str]) -> dict:
    flags: set[str] = set()
    risk = 0
    public_egress = [
        c for c in proc.connections if c.is_egress and not is_private_ip(c.remote_ip)
    ]
    for c in public_egress:
        for f in c.flags:
            flags.add(f)
    if flags:
        if any(f.startswith("unusual-port") for f in flags):
            risk += 12
            reasons.append("connects out on unusual port(s)")
        if "unresolved-destination" in flags:
            risk += 10
            reasons.append("connects to raw IP with no reverse DNS")
    # Fan-out: lots of distinct public destinations is itself a smell for unknowns.
    distinct = {c.remote_ip for c in public_egress if c.remote_ip}
    if len(distinct) >= 10 and proc.verdict and proc.verdict.category in (
        Category.UNKNOWN,
        Category.SUSPICIOUS,
    ):
        risk += 8
        reasons.append(f"high egress fan-out ({len(distinct)} destinations)")
    return {"risk": risk, "flags": sorted(flags)}


def _decide_safe_to_kill(proc: ProcessInfo, settings: Settings) -> bool:
    v = proc.verdict
    assert v is not None
    if v.category == Category.SYSTEM_CRITICAL:
        return False
    # Never offer to reap our own process(es), hard-protected, or user-pinned ones.
    if v.source in ("protected", "self") or v.do_not_kill:
        return False
    # Malicious processes are NOT auto-killed — flag for human review instead, since a
    # blind kill can trip persistence/relaunch and destroys forensic state.
    if v.category == Category.MALICIOUS:
        return False
    if v.confidence < settings.min_kill_confidence and not v.safe_to_kill:
        return False
    return v.category in (
        Category.KNOWN_SAFE_TO_KILL,
        Category.TRUSTED_APP,
    ) or (v.safe_to_kill and v.confidence >= settings.min_kill_confidence)


def _tier(score: int, settings: Settings) -> RiskTier:
    c = settings.tier_cutoffs
    if score >= c["critical"]:
        return RiskTier.CRITICAL
    if score >= c["high"]:
        return RiskTier.HIGH
    if score >= c["medium"]:
        return RiskTier.MEDIUM
    return RiskTier.LOW


def group_by_category(procs: list[ProcessInfo]) -> dict[str, list[ProcessInfo]]:
    groups: dict[str, list[ProcessInfo]] = defaultdict(list)
    for p in procs:
        cat = p.verdict.category.value if p.verdict else "unknown"
        groups[cat].append(p)
    return dict(groups)


def group_by_app(procs: list[ProcessInfo]) -> dict[str, list[ProcessInfo]]:
    """Group helper/renderer children under a representative app name."""

    groups: dict[str, list[ProcessInfo]] = defaultdict(list)
    for p in procs:
        groups[_app_key(p)].append(p)
    return dict(groups)


def _app_key(p: ProcessInfo) -> str:
    name = p.name
    for marker in (" Helper", " Renderer", " (GPU)", " (Plugin)"):
        if marker in name:
            return name.split(marker)[0]
    if p.verdict and p.verdict.vendor:
        return f"{p.verdict.vendor}: {name}"
    return name
