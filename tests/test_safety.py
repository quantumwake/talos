"""Safety tests — the rules that must never regress.

These build ProcessInfo objects directly (no live process enumeration), so they run
deterministically without sudo and never touch real processes.
"""

from __future__ import annotations

import pytest

from talos import actions
from talos.config import Settings
from talos.models import (
    Category,
    ProcessInfo,
    SigningInfo,
    TrustLevel,
    Verdict,
)


def make_proc(**kw) -> ProcessInfo:
    p = ProcessInfo(pid=kw.pop("pid", 4242), name=kw.pop("name", "widget"))
    for k, v in kw.items():
        setattr(p, k, v)
    if p.verdict is None:
        p.verdict = Verdict(category=Category.KNOWN_SAFE_TO_KILL, safe_to_kill=True, confidence=0.95)
    return p


# ---------------- protected list ----------------

@pytest.mark.parametrize("name", ["launchd", "kernel_task", "WindowServer", "loginwindow"])
def test_protected_names_never_killable(name):
    p = make_proc(name=name, verdict=Verdict(category=Category.SYSTEM_CRITICAL, safe_to_kill=False))
    res = actions.terminate(p, dry_run=False, force=True)  # even with force
    assert not res.killed
    assert res.method == "blocked"
    assert actions.is_protected(p)


def test_pid_1_protected_regardless_of_name():
    p = make_proc(pid=1, name="anything")
    assert actions.is_protected(p)
    res = actions.terminate(p, dry_run=False, force=True)
    assert not res.killed and res.method == "blocked"


# ---------------- dry-run is safe ----------------

def test_dry_run_never_kills():
    p = make_proc()
    res = actions.terminate(p, dry_run=True)
    assert res.dry_run and not res.killed and res.attempted


def test_non_safe_refused_without_force():
    p = make_proc(verdict=Verdict(category=Category.UNKNOWN, safe_to_kill=False, confidence=0.3))
    res = actions.terminate(p, dry_run=False, force=False)
    assert not res.attempted and not res.killed
    assert "not classified safe-to-kill" in res.reason


def test_wont_kill_self():
    import os
    p = make_proc(pid=os.getpid())
    res = actions.terminate(p, dry_run=False, force=True)
    assert not res.killed and "me" in res.reason


# ---------------- risk scoring ----------------

def test_unsigned_unknown_scores_higher_than_trusted():
    from talos import risk

    settings = Settings()
    trusted = make_proc(
        name="Slack", signing=SigningInfo(trust=TrustLevel.DEV_ID_NOTARIZED),
        verdict=Verdict(category=Category.TRUSTED_APP, safe_to_kill=True, confidence=0.9),
    )
    unknown = make_proc(
        name="x", signing=SigningInfo(trust=TrustLevel.UNSIGNED),
        verdict=Verdict(category=Category.UNKNOWN, safe_to_kill=False, confidence=0.3),
    )
    risk.score_process(trusted, settings)
    risk.score_process(unknown, settings)
    assert unknown.verdict.risk_score > trusted.verdict.risk_score


def test_system_critical_capped_low_risk():
    from talos import risk

    p = make_proc(
        name="launchd", is_root=True, memory_rss=2000 * 1024 * 1024,
        signing=SigningInfo(trust=TrustLevel.APPLE_SYSTEM),
        verdict=Verdict(category=Category.SYSTEM_CRITICAL, safe_to_kill=False),
    )
    risk.score_process(p, Settings())
    assert p.verdict.risk_score <= 5
    assert not p.verdict.safe_to_kill


def test_malicious_not_auto_safe_to_kill():
    from talos import risk

    p = make_proc(
        name="evil", signing=SigningInfo(trust=TrustLevel.UNSIGNED),
        verdict=Verdict(category=Category.MALICIOUS, safe_to_kill=True, confidence=0.95),
    )
    risk.score_process(p, Settings())
    # Malicious is flagged, never auto-killed (preserve forensics / avoid relaunch traps).
    assert not p.verdict.safe_to_kill
    assert p.verdict.risk_tier.value in ("high", "critical")


# ---------------- name must not override signature ----------------

def test_protected_name_with_unsigned_binary_flagged_as_impersonation(tmp_path):
    """A process using a protected system name but an UNSIGNED binary is impersonation,
    not something to trust/protect — the name must never override the signature."""
    import shutil
    import subprocess
    from talos.signing import inspect_signature
    from talos.classify import Classifier
    from talos.models import TrustLevel as TL

    fake = tmp_path / "launchd"
    shutil.copy("/bin/echo", fake)
    subprocess.run(["codesign", "--remove-signature", str(fake)], capture_output=True)
    if inspect_signature(str(fake)).trust != TL.UNSIGNED:
        pytest.skip("could not produce an unsigned binary on this host")

    p = ProcessInfo(pid=999999, name="launchd", exe=str(fake))
    v = Classifier(Settings()).classify(p)
    assert v.category == Category.SUSPICIOUS
    assert v.source == "impersonation"
    assert v.safe_to_kill is False


# ---------------- never flag / kill ourselves ----------------

def test_talos_does_not_flag_or_kill_itself():
    import os
    from talos.classify import Classifier, _is_self
    from talos import risk

    me = ProcessInfo(pid=os.getpid(), name="python")
    assert _is_self(me)
    me.verdict = Classifier(Settings()).classify(me)
    risk.score_process(me, Settings())
    assert me.verdict.source == "self"
    assert me.verdict.category == Category.TRUSTED_APP
    assert me.verdict.safe_to_kill is False  # must NOT be an auto-terminate target
    assert me.verdict.risk_score <= 10        # not a finding

    # And a separate talos process (matched by cmdline) is likewise spared.
    other = ProcessInfo(pid=999999, name="python3.12",
                        cmdline=["python", "-m", "uvicorn", "talos.api:app"])
    assert _is_self(other)


# ---------------- knowledge base ----------------

def test_knowledge_base_loads_and_matches():
    from talos.knowledge import KnowledgeBase

    kb = KnowledgeBase()
    entry = kb.lookup("launchd", "/sbin/launchd")
    assert entry is not None
    assert entry.category == Category.SYSTEM_CRITICAL
    assert entry.safe_to_kill is False
    # pattern match
    helper = kb.lookup("Google Chrome Helper", "/Applications/Google Chrome.app/...")
    assert helper is not None and helper.safe_to_kill is True


# ---------------- process identification / signing accuracy ----------------

def test_bundle_root_resolves_enclosing_bundle():
    from talos.signing import _bundle_root

    cases = {
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome":
            "/Applications/Google Chrome.app",
        "/System/Library/DriverExtensions/com.apple.X.dext/com.apple.X":
            "/System/Library/DriverExtensions/com.apple.X.dext",
        "/System/Library/PrivateFrameworks/CloudTelemetry.framework/Versions/A/"
        "XPCServices/CloudTelemetryService.xpc/Contents/MacOS/CloudTelemetryService":
            "/System/Library/PrivateFrameworks/CloudTelemetry.framework/Versions/A/"
            "XPCServices/CloudTelemetryService.xpc",
    }
    for exe, bundle in cases.items():
        assert _bundle_root(exe) == bundle
    # No bundle in the path → the exe itself.
    assert _bundle_root("/usr/sbin/cfprefsd") == "/usr/sbin/cfprefsd"


def test_display_name_untruncates():
    from talos.collect import _display_name

    # bundle name preferred
    assert _display_name("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                         "Google Chr") == "Google Chrome.app"
    # else basename (full, not the kernel's 15-char comm)
    assert _display_name("/System/Library/PrivateFrameworks/CoreKDL.framework/Support/corekdld",
                         "corekdld") == "CoreKDL.framework"
    assert _display_name("/usr/sbin/cfprefsd", "cfprefsd") == "cfprefsd"
    assert _display_name(None, "fallback") == "fallback"


def test_unsigned_is_flagged_regardless_of_path():
    """Path is never trust: an unsigned binary is penalised even under /System."""
    from talos import risk

    for path in ("/tmp/com.apple.Fake", "/System/Library/Foo/weirdsysthing"):
        p = make_proc(
            name="x", exe=path,
            signing=SigningInfo(trust=TrustLevel.UNSIGNED),
            verdict=Verdict(category=Category.UNKNOWN, safe_to_kill=False, confidence=0.3),
        )
        risk.score_process(p, Settings())
        assert any("unsigned" in r for r in p.verdict.reasons), path
        assert p.verdict.risk_score >= 25, path


def test_apple_trust_lowers_risk_only_when_verified():
    from talos import risk

    verified = make_proc(name="a", exe="/System/Library/x",
                         signing=SigningInfo(trust=TrustLevel.APPLE_SYSTEM, verified=True),
                         verdict=Verdict(category=Category.SYSTEM_SERVICE, confidence=0.8))
    unverified = make_proc(name="b", exe="/System/Library/y",
                           signing=SigningInfo(trust=TrustLevel.APPLE_SYSTEM, verified=False),
                           verdict=Verdict(category=Category.SYSTEM_SERVICE, confidence=0.8))
    risk.score_process(verified, Settings())
    risk.score_process(unverified, Settings())
    # The -10 trust credit applies only to the cryptographically verified one.
    assert verified.verdict.risk_score < unverified.verdict.risk_score or verified.verdict.risk_score == 0


# ---------------- egress flagging ----------------

def test_unusual_port_flagged():
    from talos.models import Connection
    from talos.network import flag_connection

    c = Connection(
        raddr="203.0.113.5:4444", remote_ip="203.0.113.5", remote_port=4444,
        status="ESTABLISHED",
    )
    flags = flag_connection(c, Settings(resolve_asn=False))
    assert any(f.startswith("unusual-port") for f in flags)


def test_private_ip_not_flagged():
    from talos.models import Connection
    from talos.network import flag_connection

    c = Connection(
        raddr="192.168.1.10:4444", remote_ip="192.168.1.10", remote_port=4444,
        status="ESTABLISHED",
    )
    assert flag_connection(c, Settings()) == []
