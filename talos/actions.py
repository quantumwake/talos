"""Process termination — guarded, audited, dry-run by default.

This is the only module that can kill anything, so all the safety lives here:
  * a hardcoded protected list (names + PID 0/1) that NOTHING can override, not even --force
  * dry-run unless the caller explicitly confirms
  * graceful SIGTERM, escalating to SIGKILL only if asked and the process survives
  * every attempt (real or dry-run) appended to an audit log
"""

from __future__ import annotations

import json
import os
import signal
import time
from dataclasses import dataclass

import psutil

from .config import AUDIT_LOG, PROTECTED_NAMES, ensure_cache_dir
from .models import ProcessInfo


@dataclass
class KillResult:
    pid: int
    name: str
    attempted: bool
    killed: bool
    dry_run: bool
    reason: str
    method: str = ""  # SIGTERM / SIGKILL / blocked


def is_protected(proc: ProcessInfo) -> bool:
    return proc.pid in (0, 1) or proc.name in PROTECTED_NAMES


def _audit(entry: dict) -> None:
    ensure_cache_dir()
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        with open(AUDIT_LOG, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def terminate(
    proc: ProcessInfo,
    *,
    dry_run: bool = True,
    force: bool = False,
    escalate: bool = True,
    grace_seconds: float = 3.0,
    reason: str = "",
) -> KillResult:
    """Attempt to terminate a process under the safety rules.

    ``force`` bypasses the safe-to-kill verdict (but NEVER the protected list).
    ``escalate`` sends SIGKILL if SIGTERM doesn't take within ``grace_seconds``.
    """

    if is_protected(proc):
        result = KillResult(
            proc.pid, proc.name, False, False, dry_run,
            "refused: protected system process", method="blocked",
        )
        _audit({"action": "blocked", "pid": proc.pid, "name": proc.name, "reason": result.reason})
        return result

    safe = bool(proc.verdict and proc.verdict.safe_to_kill)
    if not safe and not force:
        return KillResult(
            proc.pid, proc.name, False, False, dry_run,
            "refused: not classified safe-to-kill (use --force to override)",
            method="blocked",
        )

    if proc.pid == os.getpid():
        return KillResult(
            proc.pid, proc.name, False, False, dry_run,
            "refused: that's me (the talos)", method="blocked",
        )

    if dry_run:
        _audit({"action": "dry_run", "pid": proc.pid, "name": proc.name, "reason": reason})
        return KillResult(
            proc.pid, proc.name, True, False, True,
            reason or "would terminate", method="SIGTERM(dry-run)",
        )

    # --- real termination ---
    try:
        p = psutil.Process(proc.pid)
        p.terminate()  # SIGTERM
        method = "SIGTERM"
        try:
            p.wait(timeout=grace_seconds)
            killed = True
        except psutil.TimeoutExpired:
            if escalate:
                p.kill()  # SIGKILL
                method = "SIGKILL"
                try:
                    p.wait(timeout=grace_seconds)
                    killed = True
                except psutil.TimeoutExpired:
                    killed = False
            else:
                killed = False
    except psutil.NoSuchProcess:
        killed, method = True, "already-gone"
    except psutil.AccessDenied:
        result = KillResult(
            proc.pid, proc.name, True, False, False,
            "permission denied (try sudo)", method="denied",
        )
        _audit({"action": "denied", "pid": proc.pid, "name": proc.name})
        return result

    _audit({
        "action": "terminate", "pid": proc.pid, "name": proc.name,
        "method": method, "killed": killed, "reason": reason,
    })
    return KillResult(
        proc.pid, proc.name, True, killed, False,
        reason or "terminated", method=method,
    )


def read_audit_log(limit: int = 200) -> list[dict]:
    if not AUDIT_LOG.exists():
        return []
    out: list[dict] = []
    try:
        for line in AUDIT_LOG.read_text().splitlines()[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return out


# Map signal numbers for reference / potential UI display.
SIGNAL_NAMES = {signal.SIGTERM: "SIGTERM", signal.SIGKILL: "SIGKILL"}
