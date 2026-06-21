"""Application removal — the macOS-correct, reversible way.

"Remove" here means **uninstall the app**, not just kill the process. We:
  1. resolve the enclosing ``.app`` bundle from the process executable,
  2. find the launch items + privileged helpers that would otherwise relaunch it,
  3. move them to the **Trash** (reversible — never ``rm``), with the user-level items done
     for you and the system/privileged ones surfaced as "needs sudo" rather than silently
     failing.

Hard guards: never touch the sealed system volume, Apple-signed system components, or Talos
itself. Dry-run by default.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .models import ProcessInfo

# Locations we will never remove from.
_PROTECTED_PREFIXES = (
    "/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/",
    "/bin/", "/sbin/", "/Library/Apple/",
)

_LAUNCH_DIRS_USER = [Path.home() / "Library/LaunchAgents"]
_LAUNCH_DIRS_SYSTEM = [
    Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents"),
    Path("/Library/PrivilegedHelperTools"),
]


@dataclass
class RemovalPlan:
    app_bundle: str | None = None
    vendor: str | None = None
    trash: list[str] = field(default_factory=list)        # we can move these to Trash
    needs_sudo: list[str] = field(default_factory=list)    # system launch items / helpers
    blocked: str | None = None                             # set if removal is refused


@dataclass
class RemovalResult:
    trashed: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    needs_sudo: list[str] = field(default_factory=list)
    dry_run: bool = True
    blocked: str | None = None


def app_bundle(exe: str | None) -> str | None:
    """The outermost enclosing ``.app`` (so a nested helper app removes the whole app)."""

    if not exe:
        return None
    parts = exe.split("/")
    for i, part in enumerate(parts):
        if part.endswith(".app"):
            return "/".join(parts[: i + 1])
    return None


def _is_protected(path: str) -> bool:
    return path.startswith(_PROTECTED_PREFIXES)


def find_launch_items(proc: ProcessInfo) -> tuple[list[str], list[str]]:
    """Plists/helpers that reference this app/vendor → (user-removable, system/sudo)."""

    sig = proc.signing
    needles = [n for n in (
        sig.team_id if sig else None,
        sig.identifier if sig else None,
        proc.name.replace(".app", ""),
        app_bundle(proc.exe),
    ) if n]
    if not needles:
        return [], []

    def scan(dirs: list[Path]) -> list[str]:
        hits: list[str] = []
        for d in dirs:
            if not d.exists():
                continue
            for f in list(d.glob("*.plist")) + [p for p in d.iterdir() if p.is_file()]:
                try:
                    text = f.read_text(errors="ignore")
                except OSError:
                    continue
                if any(n in text or n in f.name for n in needles):
                    hits.append(str(f))
        return sorted(set(hits))

    return scan(_LAUNCH_DIRS_USER), scan(_LAUNCH_DIRS_SYSTEM)


def plan(proc: ProcessInfo) -> RemovalPlan:
    p = RemovalPlan()
    if proc.verdict and proc.verdict.source in ("self", "protected"):
        p.blocked = "refused: Talos itself or a protected system process"
        return p
    if proc.verdict and proc.verdict.category.value in ("system_critical", "system_service"):
        p.blocked = "refused: Apple/system component — not a removable application"
        return p

    bundle = app_bundle(proc.exe)
    p.app_bundle = bundle
    p.vendor = proc.verdict.vendor if proc.verdict else None

    if bundle and _is_protected(bundle):
        p.blocked = "refused: application lives on the protected system volume"
        return p
    if bundle:
        p.trash.append(bundle)
    elif proc.exe and not _is_protected(proc.exe):
        # No .app — a loose helper/framework (e.g. a VPN privileged helper). We don't trash a
        # bare system path blindly; the launch items below are the safe removal surface.
        pass

    user_items, system_items = find_launch_items(proc)
    p.trash.extend(user_items)
    p.needs_sudo.extend(system_items)
    if not p.trash and not p.needs_sudo:
        p.blocked = "no removable application bundle or launch items found for this process"
    return p


def _trash(path: str) -> bool:
    """Move a path to the Trash via Finder (reversible). Returns True on success."""

    script = f'tell application "Finder" to delete POSIX file "{path}"'
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def remove(proc: ProcessInfo, dry_run: bool = True) -> RemovalResult:
    p = plan(proc)
    res = RemovalResult(dry_run=dry_run, needs_sudo=p.needs_sudo, blocked=p.blocked)
    if p.blocked:
        return res
    if dry_run:
        res.trashed = list(p.trash)  # what *would* be trashed
        return res
    for path in p.trash:
        if _trash(path):
            res.trashed.append(path)
        else:
            res.failed.append({"path": path, "reason": "could not move to Trash (permission?)"})
    return res
