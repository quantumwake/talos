"""Process enumeration via psutil.

Gracefully degrades: when we lack privilege to read a process's details (common for
other users' / system processes when not root) we still record the PID + name and mark
``accessible=False`` so the report can warn about blind spots instead of silently
dropping rows.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import psutil

from .models import ProcessInfo

# Bundle directory suffixes used to derive a real display name from an exe path.
_BUNDLE_EXTS = (
    ".app", ".xpc", ".framework", ".dext", ".appex", ".systemextension",
    ".bundle", ".kext", ".plugin", ".pluginkit", ".qlgenerator", ".mdimporter",
)


def _is_root() -> bool:
    return os.geteuid() == 0


def _ps_enrich() -> tuple[dict[int, str], dict[int, str]]:
    """Full executable paths + argv per PID, via `ps`.

    macOS `psutil.name()` returns the kernel's 15-char `comm` and `psutil.exe()` is denied
    for root-owned processes when unprivileged — but `ps -axww` reports the full path even
    without sudo. Parsed as `<pid> <rest>` so paths containing spaces survive.
    """

    def run(field: str) -> dict[int, str]:
        out: dict[int, str] = {}
        try:
            res = subprocess.run(
                ["ps", "-axww", "-o", f"pid=,{field}="],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return out
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            head, _, rest = line.partition(" ")
            if head.isdigit() and rest.strip():
                out[int(head)] = rest.strip()
        return out

    return run("comm"), run("command")


def _display_name(exe: str | None, fallback: str) -> str:
    """A real, untruncated name: the enclosing bundle's name, else the exe basename."""

    if not exe:
        return fallback
    for part in exe.split("/"):
        if part.endswith(_BUNDLE_EXTS):
            return part  # e.g. "Google Chrome.app", "CloudTelemetryService.xpc"
    base = os.path.basename(exe)
    return base or fallback


def collect_processes(with_cpu: bool = True) -> list[ProcessInfo]:
    """Enumerate all visible processes.

    ``with_cpu`` does a short two-sample pass to get meaningful CPU percentages
    (psutil returns 0.0 on the first read of each process otherwise).
    """

    procs: dict[int, psutil.Process] = {}
    for p in psutil.process_iter():
        procs[p.pid] = p

    if with_cpu:
        # Prime the CPU counters, then let a moment elapse before the real read.
        for p in procs.values():
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        psutil.cpu_percent(None)  # interval handled by caller's natural latency

    ps_exe, ps_args = _ps_enrich()

    results: list[ProcessInfo] = []
    for pid, p in procs.items():
        info = _snapshot(p)
        _enrich(info, ps_exe, ps_args)
        results.append(info)
    return results


# Where bare-name system binaries actually live (so they can be signature-verified).
_BIN_DIRS = ("/usr/libexec", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/System/Library/CoreServices")


def _resolve_bare(name: str) -> str | None:
    """A bare command name (e.g. 'endpointsecurityd') → its real path, so we can verify it."""

    if "/" in name or " " in name:
        return None
    found = shutil.which(name)
    if found:
        return found
    for d in _BIN_DIRS:
        p = os.path.join(d, name)
        try:
            if os.path.exists(p):
                return p
        except OSError:
            continue
    return None


def _enrich(info: ProcessInfo, ps_exe: dict[int, str], ps_args: dict[int, str]) -> None:
    """Backfill exe/cmdline/name from `ps` where psutil came up short or truncated."""

    if not info.exe and info.pid in ps_exe:
        info.exe = ps_exe[info.pid]
        info.accessible = True  # we recovered real details after all
    if not info.cmdline and info.pid in ps_args:
        info.cmdline = ps_args[info.pid].split()
    # A bare executable name (no path) can't be signature-verified — resolve it to the real
    # on-disk binary (login → /usr/bin/login, endpointsecurityd → /usr/libexec/…).
    if info.exe and "/" not in info.exe:
        resolved = _resolve_bare(info.exe)
        if resolved:
            info.exe = resolved
    # Always prefer a real name over the kernel's 15-char truncated `comm`.
    info.name = _display_name(info.exe, info.name)


def _snapshot(p: psutil.Process) -> ProcessInfo:
    info = ProcessInfo(pid=p.pid)
    try:
        with p.oneshot():
            info.name = p.name()
            info.ppid = p.ppid()
            info.status = p.status()
            info.num_threads = p.num_threads()
            info.create_time = p.create_time()
            try:
                info.exe = p.exe()
            except (psutil.AccessDenied, FileNotFoundError, OSError):
                info.exe = None
            try:
                info.cmdline = p.cmdline()
            except (psutil.AccessDenied, OSError):
                info.cmdline = []
            try:
                username = p.username()
                info.username = username
                info.is_root = username in ("root", "0")
            except (psutil.AccessDenied, KeyError):
                info.username = None
            try:
                info.cpu_percent = p.cpu_percent(None)
            except (psutil.AccessDenied, OSError):
                pass
            try:
                mem = p.memory_info()
                info.memory_rss = mem.rss
                info.memory_percent = p.memory_percent()
            except (psutil.AccessDenied, OSError):
                pass
    except psutil.NoSuchProcess:
        info.accessible = False
        info.status = "gone"
    except psutil.AccessDenied:
        # We can see it exists but not read its guts.
        info.accessible = False
        try:
            info.name = p.name()
        except Exception:
            pass
    return info


def get_process(pid: int) -> ProcessInfo | None:
    try:
        info = _snapshot(psutil.Process(pid))
    except psutil.NoSuchProcess:
        return None
    ps_exe, ps_args = _ps_enrich()
    _enrich(info, ps_exe, ps_args)
    return info


def privilege_summary() -> dict[str, object]:
    """Describe what visibility we have so the report can warn the user."""

    root = _is_root()
    total = len(psutil.pids())
    ps_exe, _ = _ps_enrich()
    # "Restricted" = we couldn't resolve an exe even after the `ps` fallback. Network
    # sockets still need root, but paths/names are now recovered for most system procs.
    inaccessible = 0
    for p in psutil.process_iter(["pid"]):
        try:
            p.exe()
        except psutil.AccessDenied:
            if p.pid not in ps_exe:
                inaccessible += 1
        except (psutil.NoSuchProcess, FileNotFoundError, OSError):
            continue
    return {
        "running_as_root": root,
        "total_processes": total,
        "restricted_processes": inaccessible,
        "hint": (
            "Running unprivileged: per-process network sockets for system/other-user "
            "processes are hidden. Re-run with sudo to see those connections."
            if not root
            else ""
        ),
    }
