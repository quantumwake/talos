"""System-wide resource metrics — CPU, memory, disk I/O, network I/O, and GPU.

Honesty note on macOS: CPU and memory are available **per process** (psutil). Network I/O,
disk I/O, and GPU are **not** exposed per process by normal APIs — they need elevated tools
(`nettop`, `fs_usage`, `powermetrics`). So those three are reported here **system-wide**.
Per-process network bandwidth is available best-effort via `netio.py` (nettop), opt-in.
"""

from __future__ import annotations

import os
import re
import subprocess
import time

import psutil


def system_snapshot(interval: float = 0.5) -> dict:
    """A point-in-time system resource snapshot. Blocks ~``interval`` to compute rates."""

    d0 = psutil.disk_io_counters()
    n0 = psutil.net_io_counters()
    cpu = psutil.cpu_percent(interval=interval)  # blocks `interval`, giving us a window
    d1 = psutil.disk_io_counters()
    n1 = psutil.net_io_counters()

    def rate(a, b, attr):
        return max(0.0, (getattr(b, attr) - getattr(a, attr)) / interval)

    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    try:
        load = os.getloadavg()
    except (OSError, AttributeError):
        load = (0.0, 0.0, 0.0)

    return {
        "cpu": {
            "percent": cpu,
            "count": psutil.cpu_count(),
            "per_core": psutil.cpu_percent(interval=None, percpu=True),
            "load_avg": list(load),
        },
        "memory": {
            "total": vm.total, "used": vm.used, "available": vm.available,
            "percent": vm.percent,
        },
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        "disk_io": {
            "read_bps": rate(d0, d1, "read_bytes"),
            "write_bps": rate(d0, d1, "write_bytes"),
        } if d0 and d1 else None,
        "net_io": {
            "sent_bps": rate(n0, n1, "bytes_sent"),
            "recv_bps": rate(n0, n1, "bytes_recv"),
        },
        "gpu": _gpu_snapshot(),
    }


_GPU_RE = re.compile(r"GPU (?:HW )?active (?:residency|frequency).*?(\d+(?:\.\d+)?)\s*%", re.I)


def _gpu_snapshot() -> dict:
    """Best-effort GPU busy %. macOS only exposes this via `powermetrics`, which needs root."""

    if os.geteuid() != 0:
        return {"available": False, "reason": "GPU metrics need sudo (powermetrics)"}
    try:
        out = subprocess.run(
            ["powermetrics", "--samplers", "gpu_power", "-n", "1", "-i", "200"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "powermetrics unavailable"}
    m = _GPU_RE.search(out)
    if m:
        return {"available": True, "busy_percent": float(m.group(1))}
    return {"available": False, "reason": "could not parse powermetrics"}
