"""Per-process network connections + egress flagging.

Uses psutil for per-PID sockets (works for your own processes without sudo) and falls
back to ``lsof`` only when asked. The point is to surface *weird egress*: outbound
connections to unusual ports, raw IPs with no reverse DNS, or destinations a process has
no business talking to.
"""

from __future__ import annotations

import psutil

from .config import Settings, is_private_ip, COMMON_EGRESS_PORTS
from .models import Connection, ProcessInfo


def _split_addr(addr) -> tuple[str, int | None]:
    if not addr:
        return "", None
    try:
        return addr.ip, addr.port
    except AttributeError:
        return str(addr), None


def collect_connections(pid: int) -> list[Connection]:
    conns: list[Connection] = []
    try:
        raw = psutil.Process(pid).net_connections(kind="inet")
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return conns

    for c in raw:
        lip, lport = _split_addr(c.laddr)
        rip, rport = _split_addr(c.raddr)
        conn = Connection(
            fd=c.fd if c.fd != -1 else None,
            family=getattr(c.family, "name", str(c.family)),
            type=getattr(c.type, "name", str(c.type)),
            laddr=f"{lip}:{lport}" if lip else "",
            raddr=f"{rip}:{rport}" if rip else "",
            status=c.status or "",
            remote_ip=rip or None,
            remote_port=rport,
        )
        conns.append(conn)
    return conns


def flag_connection(conn: Connection, settings: Settings) -> list[str]:
    """Heuristic flags explaining why an outbound connection looks suspicious."""

    flags: list[str] = []
    if not conn.is_egress or not conn.remote_ip:
        return flags
    if is_private_ip(conn.remote_ip):
        return flags  # LAN/loopback traffic is not internet egress

    if conn.remote_port and conn.remote_port not in COMMON_EGRESS_PORTS:
        flags.append(f"unusual-port:{conn.remote_port}")
    # Raw-IP destination with no reverse DNS is a classic exfil/C2 smell once ASN
    # resolution has run (network.resolve fills rdns).
    if settings.resolve_asn and conn.rdns is None and conn.org is None:
        flags.append("unresolved-destination")
    return flags


def attach_connections(proc: ProcessInfo, settings: Settings) -> None:
    """Populate ``proc.connections`` and per-connection flags in place."""

    if not settings.collect_network:
        return
    proc.connections = collect_connections(proc.pid)
    for conn in proc.connections:
        conn.flags = flag_connection(conn, settings)


def egress_summary(proc: ProcessInfo) -> dict[str, object]:
    """Roll up a process's outbound footprint for the report."""

    egress = [c for c in proc.connections if c.is_egress and not is_private_ip(c.remote_ip)]
    flagged = [c for c in egress if c.flags]
    remote_ports = sorted({c.remote_port for c in egress if c.remote_port})
    return {
        "egress_count": len(egress),
        "flagged_count": len(flagged),
        "remote_ports": remote_ports,
        "destinations": sorted({c.remote_ip for c in egress if c.remote_ip}),
        "flags": sorted({f for c in flagged for f in c.flags}),
    }
