"""Rendering: rich terminal tables, JSON export, and grouped risk reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .engine import ScanResult
from .models import Category, ProcessInfo, RiskTier, to_dict
from .network import egress_summary
from . import risk

_TIER_STYLE = {
    RiskTier.CRITICAL: "bold white on red",
    RiskTier.HIGH: "bold red",
    RiskTier.MEDIUM: "yellow",
    RiskTier.LOW: "green",
}

_CATEGORY_ORDER = [
    Category.MALICIOUS,
    Category.SUSPICIOUS,
    Category.UNKNOWN,
    Category.KNOWN_SAFE_TO_KILL,
    Category.TRUSTED_APP,
    Category.SYSTEM_SERVICE,
    Category.SYSTEM_CRITICAL,
]


def to_json(result: ScanResult) -> dict:
    """Serialise a scan result for --json / the API."""

    return {
        "duration_s": round(result.duration_s, 2),
        "privilege": result.privilege,
        "summary": _summary(result),
        "processes": [_process_json(p) for p in result.sorted_by_risk()],
    }


def _process_json(p: ProcessInfo) -> dict:
    d = to_dict(p)
    d["memory_mb"] = round(p.memory_mb, 1)
    d["egress"] = egress_summary(p)
    return d


def _summary(result: ScanResult) -> dict:
    tiers = {t.value: 0 for t in RiskTier}
    cats: dict[str, int] = {}
    safe_to_kill = 0
    flagged_egress = 0
    for p in result.processes:
        if not p.verdict:
            continue
        tiers[p.verdict.risk_tier.value] += 1
        cats[p.verdict.category.value] = cats.get(p.verdict.category.value, 0) + 1
        if p.verdict.safe_to_kill:
            safe_to_kill += 1
        if p.verdict.egress_flags:
            flagged_egress += 1
    return {
        "total": len(result.processes),
        "by_tier": tiers,
        "by_category": cats,
        "safe_to_kill": safe_to_kill,
        "flagged_egress": flagged_egress,
    }


def print_report(result: ScanResult, console: Console | None = None, group_by: str = "category") -> None:
    console = console or Console()
    s = _summary(result)

    # --- header / privilege warning ---
    head = Text()
    head.append(f"Scanned {s['total']} processes in {result.duration_s:.1f}s\n", style="bold")
    head.append(
        f"critical={s['by_tier']['critical']}  high={s['by_tier']['high']}  "
        f"medium={s['by_tier']['medium']}  low={s['by_tier']['low']}   "
        f"safe-to-kill={s['safe_to_kill']}  flagged-egress={s['flagged_egress']}"
    )
    console.print(Panel(head, title="Talos", border_style="cyan"))

    if result.privilege.get("hint"):
        console.print(f"[yellow]⚠ {result.privilege['hint']}[/yellow]")

    groups = (
        risk.group_by_app(result.processes)
        if group_by == "app"
        else risk.group_by_category(result.processes)
    )

    if group_by == "category":
        ordered = [(c.value, groups.get(c.value, [])) for c in _CATEGORY_ORDER]
    else:
        ordered = sorted(
            groups.items(),
            key=lambda kv: max((p.verdict.risk_score for p in kv[1] if p.verdict), default=0),
            reverse=True,
        )

    for label, procs in ordered:
        if not procs:
            continue
        _print_group(console, label, procs)


def _print_group(console: Console, label: str, procs: list[ProcessInfo]) -> None:
    procs = sorted(procs, key=lambda p: p.verdict.risk_score if p.verdict else 0, reverse=True)
    total_mem = sum(p.memory_mb for p in procs)
    table = Table(
        title=f"{label}  ({len(procs)} procs, {total_mem:.0f} MB)",
        title_justify="left",
        title_style="bold",
        expand=True,
    )
    table.add_column("PID", justify="right", style="dim", width=7)
    table.add_column("Process", overflow="fold", max_width=24)
    table.add_column("Risk", justify="center", width=10)
    table.add_column("Mem", justify="right", width=8)
    table.add_column("Kill?", justify="center", width=6)
    table.add_column("Egress", width=10)
    table.add_column("What it is / why", overflow="fold")

    for p in procs:
        v = p.verdict
        tier = v.risk_tier if v else RiskTier.LOW
        risk_cell = Text(f"{v.risk_score if v else 0:>3} {tier.value}", style=_TIER_STYLE[tier])
        kill_cell = Text("✓" if v and v.safe_to_kill else "·",
                         style="bold green" if v and v.safe_to_kill else "dim")
        es = egress_summary(p)
        egress_cell = (
            Text(f"⚠{es['flagged_count']}/{es['egress_count']}", style="bold red")
            if es["flagged_count"]
            else Text(str(es["egress_count"]) if es["egress_count"] else "·", style="dim")
        )
        desc = (v.description if v else "") or ""
        if v and v.reasons:
            desc += f"  [dim]({'; '.join(v.reasons[:2])})[/dim]"
        table.add_row(
            str(p.pid), p.name, risk_cell, f"{p.memory_mb:.0f}", kill_cell, egress_cell, desc,
        )
    console.print(table)


def print_process_detail(p: ProcessInfo, console: Console | None = None) -> None:
    """Deep-dive view for `talos inspect <pid>`."""

    console = console or Console()
    v = p.verdict
    lines = Text()
    lines.append(f"{p.name}  (pid {p.pid})\n", style="bold")
    lines.append(f"  exe:     {p.exe or 'unknown'}\n")
    lines.append(f"  cmd:     {' '.join(p.cmdline[:20]) or 'unknown'}\n")
    lines.append(f"  user:    {p.username or 'unknown'}  root={p.is_root}\n")
    lines.append(f"  memory:  {p.memory_mb:.0f} MB   cpu: {p.cpu_percent:.0f}%\n")
    if p.signing:
        s = p.signing
        verified = "✓ verified" if s.verified else "✗ NOT verified"
        lines.append(f"  signing: {s.trust.value}  ({verified} via codesign --verify)")
        if s.team_id:
            lines.append(f"  team={s.team_id}")
        if s.signed_target and s.signed_target != (p.exe or ""):
            lines.append(f"\n           checked: {s.signed_target}")
        if s.authority:
            lines.append(f"\n           authority: {s.authority[0]}")
        lines.append("\n")
    if p.bundle:
        b = p.bundle
        meta = "  ".join(f"{k}={b[k]}" for k in ("bundle_id", "version", "copyright") if b.get(k))
        if meta:
            lines.append(f"  bundle:  {meta}\n")
    if v:
        lines.append(f"\n  category:   {v.category.value}\n", style="bold")
        lines.append(f"  risk:       {v.risk_score}/100 ({v.risk_tier.value})  ", style=_TIER_STYLE[v.risk_tier])
        lines.append(f"safe-to-kill: {'YES' if v.safe_to_kill else 'no'}\n")
        lines.append(f"  source:     {v.source} (confidence {v.confidence:.0%})\n")
        lines.append(f"  what:       {v.description}\n")
        if v.reasons:
            lines.append("  reasons:\n")
            for r in v.reasons:
                lines.append(f"    • {r}\n")
    console.print(Panel(lines, border_style="cyan"))

    egress = [c for c in p.connections if c.is_egress]
    if egress:
        t = Table(title="Network egress", title_justify="left")
        t.add_column("Remote")
        t.add_column("Org / ASN")
        t.add_column("rDNS")
        t.add_column("Flags", style="red")
        for c in egress:
            t.add_row(
                c.raddr,
                f"{c.org or '?'} {c.asn or ''}".strip(),
                c.rdns or "—",
                ", ".join(c.flags) or "",
            )
        console.print(t)
