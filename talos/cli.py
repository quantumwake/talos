"""Command-line interface for the Talos.

    talos scan                      # audit + grouped risk report
    talos scan --auto-terminate-safe --dry-run
    talos inspect <pid>             # deep dive on one process
    talos terminate <pid>           # guarded kill
    talos serve                     # launch the backend API
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from . import actions, collect, engine, report
from .config import Settings
from .models import to_dict

app = typer.Typer(
    add_completion=False,
    help="Audit every macOS process: identify it, score its risk, watch its egress, "
    "and safely reap the harmless ones.",
)
console = Console()


def _build_settings(
    llm: bool, vt: bool, network: bool, asn: bool, llm_model: Optional[str]
) -> Settings:
    s = Settings(
        use_llm=llm,
        use_virustotal=vt,
        collect_network=network,
        resolve_asn=asn and network,
    )
    if llm_model:
        s.llm_model = llm_model
    return s


@app.command()
def scan(
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write full results to a JSON file."),
    group_by: str = typer.Option("category", "--group-by", help="category | app"),
    llm: bool = typer.Option(False, "--llm/--no-llm", help="Use Claude to classify unknown processes."),
    vt: bool = typer.Option(False, "--vt", help="Look up binary hashes on VirusTotal (needs VT_API_KEY)."),
    network: bool = typer.Option(True, "--network/--no-network", help="Collect + flag per-process connections."),
    resolve_asn: bool = typer.Option(True, "--asn/--no-asn", help="Resolve egress IPs to org/ASN."),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Override the Claude model id."),
    min_risk: int = typer.Option(0, "--min-risk", help="Only show processes at/above this risk score."),
    auto_terminate_safe: bool = typer.Option(
        False, "--auto-terminate-safe", help="Reap processes classified safe-to-kill."
    ),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="With --auto-terminate-safe: simulate only."),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt for real terminations."),
) -> None:
    """Scan all processes, classify them, and print a grouped risk report."""

    settings = _build_settings(llm, vt, network, resolve_asn, llm_model)
    with console.status("[cyan]scanning…", spinner="dots") as status:
        result = engine.scan(
            settings,
            progress=lambda phase, done=0, total=0, current="": status.update(
                f"[cyan]{phase}" + (f" {done}/{total}" if total else "")
                + (f" — {current}" if current else "")
            ),
        )

    if min_risk > 0:
        result.processes = [
            p for p in result.processes if p.verdict and p.verdict.risk_score >= min_risk
        ]

    report.print_report(result, console=console, group_by=group_by)

    if json_out:
        json_out.write_text(json.dumps(report.to_json(result), indent=2))
        console.print(f"[green]Wrote {json_out}[/green]")

    if auto_terminate_safe:
        _auto_terminate(result, dry_run=dry_run, yes=yes)


def _auto_terminate(result: engine.ScanResult, dry_run: bool, yes: bool) -> None:
    targets = [p for p in result.processes if p.verdict and p.verdict.safe_to_kill]
    if not targets:
        console.print("[green]Nothing classified safe-to-kill. No action.[/green]")
        return

    console.print(
        f"\n[bold]{len(targets)} processes are safe-to-kill[/bold] "
        f"({sum(p.memory_mb for p in targets):.0f} MB):"
    )
    for p in targets:
        console.print(f"  • {p.pid:>6}  {p.name}  ({p.memory_mb:.0f} MB) — {p.verdict.description[:60]}")

    if dry_run:
        console.print("\n[yellow]Dry-run: nothing was terminated. Re-run with --no-dry-run to act.[/yellow]")
        for p in targets:
            actions.terminate(p, dry_run=True, reason="auto-terminate-safe")
        return

    if not yes:
        if not typer.confirm(f"\nTerminate these {len(targets)} processes?"):
            console.print("Aborted.")
            return

    killed = 0
    for p in targets:
        res = actions.terminate(p, dry_run=False, reason="auto-terminate-safe")
        flag = "[green]killed[/green]" if res.killed else f"[red]{res.reason}[/red]"
        console.print(f"  {p.pid:>6} {p.name}: {res.method} → {flag}")
        killed += int(res.killed)
    console.print(f"\n[bold]Terminated {killed}/{len(targets)}.[/bold] Audit log: ~/.talos/audit.log")


@app.command()
def analyze(
    category: str = typer.Option("unknown", "--category", help="Which group to analyze (category name)."),
    tier: Optional[str] = typer.Option(None, "--tier", help="Restrict to a risk tier (low/medium/high/critical)."),
    min_risk: int = typer.Option(0, "--min-risk"),
    limit: int = typer.Option(40, "--limit", help="Max processes to send to Claude."),
    web_search: bool = typer.Option(False, "--web-search", help="Let Claude search the web for unknown binaries."),
) -> None:
    """Auto-analyze a group of processes with Claude and remember the results.

    Verdicts are cached to the learned store, so identified binaries keep their
    descriptions and stop being re-flagged. Needs ANTHROPIC_API_KEY.
    """

    from concurrent.futures import ThreadPoolExecutor
    from .classify import apply_llm_item
    from .knowledge import KnowledgeBase
    from .llm import LLMClassifier
    from . import risk
    from .store import LearnedStore, entry_key

    settings = Settings(use_llm=True, collect_network=False)
    settings.llm_web_search = web_search
    llmc = LLMClassifier(settings, KnowledgeBase())
    if not llmc.available():
        console.print("[red]No Claude backend — install the `claude` CLI (headless, no API key) "
                      "or set ANTHROPIC_API_KEY.[/red]")
        raise typer.Exit(1)

    with console.status("[cyan]scanning…", spinner="dots"):
        result = engine.scan(Settings(collect_network=False))

    targets = [
        p for p in result.sorted_by_risk()
        if p.verdict and p.verdict.category.value == category
        and (not tier or p.verdict.risk_tier.value == tier)
        and p.verdict.risk_score >= min_risk
        and p.verdict.source not in ("user", "memory", "known_db", "protected", "self")
    ][:limit]
    if not targets:
        console.print(f"[green]Nothing to analyze in '{category}'.[/green]")
        return

    console.print(f"[cyan]Asking Claude ({llmc.backend_name()}) about {len(targets)} "
                  f"'{category}' processes in chunks{' (with web search)' if web_search else ''}…[/cyan]")
    store = LearnedStore()
    chunks = [targets[i : i + 12] for i in range(0, len(targets), 12)]

    def _do(chunk):
        verdicts = llmc.classify_batch(chunk)
        for p in chunk:
            item = verdicts.get(p.pid)
            if item and "_error" not in item:
                apply_llm_item(p.verdict, item)
                store.record(p, p.verdict, entry_key(p.name, p.exe, p.signing.sha256 if p.signing else None))
            risk.score_process(p, settings)

    with console.status("[cyan]asking Claude…", spinner="dots"):
        with ThreadPoolExecutor(max_workers=2 if web_search else 4) as pool:
            list(pool.map(_do, chunks))
    store.flush()

    from rich.table import Table
    t = Table(title=f"Claude analysis ({len(targets)})", title_justify="left")
    t.add_column("pid", justify="right"); t.add_column("name"); t.add_column("category")
    t.add_column("kill?", justify="center"); t.add_column("what it is", overflow="fold", max_width=64)
    for p in sorted(targets, key=lambda p: p.verdict.risk_score, reverse=True):
        v = p.verdict
        t.add_row(str(p.pid), p.name, v.category.value, "✓" if v.safe_to_kill else "·", v.description)
    console.print(t)
    console.print("[dim]Saved to the learned store — these won't be re-flagged next scan.[/dim]")


@app.command()
def inspect(
    pid: int = typer.Argument(..., help="PID to deep-dive."),
    llm: bool = typer.Option(False, "--llm", help="Use Claude if the process is unknown."),
    vt: bool = typer.Option(False, "--vt", help="VirusTotal hash lookup."),
) -> None:
    """Deep-dive a single process: signing, egress, and classification."""

    from .classify import Classifier
    from . import network as net, risk
    from .reputation import asn as asn_mod

    proc = collect.get_process(pid)
    if not proc:
        console.print(f"[red]No process with pid {pid}[/red]")
        raise typer.Exit(1)

    settings = _build_settings(llm, vt, True, True, None)
    net.attach_connections(proc, settings)
    asn_mod.resolve_connections([c for c in proc.connections if c.is_egress])
    for c in proc.connections:
        c.flags = net.flag_connection(c, settings)
    proc.verdict = Classifier(settings).classify(proc)
    risk.score_process(proc, settings)

    report.print_process_detail(proc, console=console)


@app.command()
def terminate(
    pid: int = typer.Argument(..., help="PID to terminate."),
    force: bool = typer.Option(False, "--force", help="Override the safe-to-kill check (NOT the protected list)."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Simulate unless --no-dry-run."),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation."),
    no_escalate: bool = typer.Option(False, "--no-escalate", help="SIGTERM only; do not escalate to SIGKILL."),
) -> None:
    """Terminate a single process (guarded; dry-run by default)."""

    from .classify import Classifier
    from . import risk

    proc = collect.get_process(pid)
    if not proc:
        console.print(f"[red]No process with pid {pid}[/red]")
        raise typer.Exit(1)
    settings = _build_settings(False, False, False, False, None)
    proc.verdict = Classifier(settings).classify(proc)
    risk.score_process(proc, settings)

    console.print(f"Target: [bold]{proc.name}[/bold] (pid {pid}) — "
                  f"{proc.verdict.category.value}, safe-to-kill={proc.verdict.safe_to_kill}")
    if not dry_run and not yes:
        if not typer.confirm("Proceed?"):
            console.print("Aborted.")
            raise typer.Exit(0)

    res = actions.terminate(proc, dry_run=dry_run, force=force, escalate=not no_escalate, reason="manual")
    style = "green" if res.killed or res.dry_run else "red"
    console.print(f"[{style}]{res.method}: {res.reason}[/{style}]")


@app.command()
def remove(
    pid: int = typer.Argument(..., help="PID whose application to uninstall."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Show the plan unless --no-dry-run."),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation."),
) -> None:
    """Uninstall the application behind a process — move it (and its launch items) to Trash.

    Reversible (Trash, never rm). Refuses Apple/system components and Talos itself. System
    launch daemons / privileged helpers are listed as 'needs sudo' rather than removed.
    """

    from .classify import Classifier
    from . import risk, uninstall

    proc = collect.get_process(pid)
    if not proc:
        console.print(f"[red]No process with pid {pid}[/red]")
        raise typer.Exit(1)
    settings = _build_settings(False, False, False, False, None)
    proc.verdict = Classifier(settings).classify(proc)
    risk.score_process(proc, settings)

    p = uninstall.plan(proc)
    if p.blocked:
        console.print(f"[red]{p.blocked}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Uninstall {proc.name}[/bold]" + (f" — {p.vendor}" if p.vendor else ""))
    if p.app_bundle:
        console.print(f"  app: {p.app_bundle}")
    if p.trash:
        console.print("[cyan]Will move to Trash (reversible):[/cyan]")
        for t in p.trash:
            console.print(f"  • {t}")
    if p.needs_sudo:
        console.print("[yellow]Needs sudo to remove (system launch items / privileged helpers):[/yellow]")
        for s in p.needs_sudo:
            console.print(f"  • {s}")
        console.print("[dim]  remove these with: sudo rm <path>  (after stopping the daemon)[/dim]")

    if dry_run:
        console.print("\n[yellow]Dry-run — nothing removed. Re-run with --no-dry-run to act.[/yellow]")
        return
    if not yes and not typer.confirm(f"\nMove {len(p.trash)} item(s) to Trash?"):
        console.print("Aborted.")
        raise typer.Exit(0)

    res = uninstall.remove(proc, dry_run=False)
    for t in res.trashed:
        console.print(f"  [green]trashed[/green] {t}")
    for f in res.failed:
        console.print(f"  [red]failed[/red] {f['path']}: {f['reason']}")
    console.print(f"[bold]Moved {len(res.trashed)} item(s) to Trash.[/bold]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(58789, "--port"),
) -> None:
    """Launch the FastAPI backend that powers the React portal."""

    import uvicorn

    console.print(f"[cyan]Starting Talos API on http://{host}:{port}[/cyan]")
    console.print("Docs at /docs · point the React portal's VITE_API_URL here.")
    uvicorn.run("talos.api:app", host=host, port=port, log_level="info")


@app.command()
def dev(
    api_port: int = typer.Option(58789, "--api-port"),
    portal_port: int = typer.Option(58790, "--portal-port"),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open a browser."),
) -> None:
    """Run the backend API and the React portal together, and open it in a browser.

    This is the one-command dev entry point: starts uvicorn, starts the Vite dev server
    (installing portal deps on first run), opens http://localhost:<portal-port>, and shuts
    both down cleanly on Ctrl-C.
    """

    import os
    import subprocess
    import sys
    import threading
    import time
    import webbrowser

    frontend = Path(__file__).resolve().parent.parent / "frontend"
    if not frontend.exists():
        console.print(
            f"[red]No frontend/ directory at {frontend}. "
            "Run `talos dev` from a source checkout (the bundled binary can't serve the portal).[/red]"
        )
        raise typer.Exit(1)

    if not (frontend / "node_modules").exists():
        console.print("[cyan]Installing portal dependencies (first run)…[/cyan]")
        if subprocess.run(["npm", "install"], cwd=frontend).returncode != 0:
            console.print("[red]npm install failed.[/red]")
            raise typer.Exit(1)

    api_url = f"http://127.0.0.1:{api_port}"
    portal_url = f"http://localhost:{portal_port}"
    console.print(f"[cyan]API[/cyan]    {api_url}")
    console.print(f"[cyan]Portal[/cyan] {portal_url}")

    procs: list[subprocess.Popen] = []
    try:
        procs.append(
            subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "talos.api:app",
                 "--host", "127.0.0.1", "--port", str(api_port), "--log-level", "warning"]
            )
        )
        env = {**os.environ, "VITE_API_URL": api_url}
        procs.append(
            subprocess.Popen(
                ["npm", "run", "dev", "--", "--port", str(portal_port), "--strictPort"],
                cwd=frontend, env=env,
            )
        )

        if not no_open:
            def _open() -> None:
                time.sleep(2.5)
                webbrowser.open(portal_url)

            threading.Thread(target=_open, daemon=True).start()

        console.print("[dim]Ctrl-C to stop both.[/dim]")
        while all(p.poll() is None for p in procs):
            time.sleep(0.4)
        console.print("[yellow]One process exited; shutting the other down.[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[cyan]Shutting down…[/cyan]")
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


@app.command()
def ack(
    pid: int = typer.Argument(..., help="PID to acknowledge."),
    kill_ok: bool = typer.Option(False, "--kill-ok", help="Acknowledge but still allow killing."),
    category: Optional[str] = typer.Option(None, "--category"),
    note: Optional[str] = typer.Option(None, "--note"),
) -> None:
    """Mark a process as known — don't flag it again (and, by default, never kill it).

    Persisted by content hash + path, so it sticks across scans and restarts.
    """

    from .signing import inspect_signature
    from .store import LearnedStore, entry_key

    proc = collect.get_process(pid)
    if not proc:
        console.print(f"[red]No process with pid {pid}[/red]")
        raise typer.Exit(1)
    sig = inspect_signature(proc.exe, hash_file=True)
    key = entry_key(proc.name, proc.exe, sig.sha256)
    LearnedStore().set_user(
        key, acknowledged=True, do_not_kill=not kill_ok, category=category, note=note,
        name=proc.name, exe=proc.exe, sha256=sig.sha256,
    )
    console.print(
        f"[green]Acknowledged[/green] {proc.name} (pid {pid}) — "
        f"{'do-not-kill' if not kill_ok else 'killable'}. Won't be flagged again."
    )


@app.command()
def forget(pid: int = typer.Argument(..., help="PID whose acknowledgement to clear.")) -> None:
    """Remove a process from the acknowledged / do-not-kill list."""

    from .signing import inspect_signature
    from .store import LearnedStore, entry_key

    proc = collect.get_process(pid)
    if not proc:
        console.print(f"[red]No process with pid {pid}[/red]")
        raise typer.Exit(1)
    sig = inspect_signature(proc.exe, hash_file=True)
    key = entry_key(proc.name, proc.exe, sig.sha256)
    ok = LearnedStore().clear_user(key)
    console.print("[green]Cleared.[/green]" if ok else "[yellow]No acknowledgement found.[/yellow]")


@app.command()
def learned() -> None:
    """List remembered analyses + the acknowledged / do-not-kill list."""

    from rich.table import Table
    from .store import LearnedStore

    entries = sorted(LearnedStore().all(), key=lambda e: e.get("last_analyzed", ""), reverse=True)
    if not entries:
        console.print("Nothing learned yet — run a scan.")
        return
    t = Table(title=f"Learned store ({len(entries)} binaries)", title_justify="left")
    t.add_column("name"); t.add_column("category"); t.add_column("ack", justify="center")
    t.add_column("last analyzed"); t.add_column("what it is", overflow="fold", max_width=60)
    for e in entries[:200]:
        u = e.get("user") or {}
        ack_mark = "🔒" if u.get("do_not_kill") else ("✓" if u.get("acknowledged") else "")
        t.add_row(
            e.get("name", "?"), e.get("category", "?"), ack_mark,
            (e.get("last_analyzed") or "")[:10], e.get("description", ""),
        )
    console.print(t)


@app.command()
def audit(limit: int = typer.Option(50, "--limit")) -> None:
    """Show the termination audit log."""

    entries = actions.read_audit_log(limit)
    if not entries:
        console.print("No audit entries yet.")
        return
    for e in entries:
        console.print(json.dumps(e))


if __name__ == "__main__":
    app()
