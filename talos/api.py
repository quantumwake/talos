"""FastAPI backend over the same engine the CLI uses.

Scans are relatively expensive (subprocess-heavy), so results are cached in memory and
re-used until the client asks for a fresh scan. The React portal talks to these endpoints.

Endpoints:
    POST /scan              run a fresh scan (body: ScanRequest)
    GET  /report            cached grouped report + summary
    GET  /processes         flat list (filterable by ?min_risk=&category=&safe_only=)
    GET  /process/{pid}     full detail for one process
    GET  /egress            processes with flagged outbound connections
    POST /terminate         guarded kill (body: {pid, confirm, force})
    GET  /audit-log         recent termination audit entries
    GET  /health
"""

from __future__ import annotations

import json
import queue
import threading
import time
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import actions, collect, engine, history, report, resources, risk
from .classify import Classifier
from .config import Settings
from .models import to_dict
from .network import egress_summary
from .signing import inspect_signature
from .store import LearnedStore, entry_key

_store = LearnedStore()  # shared across scans + acknowledge actions

app = FastAPI(title="Talos", version="0.1.0")

# The Vite dev server runs on 5173 by default; allow it plus localhost variants.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_lock = threading.Lock()
_last_scan: Optional[engine.ScanResult] = None
_last_scan_at: float = 0.0
# Finalized portal payload of the most recent scan (live or loaded from disk on startup),
# so previous scans survive a backend restart and /report can serve them.
_last_payload: Optional[dict] = history.latest_scan()
if _last_payload:
    _last_scan_at = _last_payload.get("scanned_at", 0.0)


def _finalize(result: engine.ScanResult) -> dict:
    """Build the payload, diff it against the previous scan, persist it, and cache it."""

    global _last_payload, _last_scan_at
    payload = _portal_payload(result)
    payload["scanned_at"] = time.time()
    payload["diff"] = history.diff_against_previous(payload, history.latest_scan())
    payload["id"] = history.persist_scan(payload)
    _last_payload = payload
    _last_scan_at = payload["scanned_at"]
    return payload

# Lightweight progress state, polled by the portal during long operations. Updated from the
# worker thread; read (lock-free) by GET /progress on another thread. ``recent`` is the
# growing list of items finished so far in the current op (so the UI can list them live).
_progress: dict = {"active": False, "op": "", "phase": "", "done": 0, "total": 0, "current": "", "recent": []}
_prog_lock = threading.Lock()


def _set_progress(active: bool, op: str = "", phase: str = "", done: int = 0,
                  total: int = 0, current: str = "") -> None:
    _progress.update(active=active, op=op, phase=phase, done=done, total=total, current=current)


def _progress_start(op: str) -> None:
    _progress.update(active=True, op=op, phase="starting…", done=0, total=0, current="", recent=[])


def _progress_add_recent(items: list[dict]) -> None:
    with _prog_lock:
        _progress["recent"] = (_progress["recent"] + items)[-300:]


@app.get("/progress")
def progress() -> dict:
    with _prog_lock:
        return dict(_progress)


class ScanRequest(BaseModel):
    use_llm: bool = False
    use_virustotal: bool = False
    collect_network: bool = True
    resolve_asn: bool = True
    llm_model: Optional[str] = None


class TerminateRequest(BaseModel):
    pid: int
    confirm: bool = False
    force: bool = False


class AckRequest(BaseModel):
    pid: Optional[int] = None      # acknowledge a running process by PID
    key: Optional[str] = None      # OR address a learned entry directly by key
    do_not_kill: bool = True       # add to the persistent do-not-kill list
    acknowledged: bool = True      # mark as "known — don't flag again"
    category: Optional[str] = None  # optionally force a category
    note: Optional[str] = None


class AnalyzeGroupRequest(BaseModel):
    """Auto-analyze a group of processes with Claude in one shot."""

    category: Optional[str] = None   # e.g. "unknown"
    tier: Optional[str] = None       # e.g. "high"
    min_risk: int = 0
    pids: Optional[list[int]] = None
    limit: int = 60                  # cap how many to send to the LLM
    web_search: bool = False         # let Claude search the web for unknown binaries


class ReapRequest(BaseModel):
    """Bulk-terminate the safe-to-kill set ('feeling lucky — free up processes')."""

    confirm: bool = False        # False = dry-run preview
    min_risk: int = 0            # only reap safe-to-kill procs at/above this risk score
    max_memory_mb: float = 0.0   # 0 = no cap; otherwise reap biggest first up to this much


def _settings_from(req: ScanRequest) -> Settings:
    s = Settings(
        use_llm=req.use_llm,
        use_virustotal=req.use_virustotal,
        collect_network=req.collect_network,
        resolve_asn=req.resolve_asn and req.collect_network,
    )
    if req.llm_model:
        s.llm_model = req.llm_model
    return s


def _require_scan() -> engine.ScanResult:
    if _last_scan is None:
        raise HTTPException(status_code=409, detail="No scan yet. POST /scan first.")
    return _last_scan


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "last_scan_at": _last_scan_at}


@app.get("/system")
def system() -> dict:
    """Live system-wide resource metrics (CPU/mem/disk/net + best-effort GPU)."""
    return resources.system_snapshot()


@app.post("/scan")
def run_scan(req: ScanRequest = ScanRequest()) -> dict:
    global _last_scan, _last_scan_at
    with _lock:
        settings = _settings_from(req)
        _progress_start("scan")
        try:
            result = engine.scan(
                settings, store=_store,
                progress=lambda phase, done=0, total=0, current="": _set_progress(
                    True, "scan", phase, done, total, current),
            )
            _last_scan = result
            payload = _finalize(result)
        finally:
            _set_progress(False)
    return payload


@app.get("/scan/stream")
def scan_stream(
    network: bool = True, vt: bool = False, llm: bool = False, asn: bool = True,
) -> StreamingResponse:
    """Run a scan and stream results over SSE as each process is classified.

    Emits `progress` events (phase/done/total/current), a `process` event per classified
    process (so the dashboard fills in live), and a final `done` event with the authoritative
    sorted report. This is the queue model: the scan runs on a worker thread and pushes
    events onto a queue that this generator drains.
    """

    settings = _settings_from(ScanRequest(
        use_llm=llm, use_virustotal=vt, collect_network=network, resolve_asn=asn and network,
    ))
    q: "queue.Queue" = queue.Queue()

    def run() -> None:
        global _last_scan, _last_scan_at
        try:
            _progress_start("scan")

            def on_proc(p) -> None:
                q.put(("process", _proc_summary(p)))

            def prog(phase, done=0, total=0, current="") -> None:
                _set_progress(True, "scan", phase, done, total, current)
                q.put(("progress", {"phase": phase, "done": done, "total": total, "current": current}))

            with _lock:
                result = engine.scan(settings, progress=prog, store=_store, on_process=on_proc)
                _last_scan = result
                payload = _finalize(result)
            q.put(("done", payload))
        except Exception as exc:  # surface to the client instead of hanging
            # named "fail" so it doesn't collide with EventSource's native "error" event
            q.put(("fail", {"detail": str(exc)}))
        finally:
            _set_progress(False)
            q.put((None, None))

    threading.Thread(target=run, daemon=True).start()

    def gen():
        while True:
            kind, data = q.get()
            if kind is None:
                break
            yield f"event: {kind}\ndata: {json.dumps(data)}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/report")
def get_report() -> dict:
    # Serve the finalized payload (with diff/states), which survives a backend restart.
    if _last_payload is not None:
        return _last_payload
    raise HTTPException(status_code=409, detail="No scan yet. POST /scan first.")


@app.get("/scans")
def scans() -> dict:
    """Previous scans (newest first) for the history picker."""
    return {"scans": history.list_scans()}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    payload = history.load_scan(scan_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"No scan {scan_id}")
    return payload


def _portal_payload(result: engine.ScanResult) -> dict:
    """Flat, portal-friendly shape: summary + privilege + flat process summaries.

    (The CLI's --json export uses report.to_json(), which is the richer *nested* shape.)
    """

    return {
        "duration_s": round(result.duration_s, 2),
        "privilege": result.privilege,
        "summary": report._summary(result),
        "processes": [_proc_summary(p) for p in result.sorted_by_risk()],
    }


@app.get("/processes")
def get_processes(
    min_risk: int = 0, category: Optional[str] = None, safe_only: bool = False
) -> dict:
    result = _require_scan()
    procs = result.sorted_by_risk()
    out = []
    for p in procs:
        v = p.verdict
        if not v:
            continue
        if v.risk_score < min_risk:
            continue
        if category and v.category.value != category:
            continue
        if safe_only and not v.safe_to_kill:
            continue
        out.append(_proc_summary(p))
    return {"count": len(out), "processes": out}


@app.get("/process/{pid}")
def get_process(pid: int) -> dict:
    # Re-inspect live so the detail view is always current, not stale from last scan.
    proc = collect.get_process(pid)
    if not proc:
        raise HTTPException(status_code=404, detail=f"No process {pid}")
    from . import network as net
    from .reputation import asn as asn_mod

    settings = Settings()
    net.attach_connections(proc, settings)
    asn_mod.resolve_connections([c for c in proc.connections if c.is_egress])
    for c in proc.connections:
        c.flags = net.flag_connection(c, settings)
    proc.verdict = Classifier(settings, store=_store).classify(proc)
    risk.score_process(proc, settings)
    return _proc_detail(proc)


@app.get("/egress")
def get_egress() -> dict:
    """Processes with at least one flagged outbound connection — the 'weird egress' view."""

    result = _require_scan()
    out = []
    for p in result.processes:
        es = egress_summary(p)
        if es["flagged_count"]:
            out.append({**_proc_summary(p), "egress": es})
    out.sort(key=lambda x: x["egress"]["flagged_count"], reverse=True)
    return {"count": len(out), "processes": out}


@app.post("/terminate")
def terminate(req: TerminateRequest) -> dict:
    result = _require_scan()
    proc = next((p for p in result.processes if p.pid == req.pid), None)
    if proc is None:
        proc = collect.get_process(req.pid)
        if proc:
            proc.verdict = Classifier(Settings(), store=_store).classify(proc)
            risk.score_process(proc, Settings())
    if proc is None:
        raise HTTPException(status_code=404, detail=f"No process {req.pid}")

    res = actions.terminate(
        proc, dry_run=not req.confirm, force=req.force, reason="api"
    )
    return {
        "pid": res.pid,
        "name": res.name,
        "attempted": res.attempted,
        "killed": res.killed,
        "dry_run": res.dry_run,
        "method": res.method,
        "reason": res.reason,
    }


@app.post("/reap")
def reap(req: ReapRequest = ReapRequest()) -> dict:
    """Free up the safe-to-kill set in one shot.

    With ``confirm=false`` this is a dry-run preview: it returns what *would* be killed,
    grouped by app, with the total memory that would be reclaimed — nothing is terminated.
    With ``confirm=true`` it actually terminates them (subject to the same guards as a
    single /terminate: protected processes and self are never touched).
    """

    result = _require_scan()
    targets = [
        p
        for p in result.processes
        if p.verdict and p.verdict.safe_to_kill and p.verdict.risk_score >= req.min_risk
    ]
    # Biggest first so a memory cap frees the most with the fewest kills.
    targets.sort(key=lambda p: p.memory_mb, reverse=True)
    if req.max_memory_mb > 0:
        chosen, running = [], 0.0
        for p in targets:
            if running >= req.max_memory_mb:
                break
            chosen.append(p)
            running += p.memory_mb
        targets = chosen

    dry = not req.confirm
    results = []
    reclaimed = 0.0
    groups: dict[str, dict] = {}
    for p in targets:
        res = actions.terminate(p, dry_run=dry, reason="reap")
        acted = res.killed or res.dry_run
        if acted:
            reclaimed += p.memory_mb
        results.append({
            "pid": p.pid, "name": p.name, "memory_mb": round(p.memory_mb, 1),
            "killed": res.killed, "dry_run": res.dry_run, "method": res.method,
            "reason": res.reason,
        })
        g = groups.setdefault(_app_group(p), {"app": _app_group(p), "count": 0, "memory_mb": 0.0})
        g["count"] += 1
        g["memory_mb"] = round(g["memory_mb"] + p.memory_mb, 1)

    return {
        "dry_run": dry,
        "count": len(targets),
        "reclaimable_mb": round(reclaimed, 1),
        "groups": sorted(groups.values(), key=lambda g: g["memory_mb"], reverse=True),
        "results": results,
    }


@app.post("/analyze-group")
def analyze_group(req: AnalyzeGroupRequest) -> dict:
    """Run Claude over a group of processes (e.g. all 'unknown' or all 'high' risk).

    Each verdict is cached into the learned store, so once a binary is identified it keeps
    its description and stops being re-flagged on future scans. Optionally lets Claude use
    web search for binaries it doesn't recognise.
    """

    result = _require_scan()
    settings = Settings(use_llm=True, collect_network=False, resolve_asn=False)
    settings.llm_web_search = req.web_search

    from .knowledge import KnowledgeBase
    from .llm import LLMClassifier

    llmc = LLMClassifier(settings, KnowledgeBase())
    if not llmc.available():
        raise HTTPException(
            status_code=400,
            detail="No Claude backend available — install the `claude` CLI (headless) or set ANTHROPIC_API_KEY.",
        )

    targets = []
    for p in result.sorted_by_risk():
        v = p.verdict
        if not v:
            continue
        if req.pids is not None and p.pid not in req.pids:
            continue
        if req.category and v.category.value != req.category:
            continue
        if req.tier and v.risk_tier.value != req.tier:
            continue
        if v.risk_score < req.min_risk:
            continue
        if req.pids is None and v.source in ("user", "memory", "known_db", "protected", "self"):
            continue
        targets.append(p)
    targets = targets[: req.limit]
    if not targets:
        return {"analyzed": 0, "backend": llmc.backend_name(), "processes": []}

    label = f"asking Claude ({llmc.backend_name()})" + (" + web search" if req.web_search else "")
    _progress_start("analyze")

    def _on_progress(done, total, current):
        _set_progress(True, "analyze", label, done, total, current)

    try:
        analyzed = _analyze_in_chunks(
            targets, llmc, settings, on_progress=_on_progress, on_done=_progress_add_recent)
    finally:
        _set_progress(False)
    _store.flush()
    return {
        "analyzed": analyzed,
        "backend": llmc.backend_name(),
        "processes": [_proc_summary(p) for p in targets],
    }


def _analyze_in_chunks(targets, llmc, settings, chunk_size: int = 12,
                       on_progress=None, on_done=None) -> int:
    """Send processes to Claude in small chunks (one JSON list per call) and apply results.

    Chunking keeps the model grounded and is far cheaper than one call per process.
    Reports process-level progress: ``on_progress(done_procs, total_procs, current_names)``
    as chunks start/finish, and ``on_done(items)`` with each chunk's finished summaries so
    the UI can list results live.
    """

    from concurrent.futures import ThreadPoolExecutor

    from .classify import apply_llm_item
    from .store import entry_key

    chunks = [targets[i : i + chunk_size] for i in range(0, len(targets), chunk_size)]
    total = len(targets)
    state = {"done": 0, "inflight": {}}
    lock = threading.Lock()
    count = 0

    def _emit() -> None:
        if on_progress:
            names = ", ".join(n for names in state["inflight"].values() for n in names)
            on_progress(state["done"], total, names)

    def _do(chunk) -> int:
        cid = id(chunk)
        with lock:
            state["inflight"][cid] = [p.name for p in chunk]
            _emit()
        verdicts = llmc.classify_batch(chunk)
        n = 0
        finished = []
        for p in chunk:
            item = verdicts.get(p.pid)
            if item and "_error" not in item:
                apply_llm_item(p.verdict, item)
                _store.record(p, p.verdict, entry_key(p.name, p.exe, p.signing.sha256 if p.signing else None))
                n += 1
            risk.score_process(p, settings)
            finished.append(_proc_summary(p))
        with lock:
            state["done"] += len(chunk)
            state["inflight"].pop(cid, None)
            _emit()
        if on_done:
            on_done(finished)
        return n

    workers = 2 if settings.llm_web_search else 4
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for n in pool.map(_do, chunks):
            count += n
    return count


@app.post("/acknowledge")
def acknowledge(req: AckRequest) -> dict:
    """Mark a process's binary as known — don't flag it again, and (by default) never kill it.

    Persisted by content hash + path, so it survives restarts and applies on every future
    scan. This is the 'I know what this is, leave it alone' button.
    """

    if req.pid is None:
        raise HTTPException(status_code=400, detail="acknowledge needs a running pid.")
    proc = collect.get_process(req.pid)
    if not proc:
        raise HTTPException(status_code=404, detail=f"No process {req.pid}")
    sig = inspect_signature(proc.exe, hash_file=True)
    key = entry_key(proc.name, proc.exe, sig.sha256)
    entry = _store.set_user(
        key,
        acknowledged=req.acknowledged,
        do_not_kill=req.do_not_kill,
        category=req.category,
        note=req.note,
        name=proc.name,
        exe=proc.exe,
        sha256=sig.sha256,
    )
    return {"ok": True, "key": key, "entry": entry}


@app.post("/unacknowledge")
def unacknowledge(req: AckRequest) -> dict:
    # Address by key (from the learned list) or by a running PID.
    key = req.key
    if not key:
        if req.pid is None:
            raise HTTPException(status_code=400, detail="Provide a pid or a key.")
        proc = collect.get_process(req.pid)
        if not proc:
            raise HTTPException(status_code=404, detail=f"No process {req.pid}")
        key = entry_key(proc.name, proc.exe, inspect_signature(proc.exe, hash_file=True).sha256)
    return {"ok": _store.clear_user(key), "key": key}


@app.get("/learned")
def learned() -> dict:
    """The persistent learned store: remembered analyses + user acknowledge/do-not-kill list."""

    entries = _store.all()
    return {
        "count": len(entries),
        "acknowledged": [e for e in entries if (e.get("user") or {}).get("acknowledged")],
        "entries": sorted(entries, key=lambda e: e.get("last_analyzed", ""), reverse=True),
    }


class RemoveRequest(BaseModel):
    pid: int
    confirm: bool = False


def _resolve_proc(pid: int):
    proc = collect.get_process(pid)
    if not proc:
        raise HTTPException(status_code=404, detail=f"No process {pid}")
    proc.verdict = Classifier(Settings(), store=_store).classify(proc)
    risk.score_process(proc, Settings())
    return proc


@app.get("/remove-plan/{pid}")
def remove_plan(pid: int) -> dict:
    """Preview what uninstalling the app behind a process would move to Trash."""
    from . import uninstall
    p = uninstall.plan(_resolve_proc(pid))
    return {
        "app_bundle": p.app_bundle, "vendor": p.vendor,
        "trash": p.trash, "needs_sudo": p.needs_sudo, "blocked": p.blocked,
    }


@app.post("/remove")
def remove(req: RemoveRequest) -> dict:
    """Uninstall the app behind a process (move to Trash). Dry-run unless confirm=true."""
    from . import uninstall
    res = uninstall.remove(_resolve_proc(req.pid), dry_run=not req.confirm)
    return {
        "dry_run": res.dry_run, "blocked": res.blocked,
        "trashed": res.trashed, "failed": res.failed, "needs_sudo": res.needs_sudo,
    }


@app.get("/audit-log")
def audit_log(limit: int = 100) -> dict:
    return {"entries": actions.read_audit_log(limit)}


def _app_group(p) -> str:
    name = p.name
    for marker in (" Helper", " Renderer", " (GPU)", " (Plugin)"):
        if marker in name:
            return name.split(marker)[0]
    if p.verdict and p.verdict.vendor:
        return p.verdict.vendor
    return name


def _proc_summary(p) -> dict:
    v = p.verdict
    return {
        "pid": p.pid,
        "name": p.name,
        "username": p.username,
        "create_time": p.create_time,   # for stable identity across scans (with pid)
        "status": p.status,
        "memory_mb": round(p.memory_mb, 1),
        "cpu_percent": round(p.cpu_percent, 1),
        "category": v.category.value if v else "unknown",
        "risk_score": v.risk_score if v else 0,
        "risk_tier": v.risk_tier.value if v else "low",
        "safe_to_kill": bool(v and v.safe_to_kill),
        "description": v.description if v else "",
        "vendor": v.vendor if v else None,
        "reasons": v.reasons if v else [],
        "egress_flags": v.egress_flags if v else [],
        "signing": p.signing.trust.value if p.signing else None,
        "acknowledged": bool(v and v.acknowledged),
        "do_not_kill": bool(v and v.do_not_kill),
        "analyzed_at": v.analyzed_at if v else None,
    }


def _proc_detail(p) -> dict:
    """Flat summary + the extra fields the detail drawer needs."""

    d = _proc_summary(p)
    d.update(
        {
            "exe": p.exe,
            "cmdline": p.cmdline,
            "is_root": p.is_root,
            "connections": [to_dict(c) for c in p.connections],
            "signing": to_dict(p.signing) if p.signing else None,
            "bundle": p.bundle,
            "egress": egress_summary(p),
        }
    )
    return d
