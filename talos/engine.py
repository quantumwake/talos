"""Top-level scan orchestration shared by the CLI and the API.

One call — ``scan()`` — runs the whole pipeline: enumerate processes, gather network
connections, resolve egress reputation, classify via the ladder, and score risk. Returns
a ``ScanResult`` that both the rich CLI report and the FastAPI responses consume.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from concurrent.futures import ThreadPoolExecutor

from . import collect, network, risk
from .classify import Classifier
from .config import Settings
from .knowledge import KnowledgeBase
from .models import ProcessInfo
from .reputation import asn
from .signing import inspect_signature
from .store import LearnedStore


@dataclass
class ScanResult:
    processes: list[ProcessInfo] = field(default_factory=list)
    privilege: dict = field(default_factory=dict)
    duration_s: float = 0.0
    settings: Settings | None = None

    def sorted_by_risk(self) -> list[ProcessInfo]:
        return sorted(
            self.processes,
            key=lambda p: (p.verdict.risk_score if p.verdict else 0),
            reverse=True,
        )


def scan(settings: Settings, progress=None, store: "LearnedStore | None" = None,
         on_process=None) -> ScanResult:
    """Run a full scan.

    ``progress(phase, done, total, current)`` reports status. ``on_process(proc)`` is called
    as each process finishes classification — used to stream results to the UI live.
    """

    started = time.monotonic()

    def step(msg: str, done: int = 0, total: int = 0, current: str = "") -> None:
        if progress:
            progress(msg, done, total, current)

    step("Enumerating processes…")
    procs = collect.collect_processes(with_cpu=True)
    priv = collect.privilege_summary()

    if settings.collect_network:
        step("Gathering network connections…")
        for p in procs:
            network.attach_connections(p, settings)

        if settings.resolve_asn:
            step("Resolving egress reputation (ASN/org)…")
            all_conns = [c for p in procs for c in p.connections if c.is_egress]
            asn.resolve_connections(all_conns)
            # Re-flag now that rDNS/org are populated.
            for p in procs:
                for c in p.connections:
                    c.flags = network.flag_connection(c, settings)

    # Warm the signature cache in parallel — codesign/spctl are subprocess calls and
    # are the dominant cost of a scan. inspect_signature() caches by (path, mtime, size),
    # so the serial classify() pass below just reads the warmed cache.
    step("Verifying code signatures…")
    need_hash = settings.use_virustotal or settings.use_llm
    exes = {p.exe for p in procs if p.exe}
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda e: inspect_signature(e, hash_file=need_hash), exes))

    step("Classifying processes…")
    kb = KnowledgeBase()
    store = store or LearnedStore()
    classifier = Classifier(settings, kb=kb, store=store)
    total = len(procs)
    for i, p in enumerate(procs, 1):
        p.verdict = classifier.classify(p)
        risk.score_process(p, settings)
        if on_process:
            on_process(p)
        if i % 10 == 0 or i == total:
            step("Classifying processes", i, total, p.name)
    store.flush()  # persist all learned analyses in one write

    return ScanResult(
        processes=procs,
        privilege=priv,
        duration_s=time.monotonic() - started,
        settings=settings,
    )
