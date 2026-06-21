import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { api, scanStream, type ScanOpts } from "./api";
import type { Report, ProcSummary, RiskTier, Summary } from "./types";
import { Drawer } from "./Drawer";
import { ReapModal } from "./ReapModal";
import { ProgressBar, LiveResults, LearnedView, AuditView, EgressView, ChangesView, ResourceBar } from "./Views";
import type { Progress, ScanListItem } from "./types";

const TIER_ORDER: RiskTier[] = ["critical", "high", "medium", "low"];
type Tab = "processes" | "changes" | "egress" | "learned" | "audit";

const EMPTY_SUMMARY: Summary = {
  total: 0,
  by_tier: { critical: 0, high: 0, medium: 0, low: 0 },
  by_category: {},
  safe_to_kill: 0,
  flagged_egress: 0,
};

const CATEGORY_PRIORITY = [
  "malicious", "suspicious", "unknown", "known_safe_to_kill",
  "trusted_app", "system_service", "system_critical",
];

function appKeyOf(p: ProcSummary): string {
  for (const m of [" Helper", " Renderer", " (GPU)", " (Plugin)"])
    if (p.name.includes(m)) return p.name.split(m)[0];
  return p.vendor || p.name;
}

function groupProcs(procs: ProcSummary[], by: "category" | "app"): [string, ProcSummary[]][] {
  const m = new Map<string, ProcSummary[]>();
  for (const p of procs) {
    const k = by === "category" ? p.category : appKeyOf(p);
    if (!m.has(k)) m.set(k, []);
    m.get(k)!.push(p);
  }
  const entries = [...m.entries()];
  if (by === "category")
    entries.sort((a, b) => CATEGORY_PRIORITY.indexOf(a[0]) - CATEGORY_PRIORITY.indexOf(b[0]));
  else
    entries.sort((a, b) =>
      b[1].reduce((s, p) => s + (p.memory_mb || 0), 0) - a[1].reduce((s, p) => s + (p.memory_mb || 0), 0));
  return entries;
}

// Compute the summary client-side so cards/chips update live as processes stream in.
function computeSummary(procs: ProcSummary[]): Summary {
  const s: Summary = {
    total: procs.length,
    by_tier: { critical: 0, high: 0, medium: 0, low: 0 },
    by_category: {},
    safe_to_kill: 0,
    flagged_egress: 0,
  };
  for (const p of procs) {
    s.by_tier[p.risk_tier]++;
    s.by_category[p.category] = (s.by_category[p.category] || 0) + 1;
    if (p.safe_to_kill) s.safe_to_kill++;
    if ((p.egress_flags ?? []).length) s.flagged_egress++;
  }
  return s;
}

export function App() {
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opts, setOpts] = useState<ScanOpts>({
    use_llm: false,
    use_virustotal: false,
    collect_network: true,
    resolve_asn: true,
  });

  const [query, setQuery] = useState("");
  const [cat, setCat] = useState<string | null>(null);
  const [tier, setTier] = useState<RiskTier | null>(null);
  const [safeOnly, setSafeOnly] = useState(false);
  const [egressOnly, setEgressOnly] = useState(false);
  const [sortKey, setSortKey] = useState<"risk_score" | "memory_mb" | "cpu_percent" | "name">("risk_score");
  const [groupBy, setGroupBy] = useState<"category" | "app" | "none">("category");
  // The big benign groups start collapsed — ~1000 procs are mostly system services.
  const [collapsed, setCollapsed] = useState<Set<string>>(
    () => new Set(["system_service", "system_critical", "trusted_app"])
  );
  const toggleGroup = (k: string) =>
    setCollapsed((c) => {
      const n = new Set(c);
      n.has(k) ? n.delete(k) : n.add(k);
      return n;
    });
  const [selected, setSelected] = useState<number | null>(null);
  const [showReap, setShowReap] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [webSearch, setWebSearch] = useState(false);
  const [tab, setTab] = useState<Tab>("processes");
  const [progress, setProgress] = useState<Progress | null>(null);
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [viewingId, setViewingId] = useState<string | null>(null); // non-null = historical

  const loadScans = () => api.scansList().then((r) => setScans(r.scans)).catch(() => {});

  function viewScan(id: string) {
    if (!id) {
      setViewingId(null);
      api.report().then(setReport).catch(() => {});
      return;
    }
    setViewingId(id);
    api.getScan(id).then(setReport).catch((e) => setError(e.message));
  }

  // Poll the backend for progress while a scan/analyze is running so the UI isn't blank.
  const busy = loading || analyzing;
  useEffect(() => {
    if (!busy) {
      setProgress(null);
      return;
    }
    const id = setInterval(() => {
      api.progress().then((p) => p.active && setProgress(p)).catch(() => {});
    }, 400);
    return () => clearInterval(id);
  }, [busy]);

  async function runAnalyze() {
    setAnalyzing(true);
    setError(null);
    try {
      const grp = cat ? { category: cat } : tier ? { tier } : { category: "unknown" };
      const r = await api.analyzeGroup({ ...grp, web_search: webSearch });
      setReport(await api.report());
      if (r.analyzed === 0) setError("Nothing left to analyze in that group (already known).");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setAnalyzing(false);
    }
  }

  const esRef = useRef<EventSource | null>(null);

  function runScan() {
    setLoading(true);
    setError(null);
    setTab("processes");
    const acc: ProcSummary[] = [];
    esRef.current?.close();
    esRef.current = scanStream(opts, {
      // Fill the dashboard live as each process is classified (throttled to keep the
      // growing table smooth — the `done` event sets the final authoritative list).
      onProcess: (p) => {
        acc.push(p);
        if (acc.length % 12 === 0) {
          setReport((r) => ({
            duration_s: 0,
            privilege: r?.privilege ?? { running_as_root: false },
            summary: r?.summary ?? EMPTY_SUMMARY,
            processes: acc.slice(),
          }));
        }
      },
      onDone: (r) => {
        setReport(r); // authoritative, sorted, with privilege + summary + diff
        setViewingId(null);
        loadScans();
        setLoading(false);
      },
      onFail: (msg) => {
        setError(msg);
        setLoading(false);
      },
    });
  }

  useEffect(() => () => esRef.current?.close(), []);

  // On mount, only fetch a cached report if a scan has actually run — avoids a
  // spurious 409 in the console when the backend has no scan yet.
  useEffect(() => {
    api
      .health()
      .then((h) => {
        loadScans();
        if (h.last_scan_at > 0) return api.report().then(setReport);
      })
      .catch((e) => setError(`Cannot reach API (${e.message}). Is the backend running?`));
  }, []);

  const procs = report?.processes ?? [];

  const filtered = useMemo(() => {
    let r = procs.filter((p) => {
      if (cat && p.category !== cat) return false;
      if (tier && p.risk_tier !== tier) return false;
      if (safeOnly && !p.safe_to_kill) return false;
      if (egressOnly && p.egress_flags.length === 0) return false;
      if (query) {
        const q = query.toLowerCase();
        if (!p.name.toLowerCase().includes(q) && !String(p.pid).includes(q) &&
            !(p.description || "").toLowerCase().includes(q)) return false;
      }
      return true;
    });
    r = [...r].sort((a, b) =>
      sortKey === "name"
        ? a.name.localeCompare(b.name)
        : (b[sortKey] as number) - (a[sortKey] as number)
    );
    return r;
  }, [procs, cat, tier, safeOnly, egressOnly, query, sortKey]);

  const groups = useMemo(
    () => (groupBy === "none" ? [] : groupProcs(filtered, groupBy)),
    [filtered, groupBy]
  );

  const s = report ? computeSummary(report.processes) : null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>
            TAL<span className="dot">O</span>S
          </h1>
          <span className="sub">macOS process verification &amp; egress audit</span>
        </div>
        <div className="spacer" />
        <div className="controls">
          {scans.length > 0 && (
            <select className="history-select" value={viewingId ?? ""}
              onChange={(e) => viewScan(e.target.value)} title="view a previous scan">
              <option value="">latest scan</option>
              {scans.map((sc) => (
                <option key={sc.id} value={sc.id}>
                  {new Date(sc.scanned_at * 1000).toLocaleString()} · {sc.summary?.total ?? "?"} procs
                  {sc.diff?.new ? ` (+${sc.diff.new})` : ""}
                </option>
              ))}
            </select>
          )}
          <label className="toggle">
            <input type="checkbox" checked={opts.collect_network}
              onChange={(e) => setOpts({ ...opts, collect_network: e.target.checked })} />
            network
          </label>
          <label className="toggle">
            <input type="checkbox" checked={opts.use_virustotal}
              onChange={(e) => setOpts({ ...opts, use_virustotal: e.target.checked })} />
            virustotal
          </label>
          <label className="toggle">
            <input type="checkbox" checked={opts.use_llm}
              onChange={(e) => setOpts({ ...opts, use_llm: e.target.checked })} />
            claude
          </label>
          <label className="toggle" title="let Claude search the web for binaries it doesn't recognise">
            <input type="checkbox" checked={webSearch}
              onChange={(e) => setWebSearch(e.target.checked)} />
            web search
          </label>
          {s && s.safe_to_kill > 0 && (
            <button className="danger" onClick={() => setShowReap(true)} title="terminate all safe-to-kill processes">
              ⚡ free up {s.safe_to_kill}
            </button>
          )}
          <button className="primary" onClick={runScan} disabled={loading}>
            {loading ? "scanning…" : report ? "rescan" : "scan"}
          </button>
        </div>
      </header>

      {busy && progress && (
        <>
          <ProgressBar phase={progress.phase} done={progress.done} total={progress.total}
            current={progress.current} />
          {progress.recent?.length > 0 && <LiveResults items={progress.recent} />}
        </>
      )}
      <ResourceBar />
      {error && <div className="banner warn">⚠ {error}</div>}
      {viewingId && report?.scanned_at && (
        <div className="banner warn">
          📅 Viewing a previous scan from {new Date(report.scanned_at * 1000).toLocaleString()} —
          this is historical and may include processes that have since ended.{" "}
          <a onClick={() => viewScan("")} style={{ cursor: "pointer", textDecoration: "underline" }}>
            back to latest
          </a>
        </div>
      )}
      {report?.privilege?.hint && <div className="hint">⚠ {report.privilege.hint}</div>}

      {s && (
        <div className="cards">
          <Card cls="accent" n={s.total} l="processes" />
          <Card cls="tier-critical" n={s.by_tier.critical} l="critical" />
          <Card cls="tier-high" n={s.by_tier.high} l="high risk" />
          <Card cls="tier-medium" n={s.by_tier.medium} l="medium" />
          <Card cls="tier-low" n={s.by_tier.low} l="low" />
          <Card cls="accent" n={s.safe_to_kill} l="safe to kill" />
          <Card cls="tier-high" n={s.flagged_egress} l="weird egress" />
        </div>
      )}

      {report && (
        <nav className="tabs">
          {(["processes", "changes", "egress", "learned", "audit"] as Tab[]).map((t) => (
            <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
              {t === "egress" ? "weird egress" : t}
              {t === "changes" && report?.diff && !report.diff.baseline && report.diff.new > 0
                ? ` (${report.diff.new})` : ""}
            </button>
          ))}
        </nav>
      )}

      {report && tab === "changes" && <ChangesView report={report} onSelect={setSelected} />}
      {report && tab === "egress" && <EgressView onSelect={setSelected} />}
      {report && tab === "learned" && <LearnedView />}
      {report && tab === "audit" && <AuditView />}

      {report && tab === "processes" && (
        <>
          <div className="filters">
            <input type="text" placeholder="filter by name / pid / description…"
              value={query} onChange={(e) => setQuery(e.target.value)} />
            {TIER_ORDER.map((t) => (
              <Chip key={t} label={`${t} ${s ? `(${s.by_tier[t]})` : ""}`} active={tier === t}
                tone={t} onClick={() => setTier(tier === t ? null : t)} />
            ))}
          </div>
          <div className="filters">
            <Chip label="all categories" active={!cat} onClick={() => setCat(null)} />
            {s && Object.keys(s.by_category).map((c) => (
              <Chip key={c} label={`${c} (${s.by_category[c]})`} active={cat === c}
                onClick={() => setCat(cat === c ? null : c)} />
            ))}
            <Chip label="safe-to-kill" active={safeOnly} onClick={() => setSafeOnly(!safeOnly)} />
            <Chip label="flagged egress" active={egressOnly} onClick={() => setEgressOnly(!egressOnly)} />
            <button onClick={runAnalyze} disabled={analyzing} title="Send this group to Claude to identify them">
              {analyzing ? "🤖 analyzing…" : `🤖 analyze ${cat || tier || "unknown"} with Claude`}
            </button>
          </div>

          <div className="filters">
            <span className="muted-line">group:</span>
            {(["category", "app", "none"] as const).map((g) => (
              <Chip key={g} label={g} active={groupBy === g} onClick={() => setGroupBy(g)} />
            ))}
            {groupBy !== "none" && (
              <>
                <button onClick={() => setCollapsed(new Set(groups.map((g) => g[0])))}>collapse all</button>
                <button onClick={() => setCollapsed(new Set())}>expand all</button>
              </>
            )}
          </div>

          <table className="table">
            <thead>
              <tr>
                <th className="num" onClick={() => setSortKey("risk_score")}>risk</th>
                <th className="num">pid</th>
                <th onClick={() => setSortKey("name")}>process</th>
                <th>category</th>
                <th className="num" onClick={() => setSortKey("cpu_percent")}>cpu</th>
                <th className="num" onClick={() => setSortKey("memory_mb")}>mem mb</th>
                <th>kill?</th>
                <th>egress</th>
                <th>what it is / why</th>
              </tr>
            </thead>
            <tbody>
              {groupBy === "none"
                ? filtered.map((p) => <Row key={p.pid} p={p} onClick={() => setSelected(p.pid)} />)
                : groups.map(([key, rows]) => {
                    const mem = rows.reduce((a, p) => a + (p.memory_mb || 0), 0);
                    const cpu = rows.reduce((a, p) => a + (p.cpu_percent || 0), 0);
                    const isCol = collapsed.has(key);
                    return (
                      <Fragment key={key}>
                        <tr className="group-header" onClick={() => toggleGroup(key)}>
                          <td colSpan={9}>
                            <span className="gh-caret">{isCol ? "▸" : "▾"}</span>
                            <span className={`gh-name cat-${key}`}>{key}</span>
                            <span className="group-meta">
                              {rows.length} procs · {mem.toFixed(0)} MB · {cpu.toFixed(0)}% cpu
                            </span>
                          </td>
                        </tr>
                        {!isCol && rows.map((p) => <Row key={p.pid} p={p} onClick={() => setSelected(p.pid)} />)}
                      </Fragment>
                    );
                  })}
            </tbody>
          </table>
          {filtered.length === 0 && <div className="empty">No processes match the current filter.</div>}
        </>
      )}

      {!report && !loading && (
        <div className="loading">Run a scan to audit running processes.</div>
      )}
      {loading && !report && <div className="loading">scanning processes…</div>}

      {selected !== null && (
        <Drawer pid={selected} onClose={() => setSelected(null)} onChanged={runScan} />
      )}
      {showReap && (
        <ReapModal onClose={() => setShowReap(false)} onDone={() => { setShowReap(false); runScan(); }} />
      )}
    </div>
  );
}

function Card({ n, l, cls }: { n: number; l: string; cls: string }) {
  return (
    <div className={`card ${cls}`}>
      <div className="n">{n}</div>
      <div className="l">{l}</div>
    </div>
  );
}

function Chip({ label, active, onClick, tone }: { label: string; active: boolean; onClick: () => void; tone?: string }) {
  return (
    <span className={`chip ${active ? "active" : ""} ${tone ? `chip-${tone}` : ""}`} onClick={onClick}>{label}</span>
  );
}

function Row({ p, onClick }: { p: ProcSummary; onClick: () => void }) {
  const flags = p.egress_flags ?? [];
  const reasons = p.reasons ?? [];
  return (
    <tr onClick={onClick}>
      <td className="num">
        <span className={`risk-pill risk-${p.risk_tier}`}>{p.risk_score}</span>
      </td>
      <td className="num">{p.pid}</td>
      <td>{p.name}{p.state === "new" && <span className="new-badge">new</span>}</td>
      <td className={`cat cat-${p.category}`}>{p.category}</td>
      <td className="num">{(p.cpu_percent ?? 0).toFixed(0)}</td>
      <td className="num">{(p.memory_mb ?? 0).toFixed(0)}</td>
      <td className={p.safe_to_kill ? "kill-yes" : "kill-no"}>{p.safe_to_kill ? "✓" : "·"}</td>
      <td className={flags.length ? "egress-flag" : "kill-no"}>
        {flags.length ? `⚠ ${flags.length}` : "·"}
      </td>
      <td className="desc">
        {p.description}
        {reasons.length > 0 && <div className="reasons">{reasons.slice(0, 2).join("; ")}</div>}
      </td>
    </tr>
  );
}
