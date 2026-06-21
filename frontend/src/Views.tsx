import { useEffect, useState } from "react";
import { api } from "./api";
import type { LearnedEntry, AuditEntry, ProcSummary, Report, SystemSnapshot } from "./types";

function fmtBps(b: number): string {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + " MB/s";
  if (b >= 1e3) return (b / 1e3).toFixed(0) + " KB/s";
  return b.toFixed(0) + " B/s";
}

function Meter({ label, value, sub, pct, tone }: { label: string; value: string; sub?: string; pct?: number; tone?: string }) {
  return (
    <div className="meter">
      <div className="meter-top">
        <span className="meter-label">{label}</span>
        <span className="meter-value">{value}</span>
      </div>
      {pct !== undefined && (
        <div className="meter-track">
          <div className={`meter-fill ${tone || ""}`} style={{ width: `${Math.min(100, pct)}%` }} />
        </div>
      )}
      {sub && <div className="meter-sub">{sub}</div>}
    </div>
  );
}

/** Live system-wide resource bar (CPU/mem/disk/net + best-effort GPU). Polls /system. */
export function ResourceBar() {
  const [s, setS] = useState<SystemSnapshot | null>(null);
  useEffect(() => {
    let on = true;
    const tick = () => api.system().then((d) => on && setS(d)).catch(() => {});
    tick();
    const id = setInterval(tick, 2500);
    return () => { on = false; clearInterval(id); };
  }, []);
  if (!s) return null;
  const memTone = s.memory.percent > 85 ? "hot" : s.memory.percent > 65 ? "warm" : "";
  const cpuTone = s.cpu.percent > 85 ? "hot" : s.cpu.percent > 60 ? "warm" : "";
  return (
    <div className="resource-bar">
      <Meter label="CPU" value={`${s.cpu.percent.toFixed(0)}%`} pct={s.cpu.percent} tone={cpuTone}
        sub={`${s.cpu.count} cores · load ${s.cpu.load_avg.map((x) => x.toFixed(1)).join(" ")}`} />
      <Meter label="Memory" value={`${s.memory.percent.toFixed(0)}%`} pct={s.memory.percent} tone={memTone}
        sub={`${(s.memory.used / 1e9).toFixed(1)} / ${(s.memory.total / 1e9).toFixed(0)} GB${s.swap.used ? ` · swap ${(s.swap.used / 1e9).toFixed(1)}G` : ""}`} />
      <Meter label="Network" value={`↓ ${fmtBps(s.net_io.recv_bps)}`} sub={`↑ ${fmtBps(s.net_io.sent_bps)}`} />
      <Meter label="Disk I/O" value={s.disk_io ? `R ${fmtBps(s.disk_io.read_bps)}` : "—"}
        sub={s.disk_io ? `W ${fmtBps(s.disk_io.write_bps)}` : "unavailable"} />
      <Meter label="GPU" value={s.gpu.available ? `${s.gpu.busy_percent?.toFixed(0)}%` : "—"}
        pct={s.gpu.available ? s.gpu.busy_percent : undefined}
        sub={s.gpu.available ? "busy" : s.gpu.reason} />
    </div>
  );
}

export function ChangesView({ report, onSelect }: { report: Report; onSelect: (pid: number) => void }) {
  const diff = report.diff;
  if (!diff) return <div className="empty">No diff available — run a scan.</div>;
  if (diff.baseline)
    return <div className="empty">This is the baseline scan — rescan later to see what changed.</div>;

  const news = report.processes.filter((p) => p.state === "new");
  const when = diff.previous_at ? new Date(diff.previous_at * 1000).toLocaleString() : "?";

  return (
    <>
      <div className="muted-line" style={{ marginBottom: 10 }}>
        vs previous scan ({when}): <b>{diff.active}</b> still running ·{" "}
        <b style={{ color: "var(--low)" }}>{diff.new}</b> new ·{" "}
        <b style={{ color: "var(--muted)" }}>{diff.inactive}</b> ended
      </div>

      <div className="section-title">▲ new since last scan ({news.length})</div>
      {news.length === 0 && <div className="empty">No new processes.</div>}
      {news.length > 0 && (
        <table className="table">
          <thead><tr><th className="num">risk</th><th>process</th><th>category</th><th className="num">mem</th><th>what it is</th></tr></thead>
          <tbody>
            {news.map((p) => (
              <tr key={p.pid} onClick={() => onSelect(p.pid)}>
                <td className="num"><span className={`risk-pill risk-${p.risk_tier}`}>{p.risk_score}</span></td>
                <td>{p.name} <span className="muted-line">#{p.pid}</span></td>
                <td className={`cat cat-${p.category}`}>{p.category}</td>
                <td className="num">{p.memory_mb.toFixed(0)}</td>
                <td className="desc">{p.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="section-title">▼ ended since last scan ({diff.inactive_list.length})</div>
      {diff.inactive_list.length === 0 && <div className="empty">Nothing ended.</div>}
      {diff.inactive_list.length > 0 && (
        <table className="table">
          <thead><tr><th>process</th><th>category</th><th className="num">was pid</th><th>what it was</th></tr></thead>
          <tbody>
            {diff.inactive_list.map((p, i) => (
              <tr key={i}>
                <td>{p.name}</td>
                <td className={`cat cat-${p.category}`}>{p.category}</td>
                <td className="num">{p.pid}</td>
                <td className="desc">{p.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export function ProgressBar({ phase, done, total, current }: { phase: string; done: number; total: number; current?: string }) {
  const pct = total > 0 ? Math.round((done / total) * 100) : null;
  return (
    <div className="progress">
      <div className="progress-row">
        <span className="spinner" />
        <span className="progress-phase">{phase || "working…"}</span>
        {pct !== null && <span className="progress-pct">{done}/{total}{pct !== null ? ` · ${pct}%` : ""}</span>}
      </div>
      {current && <div className="progress-current">▸ {current}</div>}
      <div className="progress-track">
        <div className={`progress-fill ${pct === null ? "indeterminate" : ""}`}
          style={pct !== null ? { width: `${pct}%` } : undefined} />
      </div>
    </div>
  );
}

export function LiveResults({ items }: { items: ProcSummary[] }) {
  if (!items.length) return null;
  return (
    <div className="live-results">
      <div className="section-title">completed ({items.length})</div>
      {[...items].reverse().map((p) => (
        <div className="live-row" key={p.pid}>
          <span className={`risk-pill risk-${p.risk_tier}`}>{p.risk_score}</span>
          <span className="live-name">{p.name}</span>
          <span className={`cat cat-${p.category}`}>{p.category}</span>
          <span className="live-desc">{p.description}</span>
        </div>
      ))}
    </div>
  );
}

export function LearnedView() {
  const [entries, setEntries] = useState<LearnedEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "acknowledged">("all");

  function load() {
    api.learned().then((r) => setEntries(r.entries)).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  if (error) return <div className="banner warn">⚠ {error}</div>;
  if (!entries) return <div className="loading">loading learned store…</div>;
  const rows = entries.filter((e) => filter === "all" || e.user?.acknowledged);

  return (
    <>
      <div className="filters">
        <span className="muted-line">{entries.length} binaries remembered · descriptions persist across scans</span>
        <span className="spacer" />
        <span className={`chip ${filter === "all" ? "active" : ""}`} onClick={() => setFilter("all")}>all</span>
        <span className={`chip ${filter === "acknowledged" ? "active" : ""}`} onClick={() => setFilter("acknowledged")}>
          acknowledged
        </span>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>process</th><th>category</th><th>state</th><th>analyses</th>
            <th>last analyzed</th><th>what it is</th><th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => (
            <tr key={e.key}>
              <td>{e.name}</td>
              <td className={`cat cat-${e.category}`}>{e.category}</td>
              <td>
                {e.user?.do_not_kill && <span className="learned-badge">🔒 do-not-kill</span>}
                {e.user?.acknowledged && !e.user?.do_not_kill && <span className="learned-badge">✓ ack</span>}
              </td>
              <td className="num">{e.analyses}</td>
              <td>{(e.last_analyzed || "").slice(0, 10)}</td>
              <td className="desc">{e.description}</td>
              <td>
                {e.user?.acknowledged && (
                  <button onClick={() => api.forgetKey(e.key).then(load)}>forget</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && <div className="empty">Nothing here yet.</div>}
    </>
  );
}

export function AuditView() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.auditLog().then((r) => setEntries(r.entries.reverse())).catch((e) => setError(e.message));
  }, []);
  if (error) return <div className="banner warn">⚠ {error}</div>;
  if (!entries) return <div className="loading">loading audit log…</div>;
  if (entries.length === 0) return <div className="empty">No terminations logged yet.</div>;
  return (
    <table className="table">
      <thead><tr><th>time</th><th>action</th><th>pid</th><th>process</th><th>method</th><th>result</th></tr></thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i}>
            <td>{(e.ts || "").replace("T", " ")}</td>
            <td>{e.action}</td>
            <td className="num">{e.pid ?? ""}</td>
            <td>{e.name ?? ""}</td>
            <td>{e.method ?? ""}</td>
            <td className={e.killed ? "kill-yes" : ""}>{e.killed ? "killed" : e.reason ?? ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function EgressView({ onSelect }: { onSelect: (pid: number) => void }) {
  const [procs, setProcs] = useState<(ProcSummary & { egress: any })[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.egress().then((r) => setProcs(r.processes)).catch((e) => setError(e.message));
  }, []);
  if (error) return <div className="banner warn">⚠ {error}</div>;
  if (!procs) return <div className="loading">loading egress…</div>;
  if (procs.length === 0) return <div className="empty">No processes with flagged outbound connections. 🎉</div>;
  return (
    <table className="table">
      <thead>
        <tr><th className="num">risk</th><th>process</th><th>destinations</th><th>flags</th><th>what it is</th></tr>
      </thead>
      <tbody>
        {procs.map((p) => (
          <tr key={p.pid} onClick={() => onSelect(p.pid)}>
            <td className="num"><span className={`risk-pill risk-${p.risk_tier}`}>{p.risk_score}</span></td>
            <td>{p.name} <span className="muted-line">#{p.pid}</span></td>
            <td className="muted-line">{p.egress?.destinations?.slice(0, 4).join(", ")}{p.egress?.destinations?.length > 4 ? " …" : ""}</td>
            <td className="egress-flag">{(p.egress?.flags || []).join(", ")}</td>
            <td className="desc">{p.description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
