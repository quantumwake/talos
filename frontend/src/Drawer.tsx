import { useEffect, useState } from "react";
import { api } from "./api";
import type { ProcDetail, TerminateResult } from "./types";

export function Drawer({
  pid,
  onClose,
  onChanged,
}: {
  pid: number;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [p, setP] = useState<ProcDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<TerminateResult | null>(null);

  useEffect(() => {
    setP(null);
    api.process(pid).then(setP).catch((e) => setError(e.message));
  }, [pid]);

  async function ack(on: boolean) {
    setBusy(true);
    setError(null);
    try {
      if (on) await api.acknowledge(pid, true);
      else await api.unacknowledge(pid);
      const fresh = await api.process(pid);
      setP(fresh);
      onChanged();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const [removePlan, setRemovePlan] = useState<any | null>(null);

  async function loadRemovePlan() {
    setBusy(true);
    setError(null);
    try {
      setRemovePlan(await api.removePlan(pid));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function doRemove() {
    setBusy(true);
    try {
      const r = await api.removeApp(pid, true);
      if (r.blocked) setError(r.blocked);
      else {
        setResult({ pid, name: p?.name ?? "", killed: true, dry_run: false, method: "Trash",
          reason: `moved ${r.trashed.length} item(s) to Trash` } as any);
        onChanged();
        setRemovePlan(null);
        setTimeout(onClose, 1400);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function kill(confirm: boolean, force: boolean) {
    setBusy(true);
    setResult(null);
    try {
      const r = await api.terminate(pid, confirm, force);
      setResult(r);
      if (r.killed) {
        onChanged();
        setTimeout(onClose, 900);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const egress = (p?.connections ?? []).filter((c) => c.raddr && c.status !== "LISTEN");

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()}>
        <button className="close-x" style={{ float: "right" }} onClick={onClose}>✕</button>
        {error && <div className="banner warn">⚠ {error}</div>}
        {!p && !error && <div className="loading">loading…</div>}
        {p && (
          <>
            <h2>
              {p.name}
              {p.acknowledged && <span className="learned-badge"> ✓ acknowledged</span>}
              {p.do_not_kill && <span className="learned-badge"> 🔒 do-not-kill</span>}
            </h2>
            <div className="pid">
              pid {p.pid} · {p.username}
              {p.is_root ? " · root" : ""}
              {p.analyzed_at && ` · last analyzed ${p.analyzed_at.slice(0, 10)}`}
            </div>

            <div className="ack-row">
              {p.acknowledged ? (
                <button disabled={busy} onClick={() => ack(false)}>↺ un-acknowledge</button>
              ) : (
                <button disabled={busy} onClick={() => ack(true)}
                  title="Mark known & never flag/kill again (persists across scans)">
                  ✓ acknowledge (don't flag again)
                </button>
              )}
            </div>

            <div className="kv">
              <span className="k">category</span>
              <span className="v">
                <span className={`risk-pill risk-${p.risk_tier}`}>{p.risk_score}</span>{" "}
                {p.category} ({p.risk_tier})
              </span>
              <span className="k">safe to kill</span>
              <span className="v" style={{ color: p.safe_to_kill ? "var(--low)" : "var(--muted)" }}>
                {p.safe_to_kill ? "yes" : "no"}
              </span>
              <span className="k">signing</span>
              <span className="v">{p.signing?.trust ?? "unknown"}{p.signing?.team_id ? ` · ${p.signing.team_id}` : ""}</span>
              <span className="k">memory / cpu</span>
              <span className="v">{p.memory_mb.toFixed(0)} MB · {p.cpu_percent.toFixed(0)}%</span>
              {p.bundle?.bundle_id && (
                <>
                  <span className="k">bundle id</span>
                  <span className="v">{p.bundle.bundle_id}{p.bundle.version ? ` · v${p.bundle.version}` : ""}</span>
                </>
              )}
              {p.bundle?.copyright && (
                <>
                  <span className="k">copyright</span>
                  <span className="v">{p.bundle.copyright}</span>
                </>
              )}
              <span className="k">executable</span>
              <span className="v">{p.exe ?? "unknown"}</span>
              <span className="k">command</span>
              <span className="v">{p.cmdline?.join(" ") || "unknown"}</span>
            </div>

            <div className="section-title">what it is</div>
            <div>{p.description || "—"}</div>

            {p.reasons?.length > 0 && (
              <>
                <div className="section-title">risk factors</div>
                <ul>
                  {p.reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </>
            )}

            <div className="section-title">
              network egress {p.egress?.flagged_count ? <span className="egress-flag">· {p.egress.flagged_count} flagged</span> : null}
            </div>
            {egress.length === 0 && <div className="empty">No outbound connections.</div>}
            {egress.map((c, i) => (
              <div className="conn" key={i}>
                <div className="addr">{c.raddr} <span className="tag">{c.status}</span></div>
                <div className="meta">
                  {c.org || "unknown org"} {c.asn || ""} {c.rdns ? `· ${c.rdns}` : ""}
                </div>
                {c.flags.length > 0 && <div className="flags">⚠ {c.flags.join(", ")}</div>}
              </div>
            ))}

            {result && (
              <div className={`banner ${result.killed || result.dry_run ? "ok" : "warn"}`}>
                {result.method}: {result.reason}
              </div>
            )}

            {removePlan && (
              <div className="remove-panel">
                {removePlan.blocked ? (
                  <div className="banner warn">⚠ {removePlan.blocked}</div>
                ) : (
                  <>
                    <div className="section-title">uninstall {removePlan.vendor ? `(${removePlan.vendor})` : ""}</div>
                    {removePlan.trash.length > 0 && (
                      <>
                        <div className="muted-line">move to Trash (reversible):</div>
                        {removePlan.trash.map((t: string) => <div className="conn" key={t}>{t}</div>)}
                      </>
                    )}
                    {removePlan.needs_sudo.length > 0 && (
                      <>
                        <div className="muted-line" style={{ color: "var(--high)" }}>
                          needs sudo (system launch items / privileged helpers) — remove manually:
                        </div>
                        {removePlan.needs_sudo.map((s: string) => (
                          <div className="conn" key={s}><code>sudo rm "{s}"</code></div>
                        ))}
                      </>
                    )}
                    {removePlan.trash.length > 0 && (
                      <button className="danger" disabled={busy} onClick={doRemove} style={{ marginTop: 10 }}>
                        move {removePlan.trash.length} item(s) to Trash
                      </button>
                    )}
                  </>
                )}
              </div>
            )}

            <div className="drawer-actions">
              <button onClick={() => kill(false, false)} disabled={busy}>dry-run</button>
              <button className="danger" disabled={busy || !p.safe_to_kill}
                onClick={() => kill(true, false)}>
                terminate
              </button>
              {!p.safe_to_kill && (
                <button className="danger" disabled={busy}
                  title="override the safe-to-kill check (still cannot kill protected processes)"
                  onClick={() => { if (confirm(`Force-terminate ${p.name} (pid ${p.pid})? It is NOT classified safe-to-kill.`)) kill(true, true); }}>
                  force kill
                </button>
              )}
              {!removePlan && (
                <button disabled={busy} onClick={loadRemovePlan}
                  title="uninstall the application behind this process (move to Trash)">
                  🗑 uninstall app…
                </button>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
