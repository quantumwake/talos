import { useEffect, useState } from "react";
import { api } from "./api";
import type { ReapResult } from "./types";

/**
 * "Feeling lucky — free up processes." Shows a grouped preview of everything that is
 * safe-to-kill (a dry-run from the backend), then terminates them all on confirm.
 */
export function ReapModal({
  onClose,
  onDone,
}: {
  onClose: () => void;
  onDone: () => void;
}) {
  const [preview, setPreview] = useState<ReapResult | null>(null);
  const [done, setDone] = useState<ReapResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [minRisk, setMinRisk] = useState(0);

  function loadPreview(mr: number) {
    api
      .reap(false, mr)
      .then(setPreview)
      .catch((e) => setError(e.message));
  }

  useEffect(() => loadPreview(minRisk), [minRisk]);

  async function reapNow() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.reap(true, minRisk);
      setDone(r);
      setTimeout(onDone, 1200);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const data = done ?? preview;

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>⚡ free up processes</h2>
          <button onClick={onClose}>✕</button>
        </div>

        {error && <div className="banner warn">⚠ {error}</div>}

        {done ? (
          <div className="banner ok">
            Terminated {done.results.filter((r) => r.killed).length}/{done.count} ·
            reclaimed ~{done.reclaimable_mb.toFixed(0)} MB
          </div>
        ) : (
          <p className="muted-line">
            Only processes classified <strong>safe-to-kill</strong> are eligible — system,
            critical, root, unidentified, and Talos itself are excluded.
          </p>
        )}

        {data && (
          <>
            <div className="reap-stat">
              <div>
                <span className="big">{data.count}</span> processes
              </div>
              <div>
                <span className="big accent-num">{data.reclaimable_mb.toFixed(0)}</span> MB
                reclaimable
              </div>
            </div>

            <div className="risk-slider">
              <label>min risk: {minRisk}</label>
              <input
                type="range"
                min={0}
                max={60}
                step={5}
                value={minRisk}
                disabled={!!done}
                onChange={(e) => setMinRisk(Number(e.target.value))}
              />
              <span className="muted-line">higher = only reap the riskier safe-to-kill ones</span>
            </div>

            <div className="section-title">by app</div>
            <div className="reap-groups">
              {data.groups.map((g) => (
                <div className="reap-group" key={g.app}>
                  <span className="g-app">{g.app}</span>
                  <span className="g-meta">
                    {g.count} · {g.memory_mb.toFixed(0)} MB
                  </span>
                </div>
              ))}
              {data.groups.length === 0 && (
                <div className="empty">Nothing safe-to-kill at this threshold.</div>
              )}
            </div>
          </>
        )}

        {!done && (
          <div className="drawer-actions">
            <button onClick={onClose}>cancel</button>
            <button
              className="danger"
              disabled={busy || !data || data.count === 0}
              onClick={reapNow}
            >
              {busy ? "freeing…" : `free up ${data?.count ?? 0} (${data?.reclaimable_mb.toFixed(0) ?? 0} MB)`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
