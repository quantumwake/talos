import type {
  Report, ProcDetail, TerminateResult, ReapResult, Progress, LearnedEntry, AuditEntry, ProcSummary,
} from "./types";

const BASE = (import.meta.env.VITE_API_URL as string) || "http://127.0.0.1:58789";

export interface ScanStreamHandlers {
  onProcess: (p: ProcSummary) => void;
  onDone: (r: Report) => void;
  onFail: (msg: string) => void;
}

/** Stream a scan over SSE: process events fill the dashboard live; done finalises it. */
export function scanStream(opts: ScanOpts, h: ScanStreamHandlers): EventSource {
  const params = new URLSearchParams({
    network: String(opts.collect_network),
    vt: String(opts.use_virustotal),
    llm: String(opts.use_llm),
    asn: String(opts.resolve_asn),
  });
  const es = new EventSource(`${BASE}/scan/stream?${params.toString()}`);
  es.addEventListener("process", (e) => h.onProcess(JSON.parse((e as MessageEvent).data)));
  es.addEventListener("done", (e) => {
    h.onDone(JSON.parse((e as MessageEvent).data));
    es.close(); // prevent EventSource auto-reconnect (which would re-run the scan)
  });
  es.addEventListener("fail", (e) => {
    h.onFail(JSON.parse((e as MessageEvent).data).detail);
    es.close();
  });
  es.addEventListener("error", () => {
    // Native connection error (not our "fail" event). If we never got 'done', report it.
    if (es.readyState === EventSource.CLOSED) h.onFail("connection to backend lost");
  });
  return es;
}

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

export interface ScanOpts {
  use_llm: boolean;
  use_virustotal: boolean;
  collect_network: boolean;
  resolve_asn: boolean;
}

export const api = {
  health: () => j<{ status: string; last_scan_at: number }>("/health"),
  scan: (opts: ScanOpts) =>
    j<Report>("/scan", { method: "POST", body: JSON.stringify(opts) }),
  report: () => j<Report>("/report"),
  process: (pid: number) => j<ProcDetail>(`/process/${pid}`),
  terminate: (pid: number, confirm: boolean, force = false) =>
    j<TerminateResult>("/terminate", {
      method: "POST",
      body: JSON.stringify({ pid, confirm, force }),
    }),
  reap: (confirm: boolean, min_risk = 0) =>
    j<ReapResult>("/reap", {
      method: "POST",
      body: JSON.stringify({ confirm, min_risk }),
    }),
  removePlan: (pid: number) =>
    j<{ app_bundle: string | null; vendor: string | null; trash: string[]; needs_sudo: string[]; blocked: string | null }>(
      `/remove-plan/${pid}`
    ),
  removeApp: (pid: number, confirm: boolean) =>
    j<{ dry_run: boolean; blocked: string | null; trashed: string[]; failed: { path: string; reason: string }[]; needs_sudo: string[] }>(
      "/remove", { method: "POST", body: JSON.stringify({ pid, confirm }) }
    ),
  acknowledge: (pid: number, do_not_kill = true, note?: string) =>
    j<{ ok: boolean }>("/acknowledge", {
      method: "POST",
      body: JSON.stringify({ pid, do_not_kill, note }),
    }),
  unacknowledge: (pid: number) =>
    j<{ ok: boolean }>("/unacknowledge", {
      method: "POST",
      body: JSON.stringify({ pid }),
    }),
  analyzeGroup: (opts: {
    category?: string | null;
    tier?: string | null;
    min_risk?: number;
    web_search?: boolean;
    limit?: number;
  }) =>
    j<{ analyzed: number; backend: string }>("/analyze-group", {
      method: "POST",
      body: JSON.stringify(opts),
    }),
  progress: () => j<Progress>("/progress"),
  system: () => j<import("./types").SystemSnapshot>("/system"),
  scansList: () => j<{ scans: import("./types").ScanListItem[] }>("/scans"),
  getScan: (id: string) => j<Report>(`/scans/${id}`),
  learned: () =>
    j<{ count: number; entries: LearnedEntry[] }>("/learned"),
  forgetKey: (key: string) =>
    j<{ ok: boolean }>("/unacknowledge", { method: "POST", body: JSON.stringify({ key }) }),
  egress: () => j<{ count: number; processes: (ProcSummary & { egress: any })[] }>("/egress"),
  auditLog: () => j<{ entries: AuditEntry[] }>("/audit-log"),
};
