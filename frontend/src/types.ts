export type RiskTier = "low" | "medium" | "high" | "critical";

export interface ProcSummary {
  pid: number;
  name: string;
  username: string | null;
  memory_mb: number;
  cpu_percent: number;
  category: string;
  risk_score: number;
  risk_tier: RiskTier;
  safe_to_kill: boolean;
  description: string;
  vendor: string | null;
  reasons: string[];
  egress_flags: string[];
  signing: string | null;
  acknowledged: boolean;
  do_not_kill: boolean;
  analyzed_at: string | null;
  state?: "new" | "active";          // vs the previous scan
  create_time?: number;
  status?: string;
}

export interface ScanDiff {
  baseline: boolean;
  previous_at: number | null;
  active: number;
  new: number;
  inactive: number;
  inactive_list: ProcSummary[];
}

export interface ScanListItem {
  id: string;
  scanned_at: number;
  summary: Summary;
  diff: { active: number; new: number; inactive: number };
}

export interface Summary {
  total: number;
  by_tier: Record<RiskTier, number>;
  by_category: Record<string, number>;
  safe_to_kill: number;
  flagged_egress: number;
}

export interface Report {
  duration_s: number;
  privilege: { running_as_root: boolean; hint?: string; restricted_processes?: number };
  summary: Summary;
  processes: ProcSummary[];
  id?: string;
  scanned_at?: number;
  diff?: ScanDiff;
}

export interface Connection {
  raddr: string;
  remote_ip: string | null;
  remote_port: number | null;
  status: string;
  org: string | null;
  asn: string | null;
  rdns: string | null;
  flags: string[];
}

export interface ProcDetail extends ProcSummary {
  exe: string | null;
  cmdline: string[];
  is_root: boolean;
  connections: Connection[];
  signing: any;
  bundle?: { name?: string; bundle_id?: string; version?: string; copyright?: string };
  egress: { egress_count: number; flagged_count: number; flags: string[] };
}

export interface TerminateResult {
  pid: number;
  name: string;
  killed: boolean;
  dry_run: boolean;
  method: string;
  reason: string;
}

export interface ReapGroup {
  app: string;
  count: number;
  memory_mb: number;
}

export interface ReapResult {
  dry_run: boolean;
  count: number;
  reclaimable_mb: number;
  groups: ReapGroup[];
  results: TerminateResult[] & { memory_mb: number }[];
}

export interface SystemSnapshot {
  cpu: { percent: number; count: number; per_core: number[]; load_avg: number[] };
  memory: { total: number; used: number; available: number; percent: number };
  swap: { total: number; used: number; percent: number };
  disk_io: { read_bps: number; write_bps: number } | null;
  net_io: { sent_bps: number; recv_bps: number };
  gpu: { available: boolean; busy_percent?: number; reason?: string };
}

export interface Progress {
  active: boolean;
  op: string;
  phase: string;
  done: number;
  total: number;
  current: string;
  recent: ProcSummary[];
}

export interface LearnedEntry {
  key: string;
  name: string;
  exe: string | null;
  sha256: string | null;
  description: string;
  vendor: string | null;
  category: string;
  safe_to_kill: boolean;
  source: string;
  first_seen: string;
  last_analyzed: string;
  analyses: number;
  user: { acknowledged: boolean; do_not_kill: boolean; note: string | null } | null;
}

export interface AuditEntry {
  ts: string;
  action: string;
  pid?: number;
  name?: string;
  method?: string;
  killed?: boolean;
  reason?: string;
}
