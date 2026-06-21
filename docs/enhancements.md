# Planned Enhancements

Deferred features for Talos, captured here so they aren't lost.
Ordered roughly by value. Each notes why it was deferred and what it would touch.

## 1. Per-process network / disk / GPU I/O — *partially done*

**Done:** system-wide CPU, memory, disk I/O, network I/O, and (sudo-only) GPU are live in
the portal's resource bar (`resources.py` → `GET /system`). Per-process **CPU** and
**memory** are in the table.

**Still pending — per-process net/disk/GPU (macOS has no normal per-process API):**

- **Per-process network bandwidth** via `nettop -P -L 1 -x` sampling → bytes in/out per PID,
  rolled into risk (sustained high outbound on an unknown/unsigned proc = exfil signal) and a
  table column. Needs `nettop`; some metrics need sudo. *(This was the original ask.)*
- **Per-process disk I/O**: psutil's `io_counters()` is unavailable on macOS. Would need
  `fs_usage` (sudo) sampling — heavy; likely a short opt-in capture.
- **Per-process GPU**: macOS exposes no per-process GPU API. `powermetrics` is system-wide and
  sudo-only (already used for the system GPU meter). Per-process is not feasible cleanly.

A process quietly uploading gigabytes is the clearest exfil signal — per-process network via
nettop is the highest-value next step here.

- **Approach:** sample `nettop -P -L 1 -x -J bytes_in,bytes_out` (or `-t external`) over a
  short window, parse per-PID byte deltas, and attribute throughput to processes. Roll
  bytes/sec into the risk score (sustained high outbound on an unknown/unsigned process =
  high risk) and show a sparkline in the portal.
- **Caveats:** `nettop` output is not stable/JSON-friendly across macOS versions; some
  counters require root. Falls under the "graceful degrade" rule — show what we can,
  warn about what needs sudo.
- **Touches:** new `talos/bandwidth.py`, a `--bandwidth` flag, risk weighting
  in `risk.py`, an egress-volume column in `report.py` and the portal.

## 1b. Streaming scan persistence + resume (part 2 of live results)

The scan now **streams results over SSE** (`GET /scan/stream`) so the dashboard fills in
live instead of waiting for the whole scan. The follow-up:

- **Persist results as they stream**, not just at the end — write each classified process to
  an on-disk scan snapshot (e.g. `~/.talos/last_scan.jsonl`) as it completes.
- **Resume**: if a scan is interrupted (browser closed, restart), reload the partial snapshot
  and either show it immediately or resume classification from where it stopped (skip PIDs
  already done). The learned store already persists per-binary analyses; this adds a
  per-run, PID-level snapshot for resumability.
- Consider a proper **job queue** (job id + `GET /scan/{id}/events`) so multiple clients can
  attach to the same in-flight scan and reconnect to it (SSE has no replay today).

## 2. Persistence / autostart audit

What relaunches a process after you kill it? Surface the persistence surface so a "killed"
malicious process can't silently come back.

- Enumerate `LaunchAgents`/`LaunchDaemons` (`/Library`, `~/Library`, `/System/Library`),
  login items, cron, and `at` jobs; map each running process back to what starts it.
- Flag unsigned/unknown persistence as high risk. Offer to disable (move the plist aside)
  alongside killing the process.

## 3. Historical tracking + alerting

Single scans are a snapshot. Persist scans to a small local DB (SQLite) and diff over time:
new processes, new outbound destinations, processes that changed binary hash. Alert on
deltas (new egress to a never-seen ASN, a system binary whose hash changed).

## 4. Deeper code-signature verification

- Verify nested bundle components (`codesign --verify --deep`), not just the main binary.
- Cross-check Apple's Gatekeeper/XProtect/MRT verdicts.
- Detect signature/identity mismatches (binary at an Apple path signed by a third party).

## 5. Offline ASN/GeoIP + richer egress context

Bundle an offline ASN/GeoIP database to avoid per-IP calls to ip-api.com (rate limits,
privacy). Add reverse-DNS and TLS SNI capture for better "who is this talking to" context.

## 6. Fleet mode & scheduled scans

Run scans across multiple Macs and aggregate into one portal; schedule recurring scans
(cron/launchd) with the results feeding the historical DB and alerting (#3).

## 7. Signed, auto-updating rule packs

Ship the curated known-process DB (and risk rules) as a versioned, signed pack that can be
updated independently of the binary — so new vendors/threats land without a re-release.

## 8. Allowlist-learning UI

Promote high-confidence LLM verdicts (already cached in `~/.talos/llm_verdicts.json`)
into the curated `known_processes.yaml` from the portal, with a human review step — so the
local knowledge base improves over time without re-querying Claude.
