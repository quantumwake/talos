# How Talos Verifies a Process

**Trust anchor: cryptographic code-signature verification — not names, not paths.**
Name- and path-based hints exist only to *describe* a process and to keep us from killing
core OS services. They are **cross-checked against the signature and can never upgrade an
unsigned binary to "trusted."** Path-based trust was removed entirely (see §6).

Measured on a real machine (unprivileged scan, ~900 processes): **792 `apple_system`, every
one `verified=True` via `codesign --verify`; 0 trusted by path.**

---

## 1. Get the *real* process identity — `collect.py`

You can't verify what you can't see correctly. macOS makes this non-obvious:

- `psutil.name()` returns the kernel's **15-char truncated `comm`** (so
  `com.apple.DriverKit-AppleBCMWLAN` → `com.apple.Driver`). Unreliable — never trusted.
- `psutil.exe()` / `cmdline()` raise `AccessDenied` for root-owned processes when we run
  unprivileged → no path → nothing to verify.

So we enrich every PID from **`ps -axww -o pid=,comm=`** (full executable path) and
`-o command=` (full argv), which the kernel exposes even without sudo. The displayed name is
derived from the **executable / enclosing bundle**, never the truncated `comm`
(`collect._display_name`). Without the real path, signature verification is impossible — this
step is a prerequisite for everything below.

## 2. Verify the signature — `signing.py` (the trust anchor)

For each binary, in order:

1. **Read the cert chain on the binary itself:** `codesign -dv --verbose=4 <exe>` → parse the
   `Authority=` chain, `TeamIdentifier`, `Identifier`. We run this on the **actual Mach-O**,
   because most standalone daemons (e.g. `/System/.../Support/fseventsd`) carry their own
   signature there.
2. **Bundle fallback only on genuine "not signed":** if and only if step 1 reports *not
   signed*, retry once against the nearest enclosing bundle (`.app/.xpc/.dext/.framework/…`,
   `signing._bundle_root`) — some bundles sign the bundle, not the inner Mach-O. We do **not**
   redirect to the bundle otherwise (doing so previously broke standalone daemons and is what
   forced the bad path-trust workaround).
3. **Actual integrity verification:** `codesign --verify --strict <target>` — this recomputes
   the code hashes and checks the seal. `verified = (returncode == 0)`. This is the difference
   between *reading a claimed signature* (`-dv`) and *proving the bytes match it* (`--verify`).
4. **Tamper signal:** if a signature is present but `--verify` **fails**, trust is downgraded
   to `unknown` with `"signature present but failed --verify"`. A present-but-invalid signature
   is a red flag, not a pass.
5. **Notarization / Gatekeeper:** `spctl -a -t exec -vv <target>` → notarized Developer ID /
   Mac App Store / Apple system.

**Trust levels** come from the real authority chain (`signing._classify_authority`):
`apple_system` (Apple "Software Signing" → Apple Root CA), `dev_id_notarized`, `app_store`,
`dev_id`, `adhoc`, `unsigned`, `unknown`.

`SigningInfo` records `trust`, `authority` (the cert chain), `team_id`, `verified`,
`signed_target` (exactly what we ran codesign against), and `sha256` of the Mach-O.

There is **no path-based trust**. A file under `/System` that fails verification is `unknown`,
identical to one anywhere else.

## 3. Classify — `classify.py` (signature is available to every step)

The ladder, and **what each step is allowed to do**:

| Step | Rule | Basis | Can it trust an unsigned binary? |
|---|---|---|---|
| 0. Self | our own process | **pid** (solid); also exe-name/cmdline (weak — see §5) | n/a (only hides ourselves) |
| 1. Signature | §2 above | **cryptographic** | — |
| 2. Protected | `PROTECTED_NAMES`, pid 0/1 → never auto-kill | **name** (safety only) | **No** — cross-checked (below) |
| 3. User override | you acknowledged / do-not-kill | explicit human | n/a |
| 4. Curated DB | `known_processes.yaml` name match → description + category | **name** | **No** — cross-checked (below) |
| 5. VirusTotal | binary hash reputation (optional) | **content hash** | overrides → malicious |
| 6. Apple fast-path | `verified apple_system` → system_service | **cryptographic** | — |
| 7. Memory | a prior cached LLM verdict | name\|path key | inherits prior verdict |
| 8. Claude (optional) | only for still-unknown | given real name/path/signature/egress | model judgement |
| 9. Default | `unknown` | — | — |

**The two name-based rules are cross-checked against the signature so a name can never
override it:**

- **Protected list:** a process using a protected system name (`launchd`, `WindowServer`, …)
  whose on-disk binary is **unsigned** → reclassified **`suspicious` (source `impersonation`)**,
  not protected. The genuine ones are pid 0/1 or Apple-verified or have no exe (`kernel_task`).
- **Curated DB:** a `trusted_app` / `system_service` / `system_critical` name match whose
  binary is **unsigned** → **`suspicious` (impersonation)**: *"Claims to be X (name match) but
  its binary is unsigned."* Vendors in these categories (Apple, Google, Slack, Microsoft,
  Docker…) always sign, so unsigned = impersonation.

**Deliberately *not* treated as impersonation:** `adhoc` and *unreadable* signatures. Homebrew
and locally-built dev tools (`node`, etc.) are legitimately ad-hoc signed, so flagging those
would be the same lazy-rule mistake in reverse. Only a true **`unsigned`** (we read it; there
is no signature at all) counts as contradicting a trusted name.

## 4. Risk scoring — `risk.py`

The `-10` "trusted provenance" credit is granted **only when `verified == True`** — an
unverified claimed signature gets no credit. `unsigned` (+25) and `adhoc` (+15) penalties apply
**regardless of path**. Egress reputation, root, and resource use add on top.

## 5. What is NOT verified (honest limitations)

- **In-memory vs on-disk:** we verify the on-disk binary's signature; we do not prove the
  *running image* matches it. A sophisticated in-memory patch wouldn't change the file's
  signature. Partial mitigations: `--verify` of the file + optional VirusTotal hash.
- **Network sockets need root:** unprivileged we see our own process's connections; system
  processes' sockets are hidden (paths/names are still recovered via `ps`).
- **Self-recognition** uses pid (reliable) plus exe-basename/cmdline (spoofable). It only
  affects whether we list *ourselves*, not any security verdict.
- **codesign/spctl trust the OS toolchain.** If SIP is disabled and an attacker has root, the
  tooling itself could be subverted — out of scope for a user-space auditor.
- **Curated DB descriptions are human-written hints,** not an authority — they never override
  §2.

## 6. Removed: path-based trust (and why it was wrong)

An earlier version trusted *any* file under `/System` (the Signed System Volume) even when
`codesign` couldn't read a signature — a `on_sealed_system_volume()` path check. That was
exactly the "ridiculous rule" to avoid: **a path string is not proof.** It silenced 161
processes on a real scan. It was **deleted**. The correct fix was reading the signature on the
right object (the binary itself, §2 step 1), which verifies all of them cryptographically —
`792 apple_system, all verified=True, 0 path-trusted`.

---

### Reproduce the audit

```sh
# Per-binary: see exactly what was verified
uv run talos inspect <pid>     # shows signed_target, authority chain, verified

# Aggregate: trust levels + how many are cryptographically verified vs not
uv run python -c "from talos import engine; from talos.config import Settings; \
import collections; r=engine.scan(Settings(collect_network=False)); \
print(collections.Counter((p.signing.trust.value, p.signing.verified) for p in r.processes if p.signing))"
```
