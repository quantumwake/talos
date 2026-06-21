"""The identity & safety ladder: turn a ProcessInfo into a Verdict.

Escalates cheapest → most expensive, stopping as soon as a layer is confident:
  1. signing      (codesign/spctl — local, authoritative)
  2. knowledge DB (curated descriptions + safe-to-kill flags)
  3. VirusTotal   (hash reputation; only when --vt and a hash exist)
  4. Claude       (fallback for true unknowns; cached back into the DB)

The combined evidence then feeds risk.py for scoring.
"""

from __future__ import annotations

import os
from typing import Optional

from .config import Settings, PROTECTED_NAMES
from .knowledge import KnowledgeBase, KnownEntry
from .llm import LLMClassifier
from .models import Category, ProcessInfo, TrustLevel, Verdict
from .metadata import bundle_metadata, describe, vendor_from_copyright
from .reputation.virustotal import VirusTotal
from .signing import inspect_signature
from .store import LearnedStore, entry_key


def apply_llm_item(verdict: Verdict, item: dict) -> None:
    """Apply one LLM verdict dict (from classify / classify_batch) onto a Verdict."""

    try:
        verdict.category = Category(item.get("category", "unknown"))
    except ValueError:
        verdict.category = Category.UNKNOWN
    verdict.description = item.get("description", verdict.description)
    verdict.vendor = item.get("vendor") or verdict.vendor
    verdict.safe_to_kill = bool(item.get("safe_to_kill", False))
    try:
        verdict.confidence = float(item.get("confidence", 0.6))
    except (TypeError, ValueError):
        verdict.confidence = 0.6
    verdict.source = "llm"
    if item.get("reasoning"):
        verdict.reasons.append(f"Claude: {item['reasoning']}")


def _is_self(proc: ProcessInfo) -> bool:
    """True if this process is the talos itself (CLI, API, or scan worker)."""

    if proc.pid == os.getpid():
        return True
    cmd = " ".join(proc.cmdline).lower()
    if "talos" in cmd:
        return True
    if proc.exe and os.path.basename(proc.exe) == "talos":
        return True
    return False


class Classifier:
    def __init__(
        self,
        settings: Settings,
        kb: Optional[KnowledgeBase] = None,
        vt: Optional[VirusTotal] = None,
        llm: Optional[LLMClassifier] = None,
        store: Optional[LearnedStore] = None,
    ) -> None:
        self.settings = settings
        self.kb = kb or KnowledgeBase()
        self.vt = vt or VirusTotal(settings.vt_api_key)
        self.llm = llm or LLMClassifier(settings, self.kb)
        self.store = store or LearnedStore()

    def classify(self, proc: ProcessInfo) -> Verdict:
        verdict = Verdict()

        # --- Don't flag ourselves. The talos's own process (and the API/scan worker
        #     it runs in) should never show up as an unknown finding or a kill target. ---
        if _is_self(proc):
            verdict.category = Category.TRUSTED_APP
            verdict.description = "Talos itself — the tool you're running. Not a finding."
            verdict.vendor = "Talos"
            verdict.safe_to_kill = False
            verdict.confidence = 1.0
            verdict.source = "self"
            return verdict

        # --- Layer 1: code signature + bundle metadata (cheap, authoritative) ---
        need_hash = self.settings.use_virustotal or self.settings.use_llm
        proc.signing = inspect_signature(proc.exe, hash_file=need_hash)
        trust = proc.signing.trust
        proc.bundle = bundle_metadata(proc.exe)
        # A precise, no-LLM description from Info.plist + signer + path role.
        synth = describe(proc.name, proc.exe, proc.bundle, proc.signing.developer, proc.cmdline)
        # A binary that we read and found carries NO signature at all is the only thing we
        # treat as "contradicts a trusted name" — adhoc (common for homebrew/dev builds) and
        # unreadable signatures are NOT used to flag, to avoid false positives.
        sig_unsigned = trust == TrustLevel.UNSIGNED

        # --- Hard protection: certain names are never touched, period ---
        if proc.name in PROTECTED_NAMES or proc.pid in (0, 1):
            if sig_unsigned and proc.exe and proc.pid not in (0, 1):
                # Uses a protected system name but the on-disk binary is unsigned — that is
                # an impersonation signal, NOT a reason to trust it. Flag it.
                verdict.category = Category.SUSPICIOUS
                verdict.safe_to_kill = False
                verdict.confidence = 0.85
                verdict.source = "impersonation"
                verdict.reasons.append(
                    f"uses protected system name '{proc.name}' but its binary is unsigned "
                    f"({proc.exe}) — possible impersonation"
                )
            else:
                verdict.category = Category.SYSTEM_CRITICAL
                verdict.safe_to_kill = False
                verdict.confidence = 1.0
                verdict.source = "protected"
                verdict.reasons.append("on hardcoded protected-process list")

        key = entry_key(proc.name, proc.exe, proc.signing.sha256)
        learned = self.store.get(key)
        user = (learned or {}).get("user")

        # --- User override (authoritative): you've acknowledged / do-not-kill'd this. ---
        if user and verdict.source != "protected":
            cat = user.get("category") or (learned.get("category") if learned else None)
            try:
                verdict.category = Category(cat) if cat else Category.TRUSTED_APP
            except ValueError:
                verdict.category = Category.TRUSTED_APP
            verdict.description = (learned or {}).get("description") or "Acknowledged — you marked this known."
            verdict.vendor = (learned or {}).get("vendor")
            verdict.acknowledged = bool(user.get("acknowledged"))
            verdict.do_not_kill = bool(user.get("do_not_kill"))
            verdict.confidence = 1.0
            verdict.source = "user"
            if user.get("note"):
                verdict.reasons.append(f"you: {user['note']}")

        # --- Layer 2: curated knowledge DB (name match) ---
        entry = self.kb.lookup(proc.name, proc.exe)
        if entry and verdict.source not in ("protected", "user", "impersonation"):
            self._apply_known(verdict, entry)
            # Cross-check: the DB matched by NAME. A commercial/system app that should be
            # signed (trusted_app/system_service/system_critical) but is unsigned is a
            # name-match impersonation — the name must not override the signature.
            if sig_unsigned and entry.category in (
                Category.TRUSTED_APP, Category.SYSTEM_SERVICE, Category.SYSTEM_CRITICAL,
            ):
                verdict.category = Category.SUSPICIOUS
                verdict.safe_to_kill = False
                verdict.confidence = 0.85
                verdict.source = "impersonation"
                verdict.description = (
                    f"Claims to be {entry.vendor or entry.name} (name match) but its binary "
                    f"is unsigned — possible impersonation. {entry.description or ''}"
                )
                verdict.reasons.append(
                    f"name matches '{entry.name}' but binary is unsigned — possible impersonation"
                )
        elif entry and not verdict.description:
            # Protected/user: keep the hard verdict, but borrow the human description.
            verdict.description = entry.description
            verdict.vendor = verdict.vendor or entry.vendor

        # --- Layer 3: VirusTotal reputation (overrides toward danger) ---
        if self.settings.use_virustotal and proc.signing.sha256:
            rep = self.vt.lookup(proc.signing.sha256)
            if rep:
                self._apply_reputation(verdict, rep)

        # --- Apple-signed fast path (verified signature only — never path-based) ---
        if verdict.source == "heuristic" and trust in (
            TrustLevel.APPLE_SYSTEM,
            TrustLevel.APP_STORE,
        ):
            verdict.category = Category.SYSTEM_SERVICE
            verdict.description = verdict.description or (
                "Apple-signed system component (signature verified). Generally leave running."
            )
            verdict.vendor = verdict.vendor or "Apple"
            verdict.confidence = 0.8
            verdict.source = "signature"
        elif verdict.source == "heuristic" and trust in (
            TrustLevel.DEV_ID_NOTARIZED, TrustLevel.DEV_ID,
        ):
            # A Developer ID signature is an Apple-issued cert tied to an identified
            # developer account, and we already ran `codesign --verify`. Notarized is
            # slightly stronger, but plain Developer ID is still a known, real vendor —
            # not "unknown". Name the developer so it's actually identified.
            dev = proc.signing.developer
            notarized = trust == TrustLevel.DEV_ID_NOTARIZED
            verdict.category = Category.TRUSTED_APP
            verdict.vendor = verdict.vendor or dev or vendor_from_copyright(proc.bundle.get("copyright"))
            tag = "notarized" if notarized else "Developer ID"
            verdict.description = verdict.description or (
                f"{synth} — {tag}." if synth
                else (f"Signed by {dev} ({tag} app)." if dev
                      else f"{tag}-signed third-party app (Apple-issued cert).")
            )
            verdict.confidence = 0.75 if synth else (0.7 if notarized else 0.6)
            verdict.source = "signature"

        # --- Memory: a prior good analysis (e.g. an earlier LLM eval) is remembered, so
        #     we don't re-flag it and don't pay to re-evaluate it. ---
        if (
            verdict.source in ("heuristic", "signature")
            and verdict.confidence < 0.65
            and learned
            and learned.get("source") not in (None, "heuristic", "self")
        ):
            try:
                verdict.category = Category(learned.get("category", "unknown"))
            except ValueError:
                verdict.category = Category.UNKNOWN
            verdict.description = learned.get("description") or verdict.description
            verdict.vendor = learned.get("vendor") or verdict.vendor
            verdict.safe_to_kill = bool(learned.get("safe_to_kill"))
            verdict.confidence = 0.7
            verdict.source = "memory"

        # --- Metadata identification (free, no LLM): even unsigned/adhoc things are usually
        #     identifiable from their bundle Info.plist + signer + path role. Do this BEFORE
        #     paying for an LLM call. ---
        if verdict.source == "heuristic" and synth:
            verdict.description = synth
            verdict.vendor = (
                proc.signing.developer or vendor_from_copyright(proc.bundle.get("copyright"))
            )
            verdict.category = Category.UNKNOWN  # identified, but signature trust is weak
            verdict.confidence = 0.5
            verdict.source = "metadata"
            if trust in (TrustLevel.UNSIGNED, TrustLevel.ADHOC):
                verdict.reasons.append(f"binary is {trust.value}")

        # --- Layer 4: Claude fallback for whatever metadata still couldn't identify ---
        if (
            self.settings.use_llm
            and verdict.source in ("heuristic", "signature")
            and verdict.confidence < 0.65
        ):
            llm_verdict = self.llm.classify(proc)
            if llm_verdict and "_error" not in llm_verdict:
                self._apply_llm(verdict, llm_verdict)

        # --- Default: genuinely unidentifiable ---
        if verdict.source == "heuristic":
            verdict.category = Category.UNKNOWN
            verdict.description = self._heuristic_description(proc, trust)
            verdict.confidence = 0.3
            if trust in (TrustLevel.UNSIGNED, TrustLevel.ADHOC):
                verdict.reasons.append(f"binary is {trust.value}")

        # --- Persist what we learned, and surface the last-analysed date. ---
        self.store.record(proc, verdict, key)
        recorded = self.store.get(key)
        if recorded:
            verdict.analyzed_at = recorded.get("last_analyzed")
        return verdict

    # ---- layer appliers ----
    def _apply_known(self, verdict: Verdict, entry: KnownEntry) -> None:
        verdict.category = entry.category
        verdict.description = entry.description
        verdict.vendor = entry.vendor
        verdict.safe_to_kill = entry.safe_to_kill
        verdict.confidence = 0.9
        verdict.source = "known_db"

    def _apply_reputation(self, verdict: Verdict, rep: dict) -> None:
        v = rep.get("verdict")
        if v == "malicious":
            verdict.category = Category.MALICIOUS
            verdict.safe_to_kill = False  # don't auto-kill; user should investigate
            verdict.confidence = 0.95
            verdict.source = "virustotal"
            verdict.reasons.append(
                f"VirusTotal: {rep.get('malicious', 0)} engines flag this as malicious"
            )
        elif v == "suspicious":
            if verdict.category not in (Category.SYSTEM_CRITICAL,):
                verdict.category = Category.SUSPICIOUS
            verdict.confidence = max(verdict.confidence, 0.7)
            verdict.reasons.append("VirusTotal: flagged suspicious by ≥1 engine")
        elif v == "clean" and verdict.source == "heuristic":
            verdict.reasons.append("VirusTotal: clean across all engines")
            verdict.confidence = max(verdict.confidence, 0.55)

    def _apply_llm(self, verdict: Verdict, lv: dict) -> None:
        apply_llm_item(verdict, lv)

    def _heuristic_description(self, proc: ProcessInfo, trust: TrustLevel) -> str:
        if proc.cmdline:
            return f"Unidentified process running: {' '.join(proc.cmdline[:4])}"
        return f"Unidentified process '{proc.name}' ({trust.value} binary)."
