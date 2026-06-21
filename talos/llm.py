"""Claude classifier — identifies processes the cheaper layers can't.

Two ways to reach Claude:
  * **Headless** (default): shell out to the `claude` CLI in print mode (`claude -p`). This
    uses your existing Claude Code login — no API key needed.
  * **API**: the Anthropic SDK with ANTHROPIC_API_KEY, used only if the `claude` CLI isn't
    installed (or you force it).

And two granularities:
  * ``classify(proc)`` — one process, used by the scan-time `--llm` fallback.
  * ``classify_batch(procs)`` — a *list* of processes in one prompt, returning a JSON list.
    This is what the group/auto-analyze uses: callers chunk the work (≈12 per call) so the
    model stays grounded and doesn't hallucinate, and it's far cheaper than one call each.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

from .config import Settings
from .knowledge import KnowledgeBase
from .models import ProcessInfo

_CATEGORIES = [
    "system_critical", "system_service", "trusted_app",
    "known_safe_to_kill", "unknown", "suspicious", "malicious",
]

_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "vendor": {"type": "string"},
        "category": {"type": "string", "enum": _CATEGORIES},
        "safe_to_kill": {"type": "boolean"},
        "confidence": {"type": "number"},
        "reasoning": {"type": "string"},
    },
    "required": ["description", "vendor", "category", "safe_to_kill", "confidence", "reasoning"],
    "additionalProperties": False,
}

_SYSTEM = (
    "You are a macOS process-security analyst. For each process you are given, identify "
    "what it is, what it does, how risky it is, and whether it is safe to terminate. Be "
    "conservative: if a process looks like core system infrastructure or you are unsure, "
    "mark it not safe to kill. Treat unsigned binaries with outbound connections to raw "
    "IPs as suspicious. Only describe what you can actually infer — never invent details."
)


class LLMClassifier:
    def __init__(self, settings: Settings, kb: KnowledgeBase) -> None:
        self.settings = settings
        self.kb = kb
        self._client = None

    # ---- backend selection ----
    def _backend(self) -> Optional[str]:
        pref = self.settings.llm_backend
        has_cli = shutil.which("claude") is not None
        has_key = bool(self.settings.anthropic_api_key)
        if pref == "api":
            return "api" if has_key else None
        if pref == "headless":
            return "headless" if has_cli else None
        # auto: prefer the CLI (no API key needed), fall back to the API.
        if has_cli:
            return "headless"
        if has_key:
            return "api"
        return None

    def available(self) -> bool:
        return self._backend() is not None

    def backend_name(self) -> str:
        return self._backend() or "none"

    def _get_client(self):
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self.settings.anthropic_api_key)
        return self._client

    # ---- single process (scan-time fallback) ----
    def classify(self, proc: ProcessInfo) -> Optional[dict]:
        sha = proc.signing.sha256 if proc.signing else None
        key = self.kb.llm_key(proc.name, proc.exe, sha)
        cached = self.kb.get_llm(key)
        if cached:
            return cached
        backend = self._backend()
        if backend is None:
            return None
        try:
            if backend == "api" and not self.settings.llm_web_search:
                verdict = self._api_structured(proc)
            else:
                text = self._run(self._single_prompt(proc))
                verdict = _parse_obj(text)
        except Exception as exc:
            return {"_error": str(exc)}
        if not verdict or "_error" in verdict:
            return verdict
        verdict["source"] = "llm"
        self.kb.put_llm(key, verdict)
        return verdict

    # ---- batch: a list of processes -> a list of verdicts (keyed by pid) ----
    def classify_batch(self, procs: list[ProcessInfo]) -> dict[int, dict]:
        if not procs or self._backend() is None:
            return {}
        try:
            text = self._run(self._batch_prompt(procs))
        except Exception:
            return {}
        out: dict[int, dict] = {}
        for item in _parse_list(text):
            try:
                pid = int(item.get("pid"))
            except (TypeError, ValueError):
                continue
            item["source"] = "llm"
            out[pid] = item
        return out

    # ---- transport ----
    def _run(self, prompt: str) -> str:
        """Run a prompt through whichever backend is active; return the model's text."""

        if self._backend() == "headless":
            return self._run_headless(prompt)
        return self._run_api_text(prompt)

    def _run_headless(self, prompt: str) -> str:
        cmd = ["claude", "-p", prompt, "--output-format", "json"]
        if self.settings.llm_web_search:
            cmd += ["--allowedTools", "WebSearch"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=420, check=False)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "claude CLI failed")
        out = proc.stdout.strip()
        try:
            env = json.loads(out)
            if isinstance(env, dict) and "result" in env:
                return env["result"]
        except json.JSONDecodeError:
            pass
        return out

    def _run_api_text(self, prompt: str) -> str:
        client = self._get_client()
        tools = (
            [{"type": "web_search_20260209", "name": "web_search", "max_uses": 5}]
            if self.settings.llm_web_search
            else []
        )
        messages = [{"role": "user", "content": prompt}]
        resp = None
        for _ in range(6):
            resp = client.messages.create(
                model=self.settings.llm_model, max_tokens=4096,
                system=_SYSTEM, messages=messages, tools=tools or None,
            )
            if resp.stop_reason == "pause_turn":
                messages.append({"role": "assistant", "content": resp.content})
                continue
            break
        return "".join(b.text for b in resp.content if b.type == "text") if resp else ""

    def _api_structured(self, proc: ProcessInfo) -> dict:
        resp = self._get_client().messages.create(
            model=self.settings.llm_model, max_tokens=1024, system=_SYSTEM,
            output_config={
                "format": {"type": "json_schema", "schema": _VERDICT_SCHEMA},
                "effort": self.settings.llm_effort,
            },
            messages=[{"role": "user", "content": "Classify this macOS process:\n" + self._descriptor(proc)}],
        )
        return _parse_obj(next((b.text for b in resp.content if b.type == "text"), ""))

    # ---- prompts ----
    def _descriptor(self, proc: ProcessInfo) -> str:
        sig = proc.signing
        sig_desc = "unknown"
        if sig:
            sig_desc = sig.trust.value + (f" (team {sig.team_id})" if sig.team_id else "")
            if sig.authority:
                sig_desc += f"; {sig.authority[0]}"
        egress = [
            f"{c.remote_ip}:{c.remote_port}"
            + (f" [{c.org}]" if c.org else "")
            + (f" !{','.join(c.flags)}" if c.flags else "")
            for c in proc.connections if c.is_egress
        ]
        b = proc.bundle or {}
        bundle_line = ", ".join(
            f"{k}={b[k]}" for k in ("name", "bundle_id", "version", "copyright") if b.get(k)
        )
        lines = [
            f"  name: {proc.name}",
            f"  executable: {proc.exe or 'unknown'}",
            f"  command: {' '.join(proc.cmdline[:12]) or 'unknown'}",
            f"  user: {proc.username or 'unknown'} (root={proc.is_root})",
            f"  signature: {sig_desc}",
        ]
        if bundle_line:
            lines.append(f"  bundle Info.plist: {bundle_line}")
        lines.append(f"  outbound: {egress or 'none'}")
        return "\n".join(lines)

    def _json_shape(self) -> str:
        return (
            '{"description": str (1-2 sentences on what it is and what it\'s for), '
            '"vendor": str, "category": one of '
            + json.dumps(_CATEGORIES)
            + ', "safe_to_kill": bool (true only if killing it is harmless), '
            '"confidence": number 0-1, "reasoning": str}'
        )

    def _single_prompt(self, proc: ProcessInfo) -> str:
        search = (
            "If you don't recognise this binary, search the web to identify it. "
            if self.settings.llm_web_search else ""
        )
        return (
            "Identify this macOS process:\n" + self._descriptor(proc) + "\n\n" + search
            + "Respond with ONLY a JSON object — no prose — of the form:\n" + self._json_shape()
        )

    def _batch_prompt(self, procs: list[ProcessInfo]) -> str:
        search = (
            "If you don't recognise a binary, search the web to identify it. "
            if self.settings.llm_web_search else ""
        )
        blocks = []
        for p in procs:
            blocks.append(f"- pid {p.pid}:\n" + self._descriptor(p))
        return (
            f"Identify each of these {len(procs)} macOS processes. {search}\n\n"
            + "\n".join(blocks)
            + "\n\nRespond with ONLY a JSON array — no prose, no markdown fences — with "
            "exactly one object per process above, each of the form:\n"
            '{"pid": int (the pid given above), '
            + self._json_shape()[1:]
            + "\nInclude every pid exactly once. Do not invent processes that weren't listed."
        )


# ---- lenient JSON extraction (headless output may include stray text) ----
def _parse_obj(text: str) -> dict:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
        return {"_error": "could not parse LLM response"}


def _parse_list(text: str) -> list[dict]:
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
    except (json.JSONDecodeError, TypeError):
        pass
    start, end = text.find("["), text.rfind("]")
    if 0 <= start < end:
        try:
            data = json.loads(text[start : end + 1])
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
    return []
