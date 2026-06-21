"""Code-signature & notarization inspection — the cheapest authoritative trust signal.

On macOS, ``codesign`` and ``spctl`` tell us *who* made a binary and whether Apple
notarized it, entirely offline. Apple-signed system binaries and notarized Developer ID
apps are trustworthy; ad-hoc/unsigned binaries deserve scrutiny.

Results are cached in-process keyed by (path, mtime, size) so a scan that sees the same
executable many times (helpers, forks) pays the subprocess cost once.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from .models import SigningInfo, TrustLevel

_CACHE: dict[tuple, SigningInfo] = {}

_AUTHORITY_RE = re.compile(r"Authority=(.+)")
_TEAMID_RE = re.compile(r"TeamIdentifier=(.+)")
_IDENT_RE = re.compile(r"Identifier=(.+)")
# "Developer ID Application: OpenVPN Inc. (ACV7L3WCD8)" → developer name + team id
_DEVNAME_RE = re.compile(r"Developer ID Application:\s*(.+?)\s*\(([A-Z0-9]+)\)")

# Bundle directory suffixes — the signature lives on the bundle, not the inner Mach-O.
_BUNDLE_EXTS = (
    ".app", ".xpc", ".framework", ".dext", ".appex", ".systemextension",
    ".bundle", ".kext", ".plugin", ".pluginkit", ".qlgenerator", ".mdimporter",
)

def _bundle_root(exe: str) -> str:
    """The nearest enclosing bundle directory for an exe path, else the exe itself."""

    p = Path(exe)
    for parent in p.parents:
        if parent.name.endswith(_BUNDLE_EXTS):
            return str(parent)
    return exe


def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return -1, "", str(exc)


def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def inspect_signature(exe: str | None, hash_file: bool = False) -> SigningInfo:
    if not exe:
        return SigningInfo(trust=TrustLevel.UNKNOWN, error="no executable path")

    try:
        st = Path(exe).stat()
        key = (exe, int(st.st_mtime), st.st_size, hash_file)
    except OSError:
        key = (exe, 0, 0, hash_file)
    if key in _CACHE:
        return _CACHE[key]

    info = SigningInfo()

    # Read the signature on the binary ITSELF first. Most standalone daemons (e.g.
    # /System/.../Support/fseventsd) carry their own signature here. Only if the binary is
    # genuinely "not signed" do we retry against the enclosing bundle — that covers the case
    # where the signature lives on the .app/.xpc/.dext rather than the inner Mach-O.
    target = exe
    rc, _out, err = _run(["codesign", "-dv", "--verbose=4", exe])
    if rc != 0 and "not signed" in err.lower():
        bundle = _bundle_root(exe)
        if bundle != exe:
            rc2, _o2, err2 = _run(["codesign", "-dv", "--verbose=4", bundle])
            if not (rc2 != 0 and "not signed" in err2.lower()):
                rc, err, target = rc2, err2, bundle

    info.signed_target = target
    text = err
    if rc != 0 and "not signed" in text.lower():
        info.trust = TrustLevel.UNSIGNED
    elif rc != 0 and not _AUTHORITY_RE.search(text):
        info.trust = TrustLevel.UNKNOWN
        info.error = text.strip() or "codesign failed"
    else:
        info.authority = [m.group(1).strip() for m in _AUTHORITY_RE.finditer(text)]
        tm = _TEAMID_RE.search(text)
        if tm and tm.group(1).strip() not in ("not set", ""):
            info.team_id = tm.group(1).strip()
        im = _IDENT_RE.search(text)
        if im:
            info.identifier = im.group(1).strip()
        dm = _DEVNAME_RE.search(text)
        if dm:
            info.developer = dm.group(1).strip()
            info.team_id = info.team_id or dm.group(2)
        info.trust = _classify_authority(info.authority, text)

    # ACTUAL integrity verification (not just reading the claimed signature):
    # `codesign --verify --strict` recomputes the code hashes and checks the seal.
    if info.authority:
        vrc, _vo, _ve = _run(["codesign", "--verify", "--strict", target], timeout=8.0)
        info.verified = vrc == 0
        if not info.verified:
            # A signature is present but the bytes don't match it — a real red flag.
            info.trust = TrustLevel.UNKNOWN
            info.error = (info.error or "") + " signature present but failed --verify"

    # spctl confirms Gatekeeper acceptance / notarization for non-system binaries.
    if info.trust in (TrustLevel.DEV_ID, TrustLevel.UNKNOWN, TrustLevel.ADHOC):
        rc3, out3, err3 = _run(["spctl", "-a", "-t", "exec", "-vv", target])
        assess = (out3 + err3).lower()
        if "source=notarized developer id" in assess:
            info.trust = TrustLevel.DEV_ID_NOTARIZED
            info.notarized = True
        elif "source=mac app store" in assess:
            info.trust = TrustLevel.APP_STORE
        elif "source=apple system" in assess:
            info.trust = TrustLevel.APPLE_SYSTEM

    if hash_file:
        info.sha256 = _sha256(exe)  # hash the actual Mach-O, not the bundle dir

    _CACHE[key] = info
    return info


def _classify_authority(authority: list[str], raw: str) -> TrustLevel:
    joined = " | ".join(authority).lower()
    raw_l = raw.lower()
    if "software signing" in joined and "apple" in joined:
        return TrustLevel.APPLE_SYSTEM
    if "apple root ca" in joined and "developer id" not in joined and authority:
        # Apple-issued leaf without a Developer ID — treat as system component.
        return TrustLevel.APPLE_SYSTEM
    if "developer id application" in joined:
        return TrustLevel.DEV_ID
    if "apple mac os application signing" in joined or "mac app store" in joined:
        return TrustLevel.APP_STORE
    if "adhoc" in raw_l or "linker-signed" in raw_l:
        return TrustLevel.ADHOC
    if authority:
        return TrustLevel.DEV_ID
    return TrustLevel.UNKNOWN
