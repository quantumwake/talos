"""Extract everything identifying from an app/binary, and synthesize a real description.

Most "unknown" processes are fully identifiable without an LLM: the bundle they live in
carries a name, a reverse-DNS identifier, a version, and a copyright string; the code
signature names the developer; and the filesystem path tells you the *role* (privileged
helper, XPC service, app extension, daemon). We pull all of it together so a process is
described precisely — and when the LLM *is* used, it receives this as grounding context.
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path
from typing import Optional

_BUNDLE_EXTS = (
    ".app", ".framework", ".appex", ".xpc", ".bundle",
    ".systemextension", ".dext", ".plugin", ".kext", ".pluginkit",
)


def _nearest_bundle(exe: str) -> Optional[Path]:
    for parent in Path(exe).parents:
        if parent.suffix in _BUNDLE_EXTS:
            return parent
    return None


def _read_info_plist(bundle: Path) -> Optional[dict]:
    for rel in (
        "Contents/Info.plist", "Resources/Info.plist",
        "Versions/Current/Resources/Info.plist", "Versions/A/Resources/Info.plist",
        "Info.plist",
    ):
        try:
            with open(bundle / rel, "rb") as fh:
                return plistlib.load(fh)
        except Exception:
            continue  # missing / permission-denied / malformed — try the next location
    return None


def bundle_metadata(exe: Optional[str]) -> dict:
    """Pull Info.plist fields from the enclosing bundle. Empty dict if none/unreadable."""

    if not exe:
        return {}
    try:
        b = _nearest_bundle(exe)
    except Exception:
        return {}
    if not b:
        return {}
    out: dict = {"bundle_path": str(b), "bundle_type": b.suffix.lstrip(".")}
    pl = _read_info_plist(b)
    if pl:
        out["name"] = pl.get("CFBundleDisplayName") or pl.get("CFBundleName")
        out["bundle_id"] = pl.get("CFBundleIdentifier")
        out["version"] = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
        out["copyright"] = pl.get("NSHumanReadableCopyright")
        out["category"] = pl.get("LSApplicationCategoryType")
    return {k: v for k, v in out.items() if v}


_COPYRIGHT_RE = re.compile(r"(?:copyright|\(c\)|©)\s*", re.I)
_YEAR_RE = re.compile(r"\b(19|20)\d{2}(\s*[-–]\s*(19|20)?\d{2,4})?\b")


def vendor_from_copyright(copyright: Optional[str]) -> Optional[str]:
    """'Copyright © 2024 Mullvad VPN AB. All rights reserved.' -> 'Mullvad VPN AB'."""

    if not copyright:
        return None
    s = _COPYRIGHT_RE.sub("", copyright)
    s = _YEAR_RE.sub("", s)
    s = re.split(r"\.\s|\bAll rights reserved", s, 1)[0]
    s = s.strip(" .,-–\t")
    return s or None


def _role_from_path(exe: str, bundle_type: Optional[str]) -> Optional[str]:
    """A human label for what kind of component this is, from its path."""

    e = exe
    if "/PrivilegedHelperTools/" in e:
        return "privileged helper (runs as root)"
    if "/LaunchDaemons/" in e:
        return "background daemon"
    if "/LaunchAgents/" in e:
        return "login agent"
    if "/XPCServices/" in e or bundle_type == "xpc":
        return "XPC helper service"
    if bundle_type == "appex" or "/PlugIns/" in e:
        return "app extension"
    if "/Contents/Helpers/" in e or "Helper" in e.rsplit("/", 1)[-1]:
        return "helper process"
    if bundle_type == "framework" or "/Frameworks/" in e:
        return "framework agent"
    if bundle_type == "dext":
        return "DriverKit driver extension"
    if e.rsplit("/", 1)[-1].endswith("d") and "/usr/" in e:
        return "daemon"
    return None


def describe(name: str, exe: Optional[str], bundle: dict,
             developer: Optional[str], cmdline: Optional[list[str]] = None) -> Optional[str]:
    """Synthesize a precise description from bundle + signature + path. None if too thin."""

    vendor = developer or vendor_from_copyright(bundle.get("copyright"))
    bundle_id = bundle.get("bundle_id")
    product = bundle.get("name")
    # Fall back to the .app/.framework bundle name (minus extension) for the product.
    if not product and bundle.get("bundle_path"):
        product = Path(bundle["bundle_path"]).stem
    role = _role_from_path(exe or "", bundle.get("bundle_type"))

    # Need at least one solid identifier to claim we've identified it.
    if not (bundle_id or product or vendor):
        return None

    head = product or (bundle_id.split(".")[-1] if bundle_id else name)
    bits = [head]
    if role:
        bits.append(f"— {role}")
    tail = []
    if bundle_id and bundle_id != head:
        tail.append(bundle_id)
    if bundle.get("version"):
        tail.append(f"v{bundle['version']}")
    if vendor:
        tail.append(f"by {vendor}")
    desc = " ".join(bits)
    if tail:
        desc += " (" + ", ".join(tail) + ")"
    return desc
