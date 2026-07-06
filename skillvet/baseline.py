"""Baseline / rug-pull detection. Stdlib only, no execution.

A skill you trusted at install can turn hostile on its next "update" — the classic rug-pull.
skillvet records a fingerprint of a package you've reviewed:

    skillvet baseline ./skill -o baseline.json

and later compares an update against it:

    skillvet diff baseline.json ./skill

The fingerprint (schema: schema/baseline.schema.json) is per-file SHA-256 hashes plus the
capability set and trust score at record time. A diff reports files added/removed/changed and —
the headline signal — **capabilities that newly appeared**. New process_exec / network_egress /
credential_access on an update is the rug-pull, and skillvet flags it loudly.

"Signed-ish": the fingerprint includes a self-hash (BLAKE2b over the canonical body) so tampering
with the baseline file itself is detectable. It is integrity, not authenticity — see the roadmap
issue on cryptographically signed baselines.
"""
from __future__ import annotations
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .analyzer import analyze, check_meta
from .policy import Policy

BASELINE_VERSION = 1
# Capabilities whose *appearance* on an update is treated as a rug-pull red flag.
RUGPULL_CAPS = ("process_exec", "credential_access", "network_egress", "dynamic_fetch",
                "obfuscation", "install_hook", "exfiltration_surface")


def _iter_files(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]
    files: List[str] = []
    for root, _, fnames in os.walk(path):
        if any(skip in root.split(os.sep) for skip in ("node_modules", ".git", "__pycache__")):
            continue
        for f in fnames:
            files.append(os.path.join(root, f))
    return files


def _rel(path: str, base: str) -> str:
    if os.path.isfile(base):
        return os.path.basename(path)
    return os.path.relpath(path, base).replace(os.sep, "/")


def file_hashes(path: str) -> Dict[str, str]:
    """SHA-256 per file, keyed by forward-slash relative path (stable across OSes)."""
    out: Dict[str, str] = {}
    for fp in _iter_files(path):
        try:
            with open(fp, "rb") as fh:
                out[_rel(fp, path)] = hashlib.sha256(fh.read()).hexdigest()
        except Exception:
            continue
    return out


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record(path: str, content_scan: bool = True,
           policy: Optional[Policy] = None) -> dict:
    """Build a baseline fingerprint for a package."""
    v = analyze(path, content_scan=content_scan, policy=policy)
    body = {
        "version": BASELINE_VERSION,
        "package": v.package,
        "score": v.score,
        "verdict": v.verdict,
        "capabilities": v.capabilities,
        "files": file_hashes(path),
    }
    body["self_hash"] = hashlib.blake2b(_canonical(body), digest_size=16).hexdigest()
    return body


def save(baseline: dict, out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, sort_keys=True)


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def verify_integrity(baseline: dict) -> bool:
    """True if the baseline's self_hash matches its body (tamper check)."""
    claimed = baseline.get("self_hash")
    if not claimed:
        return False
    body = {k: v for k, v in baseline.items() if k != "self_hash"}
    return hashlib.blake2b(_canonical(body), digest_size=16).hexdigest() == claimed


@dataclass
class Diff:
    package: str
    files_added: List[str] = field(default_factory=list)
    files_removed: List[str] = field(default_factory=list)
    files_changed: List[str] = field(default_factory=list)
    new_capabilities: List[str] = field(default_factory=list)
    removed_capabilities: List[str] = field(default_factory=list)
    old_score: int = 0
    new_score: int = 0
    integrity_ok: bool = True

    @property
    def new_dangerous(self) -> List[str]:
        """Newly-appeared capabilities that are rug-pull red flags."""
        return sorted(c for c in self.new_capabilities if c in RUGPULL_CAPS)

    @property
    def is_rugpull(self) -> bool:
        return bool(self.new_dangerous)

    @property
    def changed(self) -> bool:
        return bool(self.files_added or self.files_removed or self.files_changed
                    or self.new_capabilities or self.removed_capabilities)


def diff(baseline: dict, path: str, content_scan: bool = True,
         policy: Optional[Policy] = None) -> Diff:
    """Compare a package against a recorded baseline; surface what changed (rug-pull signal)."""
    integrity = verify_integrity(baseline)
    cur = analyze(path, content_scan=content_scan, policy=policy)
    cur_hashes = file_hashes(path)
    old_hashes: Dict[str, str] = baseline.get("files", {})

    added = sorted(set(cur_hashes) - set(old_hashes))
    removed = sorted(set(old_hashes) - set(cur_hashes))
    changed = sorted(f for f in (set(cur_hashes) & set(old_hashes))
                     if cur_hashes[f] != old_hashes[f])

    old_caps = set(baseline.get("capabilities", []))
    new_caps = set(cur.capabilities)
    return Diff(
        package=cur.package,
        files_added=added, files_removed=removed, files_changed=changed,
        new_capabilities=sorted(new_caps - old_caps),
        removed_capabilities=sorted(old_caps - new_caps),
        old_score=int(baseline.get("score", 0)),
        new_score=cur.score,
        integrity_ok=integrity,
    )


def diff_to_dict(d: Diff) -> dict:
    return {
        "package": d.package,
        "integrity_ok": d.integrity_ok,
        "old_score": d.old_score, "new_score": d.new_score,
        "files_added": d.files_added, "files_removed": d.files_removed,
        "files_changed": d.files_changed,
        "new_capabilities": d.new_capabilities,
        "removed_capabilities": d.removed_capabilities,
        "new_dangerous": d.new_dangerous,
        "is_rugpull": d.is_rugpull,
        "changed": d.changed,
    }
