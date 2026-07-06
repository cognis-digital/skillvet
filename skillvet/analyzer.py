"""Static trust analysis of a skill / MCP / plugin package. Stdlib only, no execution.

skillvet never runs the package. It reads the files and looks for the capabilities that decide
whether a skill is safe to trust: network egress, process execution, credential/filesystem access,
install hooks, and hidden/obfuscated code — plus (optionally) an agentsigs content scan of the
skill's prose. It turns those into a 0-100 trust score and a TRUST / REVIEW / BLOCK verdict.

Two correlated signals sit on top of the per-file capability checks:
  - exfiltration_surface: credential_access + network_egress in the same file/package is worse
    than either alone (read secrets AND phone home = a exfil path).
  - manifest_overbroad: a manifest that DECLARES a permission/scope the code never uses (or
    declares broad exec/network/fs permissions at all) is an over-broad request.
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .manifest import scan_manifests
from .policy import Policy

CODE_EXT = (".py", ".js", ".ts", ".mjs", ".sh", ".bash", ".rb", ".ps1")
TEXT_EXT = (".md", ".txt", ".json", ".yaml", ".yml", ".toml")

# capability -> (severity, weight, [ (regex, why) ])
CHECKS: Dict[str, dict] = {
    "process_exec": {"severity": "critical", "weight": 30, "atlas": "AML.T0053", "patterns": [
        (r"\bsubprocess\.(run|call|Popen|check_output)", "spawns a subprocess"),
        (r"\bos\.(system|popen|exec[lv]?[pe]?)\b", "executes a shell command"),
        (r"\b(child_process|execSync|spawnSync|spawn|exec)\s*\(", "executes a subprocess (node)"),
        (r"\beval\s*\(|\bexec\s*\(", "evaluates code at runtime"),
    ]},
    "network_egress": {"severity": "high", "weight": 20, "atlas": "AML.T0025", "patterns": [
        (r"\b(urllib|requests|httpx|aiohttp|urllib2)\b", "makes HTTP requests"),
        (r"\b(fetch|axios|XMLHttpRequest|http\.request|https\.request)\b", "makes HTTP requests (js)"),
        (r"\bsocket\.(socket|create_connection)\b", "opens a raw socket"),
        (r"\b(curl|wget|nc|ncat)\b", "shells out to a network tool"),
    ]},
    "credential_access": {"severity": "critical", "weight": 30, "atlas": "AML.T0055", "patterns": [
        (r"~/\.ssh|id_rsa|\.aws/credentials|\.env\b|\.netrc|keychain", "reads credential files"),
        (r"\bos\.environ\b|\bprocess\.env\b", "reads environment variables"),
        (r"(AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}|sk_live_)", "contains an embedded credential"),
    ]},
    "filesystem_write": {"severity": "medium", "weight": 10, "atlas": "AML.T0053", "patterns": [
        (r"\bopen\s*\([^)]*['\"][wa]\+?['\"]", "writes files"),
        (r"\b(shutil\.(copy|move|rmtree)|os\.remove|os\.unlink|fs\.writeFile)", "modifies the filesystem"),
    ]},
    "obfuscation": {"severity": "high", "weight": 20, "atlas": "AML.T0051", "patterns": [
        (r"base64\.b64decode[^\n]{0,40}(exec|eval|decode)", "decodes then executes base64"),
        (r"\b(exec|eval)\s*\(\s*(base64|bytes\.fromhex|codecs\.decode)", "executes decoded bytes"),
        (r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/])", "contains a long encoded blob"),
        (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){20,}", "contains a long hex-escaped blob"),
    ]},
    "dynamic_fetch": {"severity": "critical", "weight": 30, "atlas": "AML.T0053", "patterns": [
        (r"(exec|eval)\s*\([^\n]{0,60}(requests\.get|urllib|fetch|http)", "fetches and executes remote code"),
        (r"pip\s+install[^\n]{0,40}(http|git\+)", "installs a package from a URL at runtime"),
    ]},
}

# Capabilities that have no regex patterns of their own — they are derived (correlated or
# parsed from manifests). They still carry severity/weight/atlas so scoring and SARIF are uniform.
DERIVED = {
    "install_hook": {"severity": "high", "weight": 20, "atlas": "AML.T0053",
                     "why": "runs code at install time (supply-chain foothold)"},
    "exfiltration_surface": {"severity": "critical", "weight": 25, "atlas": "AML.T0025",
                             "why": "reads credentials AND has network egress in the same package (exfil path)"},
    "manifest_overbroad": {"severity": "high", "weight": 15, "atlas": "AML.T0051",
                           "why": "manifest declares broad or unused permissions/scopes"},
}


def check_meta(cap: str) -> dict:
    """Uniform metadata (severity/weight/atlas) for any capability, declared or derived."""
    if cap in CHECKS:
        return CHECKS[cap]
    return DERIVED.get(cap, {"severity": "medium", "weight": 10, "atlas": ""})


# Every capability skillvet can emit, for SARIF rule enumeration and docs.
ALL_CAPABILITIES = tuple(list(CHECKS) + list(DERIVED))

INSTALL_HOOK_FILES = {
    "package.json": [(r'"(pre|post)?install"\s*:', "npm install hook runs code on install")],
    "setup.py": [(r"\b(cmdclass|subprocess|os\.system|exec)\b", "setup.py runs code on install")],
    "pyproject.toml": [(r"\[tool\.(poetry\.scripts|hatch\.build\.hooks)", "build hook runs on install")],
}


@dataclass
class Finding:
    capability: str
    severity: str
    why: str
    file: str
    line: int
    atlas: str = ""


@dataclass
class Verdict:
    package: str
    findings: List[Finding] = field(default_factory=list)
    content_matches: int = 0
    files_scanned: int = 0
    policy: Policy = field(default_factory=Policy)

    @property
    def score(self) -> int:
        """0-100 trust score; 100 = clean. Capabilities subtract weight (deduped per capability).

        Weights come from the active policy (defaults mirror check_meta). An allow-listed
        capability contributes 0; a deny-listed capability forces the floor via verdict()."""
        seen: Dict[str, int] = {}
        for f in self.findings:
            if self.policy.is_allowed(f.capability):
                continue
            w = self.policy.weight(f.capability, check_meta(f.capability).get("weight", 10))
            seen[f.capability] = max(seen.get(f.capability, 0), w)
        penalty = sum(seen.values()) + min(self.content_matches * self.policy.content_weight, 24)
        return max(0, 100 - penalty)

    @property
    def verdict(self) -> str:
        caps = set(self.capabilities)
        # A deny-listed capability is an unconditional BLOCK regardless of score.
        if any(self.policy.is_denied(c) for c in caps):
            return "BLOCK"
        s = self.score
        crit = any(f.severity == "critical" and not self.policy.is_allowed(f.capability)
                   for f in self.findings)
        active = [f for f in self.findings if not self.policy.is_allowed(f.capability)]
        if crit or s < self.policy.block_below:
            return "BLOCK"
        if s < self.policy.review_below or active or self.content_matches:
            return "REVIEW"
        return "TRUST"

    @property
    def capabilities(self) -> List[str]:
        return sorted({f.capability for f in self.findings})


def _scan_code(text: str, path: str, out: List[Finding]) -> None:
    lines = text.splitlines()
    for cap, spec in CHECKS.items():
        for rx, why in spec["patterns"]:
            m = re.search(rx, text)
            if m:
                line = text[:m.start()].count("\n") + 1
                out.append(Finding(cap, spec["severity"], why, path, line, spec.get("atlas", "")))
                break  # one finding per capability per file


def _scan_install_hooks(name: str, text: str, path: str, out: List[Finding]) -> None:
    for rx, why in INSTALL_HOOK_FILES.get(name, []):
        m = re.search(rx, text)
        if m:
            out.append(Finding("install_hook", "high", why, path,
                               text[:m.start()].count("\n") + 1, "AML.T0053"))
            break


def _add_exfiltration_surface(findings: List[Finding]) -> None:
    """Correlated signal: credential_access + network_egress => an exfiltration surface.

    Same-file correlation is the strongest signal (read a secret and phone home on the same
    line of code). Package-level correlation (both present anywhere) is still elevated."""
    meta = DERIVED["exfiltration_surface"]
    by_file: Dict[str, set] = {}
    for f in findings:
        by_file.setdefault(f.file, set()).add(f.capability)
    # Same-file: the credential read and the egress live in one module.
    for fp, caps in by_file.items():
        if "credential_access" in caps and "network_egress" in caps:
            findings.append(Finding("exfiltration_surface", meta["severity"],
                                    "same file reads credentials and has network egress",
                                    fp, 0, meta["atlas"]))
            return
    # Package-level: still an exfil path, just spread across files.
    all_caps = {f.capability for f in findings}
    if "credential_access" in all_caps and "network_egress" in all_caps:
        findings.append(Finding("exfiltration_surface", meta["severity"],
                                meta["why"], "<package>", 0, meta["atlas"]))


def analyze(path: str, content_scan: bool = True, policy: Optional[Policy] = None) -> Verdict:
    """Analyze a package directory (or a single file) and return a Verdict."""
    v = Verdict(package=os.path.basename(os.path.abspath(path)),
                policy=policy or Policy())
    files = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, _, fnames in os.walk(path):
            if any(skip in root.split(os.sep) for skip in ("node_modules", ".git", "__pycache__")):
                continue
            for f in fnames:
                files.append(os.path.join(root, f))
    for fp in files:
        base = os.path.basename(fp)
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except Exception:
            continue
        if base in INSTALL_HOOK_FILES:
            _scan_install_hooks(base, text, fp, v.findings)
        if fp.endswith(CODE_EXT):
            v.files_scanned += 1
            _scan_code(text, fp, v.findings)
        elif fp.endswith(TEXT_EXT):
            v.files_scanned += 1
            if base in INSTALL_HOOK_FILES:  # package.json also code-ish
                _scan_code(text, fp, v.findings)
    # Manifest / permission-scope vetting (declared-vs-used mismatch, broad permissions).
    used = {f.capability for f in v.findings}
    for mf in scan_manifests(path, used_capabilities=used):
        v.findings.append(Finding(mf.capability, mf.severity, mf.why, mf.file, mf.line, mf.atlas))
    # Correlated exfiltration surface (credential_access + network_egress).
    _add_exfiltration_surface(v.findings)
    if content_scan:
        v.content_matches = _agentsigs_scan(path)
    return v


def _agentsigs_scan(path: str) -> int:
    """Optional: if shrike is installed, scan the package's prose for injection/poisoning using
    its bundled AI-threat signature library (formerly the standalone agentsigs)."""
    try:
        from shrike.sigs import Library
    except Exception:
        try:
            from agentsigs.engine import Library  # backward-compat if the old package is present
        except Exception:
            return 0
    lib = Library()
    total = 0
    target = path
    if os.path.isfile(path):
        total = len(lib.scan_file(path))
    else:
        results = lib.scan_path(target)
        total = sum(len(v) for v in results.values())
    return total
