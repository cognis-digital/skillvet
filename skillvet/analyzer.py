"""Static trust analysis of a skill / MCP / plugin package. Stdlib only, no execution.

skillvet never runs the package. It reads the files and looks for the capabilities that decide
whether a skill is safe to trust: network egress, process execution, credential/filesystem access,
install hooks, and hidden/obfuscated code — plus (optionally) an agentsigs content scan of the
skill's prose. It turns those into a 0-100 trust score and a TRUST / REVIEW / BLOCK verdict.
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

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

    @property
    def score(self) -> int:
        """0-100 trust score; 100 = clean. Capabilities subtract weight (deduped per capability)."""
        seen = {}
        for f in self.findings:
            seen[f.capability] = max(seen.get(f.capability, 0), CHECKS.get(f.capability, {}).get("weight", 10))
        penalty = sum(seen.values()) + min(self.content_matches * 8, 24)
        return max(0, 100 - penalty)

    @property
    def verdict(self) -> str:
        s = self.score
        crit = any(f.severity == "critical" for f in self.findings)
        if crit or s < 40:
            return "BLOCK"
        if s < 75 or self.findings or self.content_matches:
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


def analyze(path: str, content_scan: bool = True) -> Verdict:
    """Analyze a package directory (or a single file) and return a Verdict."""
    v = Verdict(package=os.path.basename(os.path.abspath(path)))
    files = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, _, fnames in os.walk(path):
            if any(skip in root for skip in ("node_modules", ".git", "__pycache__")):
                continue
            for f in fnames:
                files.append(os.path.join(root, f))
    for fp in files:
        base = os.path.basename(fp)
        try:
            text = open(fp, encoding="utf-8", errors="replace").read()
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
