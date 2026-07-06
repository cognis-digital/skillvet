"""Manifest / permission-scope vetting. Stdlib only, no execution.

A well-behaved skill package declares what it needs. skillvet parses the manifests it can read —
SKILL.md YAML-ish frontmatter, package.json, MCP server config (mcp.json / .mcp.json /
mcp_config.json / claude_desktop_config.json), and pyproject.toml — and flags two honest signals:

  1. Broad permissions declared at all (exec/network/filesystem/credential scopes) — a skill that
     *asks* for a shell or your secrets is worth reviewing even before you read its code.
  2. Declared-vs-used mismatch — the manifest DECLARES a permission the code never appears to use.
     (We only assert this for the strongest signal: exec/credential declared but not observed.)

We only flag what we can actually parse. No YAML dependency: the frontmatter reader is a tiny
line-based parser for the flat `key: value` and `key: [a, b]` / `- item` shapes skills use.
Everything is best-effort and degrades to "no finding" on anything it can't read.
"""
from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

# Manifest files we know how to read.
MANIFEST_NAMES = ("SKILL.md", "package.json", "pyproject.toml", "mcp.json", ".mcp.json",
                  "mcp_config.json", "claude_desktop_config.json", "manifest.json")

# Declared-permission keyword -> the capability it maps to. Case-insensitive substring match
# against declared scope/permission strings found in manifests.
PERMISSION_MAP = {
    "process_exec": ("exec", "shell", "command", "subprocess", "run_command", "terminal", "bash"),
    "network_egress": ("network", "http", "fetch", "egress", "internet", "url", "outbound", "web"),
    "credential_access": ("credential", "secret", "token", "apikey", "api_key", "keychain",
                          "env", "environment"),
    "filesystem_write": ("filesystem", "file_write", "write", "fs", "disk", "storage"),
}


@dataclass
class ManifestFinding:
    capability: str
    severity: str
    why: str
    file: str
    line: int
    atlas: str = ""


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def parse_frontmatter(text: str) -> Dict[str, object]:
    """Parse a leading `---`-delimited YAML-ish frontmatter block into a flat dict.

    Supports `key: value`, inline lists `key: [a, b]`, and block lists (`key:` then `- item`).
    Nested maps are collapsed to their leaf strings. Deliberately tiny; not a full YAML parser."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    block = text[3:end]
    out: Dict[str, object] = {}
    cur_key: Optional[str] = None
    for raw in block.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        m = re.match(r"^(\s*)-\s+(.*)$", line)
        if m and cur_key:
            lst = out.setdefault(cur_key, [])
            if isinstance(lst, list):
                lst.append(m.group(2).strip().strip("'\""))
            continue
        m = re.match(r"^(\w[\w\-]*)\s*:\s*(.*)$", line)
        if m:
            key, val = m.group(1).strip(), m.group(2).strip()
            cur_key = key
            if val == "":
                out[key] = []
            elif val.startswith("[") and val.endswith("]"):
                out[key] = [x.strip().strip("'\"") for x in val[1:-1].split(",") if x.strip()]
            else:
                out[key] = val.strip("'\"")
    return out


def _collect_scope_strings(obj: object, acc: List[str]) -> None:
    """Recursively pull every string out of a parsed manifest structure, so we can substring-match
    declared permissions/scopes wherever a skill author put them."""
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            acc.append(str(k))
            _collect_scope_strings(v, acc)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_scope_strings(v, acc)


# Keys in a manifest whose *contents* are permission/scope declarations. We only treat strings
# under these keys as declared permissions to avoid false positives from unrelated prose.
PERMISSION_KEYS = ("permissions", "permission", "scopes", "scope", "allowed-tools",
                   "allowed_tools", "capabilities", "grants", "access", "requires")


def _declared_permissions(parsed: object) -> Set[str]:
    """Map declared scope strings (only those under permission-ish keys) to capabilities."""
    strings: List[str] = []

    def walk(o: object) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() in PERMISSION_KEYS:
                    _collect_scope_strings(v, strings)
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)

    walk(parsed)
    declared: Set[str] = set()
    for s in strings:
        low = s.lower()
        for cap, kws in PERMISSION_MAP.items():
            if any(kw in low for kw in kws):
                declared.add(cap)
    return declared


def _mcp_declares_command(parsed: object) -> bool:
    """An MCP server config that launches via `command`/`args` is, by construction, a process
    the host will exec on your box. That is a declared exec surface worth surfacing."""
    if isinstance(parsed, dict):
        if "command" in parsed and parsed.get("command"):
            return True
        for v in parsed.values():
            if _mcp_declares_command(v):
                return True
    elif isinstance(parsed, (list, tuple)):
        return any(_mcp_declares_command(v) for v in parsed)
    return False


def _analyze_manifest(name: str, text: str, path: str,
                      used: Set[str], out: List[ManifestFinding]) -> None:
    parsed: object = {}
    is_mcp = name in ("mcp.json", ".mcp.json", "mcp_config.json",
                      "claude_desktop_config.json") or "mcpServers" in text
    if name.endswith(".json"):
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = {}
    elif name == "SKILL.md":
        parsed = parse_frontmatter(text)
    elif name == "pyproject.toml":
        # Minimal: pull scope-ish lines without a TOML dep.
        parsed = {"requires": re.findall(r"(?im)^\s*(?:permissions|scopes)\s*=\s*(.+)$", text)}

    declared = _declared_permissions(parsed)

    # MCP command surface: declared exec even if code wasn't scanned.
    if is_mcp and _mcp_declares_command(parsed):
        declared.add("process_exec")

    for cap in sorted(declared):
        # Broad permission declared: always worth surfacing.
        why = f"manifest declares a {cap.replace('_', ' ')} permission/scope"
        # Declared-vs-used mismatch is the sharper signal for the dangerous scopes.
        if cap in ("process_exec", "credential_access") and cap not in used:
            why += " that the code does not appear to use (over-broad request)"
        out.append(ManifestFinding("manifest_overbroad", "high", why, path, 0, "AML.T0051"))


def scan_manifests(path: str, used_capabilities: Optional[Set[str]] = None) -> List["ManifestFinding"]:
    """Walk a package (or handle a single file) and return manifest_overbroad findings."""
    used = used_capabilities or set()
    out: List[ManifestFinding] = []
    targets: List[str] = []
    if os.path.isfile(path):
        if os.path.basename(path) in MANIFEST_NAMES:
            targets = [path]
    else:
        for root, _, fnames in os.walk(path):
            if any(skip in root.split(os.sep) for skip in ("node_modules", ".git", "__pycache__")):
                continue
            for f in fnames:
                if f in MANIFEST_NAMES:
                    targets.append(os.path.join(root, f))
    for fp in targets:
        text = _read(fp)
        if text:
            _analyze_manifest(os.path.basename(fp), text, fp, used, out)
    return out
