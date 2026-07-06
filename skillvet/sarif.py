"""SARIF 2.1.0 output. Stdlib only.

SARIF (Static Analysis Results Interchange Format, OASIS 2.1.0) is what GitHub code scanning,
Azure DevOps, and most CI security dashboards ingest. Emitting SARIF makes skillvet a CI-native
scanner: `skillvet vet PATH -f sarif > skillvet.sarif` and upload it.

One SARIF rule per capability (rule id == capability). Each rule carries:
  - a full description = the "why this matters"
  - a severity level (SARIF: error/warning/note) mapped from skillvet severity
  - properties.tags = the MITRE ATLAS technique + "security"
Each finding becomes a `result` referencing its rule, at the file/line where skillvet saw it.
"""
from __future__ import annotations
import os
from typing import Dict, List

from . import __version__
from .analyzer import ALL_CAPABILITIES, check_meta

# skillvet severity -> SARIF result level and a numeric security-severity (GitHub uses 0.0-10.0).
_LEVEL = {"critical": ("error", "9.0"), "high": ("error", "7.5"),
          "medium": ("warning", "5.0"), "low": ("note", "3.0")}

# Human-readable rule descriptions (the "why") per capability.
_RULE_HELP = {
    "process_exec": "The package can execute processes or evaluate code (subprocess, os.system, "
                    "eval/exec, child_process). A skill that only transforms text does not need this.",
    "network_egress": "The package can send data off the machine (HTTP clients, raw sockets, "
                      "curl/wget). Egress is how exfiltrated data leaves.",
    "credential_access": "The package reads credentials — SSH keys, cloud credential files, .env, "
                         "environment variables — or embeds a secret.",
    "filesystem_write": "The package writes to or deletes files on disk.",
    "obfuscation": "The package hides code behind base64/hex encoding or decodes-then-executes — a "
                   "common way to smuggle a payload past review.",
    "dynamic_fetch": "The package fetches and executes remote code or installs packages from a URL "
                     "at runtime — the code you review is not the code that runs.",
    "install_hook": "The package runs code at install time (npm pre/postinstall, setup.py, build "
                    "hooks) — a classic supply-chain foothold that fires before you ever use it.",
    "exfiltration_surface": "The package both reads credentials AND has network egress — the two "
                            "halves of an exfiltration path in one package.",
    "manifest_overbroad": "The manifest declares broad or unused permissions/scopes (e.g. requests "
                          "exec/network/credential access the code does not appear to use).",
}


def _rule(cap: str) -> dict:
    meta = check_meta(cap)
    level, sec = _LEVEL.get(meta.get("severity", "medium"), ("warning", "5.0"))
    tags = ["security", "supply-chain"]
    atlas = meta.get("atlas", "")
    if atlas:
        tags.append(f"ATLAS/{atlas}")
    help_text = _RULE_HELP.get(cap, cap)
    return {
        "id": cap,
        "name": "".join(p.capitalize() for p in cap.split("_")),
        "shortDescription": {"text": f"{cap} capability detected"},
        "fullDescription": {"text": help_text},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": level},
        "properties": {
            "tags": tags,
            "security-severity": sec,
            "atlas": atlas,
            "skillvet-severity": meta.get("severity", "medium"),
        },
    }


def _uri(path: str) -> str:
    """Forward-slash relative-ish URI for SARIF locations (SARIF wants URIs, not backslashes)."""
    return str(path).replace("\\", "/")


def to_sarif(verdict) -> dict:
    """Build a SARIF 2.1.0 log for a skillvet Verdict."""
    results: List[dict] = []
    for f in verdict.findings:
        meta = check_meta(f.capability)
        level, _ = _LEVEL.get(meta.get("severity", "medium"), ("warning", "5.0"))
        region = {"startLine": max(1, int(f.line))} if f.line and f.line > 0 else {"startLine": 1}
        results.append({
            "ruleId": f.capability,
            "level": level,
            "message": {"text": f.why},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.file)},
                    "region": region,
                }
            }],
            "properties": {"atlas": f.atlas, "capability": f.capability},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "skillvet",
                    "informationUri": "https://github.com/cognis-digital/skillvet",
                    "version": __version__,
                    "rules": [_rule(c) for c in ALL_CAPABILITIES],
                }
            },
            "results": results,
            "properties": {
                "skillvet.package": verdict.package,
                "skillvet.verdict": verdict.verdict,
                "skillvet.score": verdict.score,
                "skillvet.capabilities": verdict.capabilities,
                "skillvet.contentMatches": verdict.content_matches,
            },
        }],
    }
