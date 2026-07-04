"""skillvet command line — the trust gate.

    skillvet vet PATH          analyze a skill/MCP/plugin package -> trust score + verdict
    skillvet vet PATH -f json  machine-readable

Exit codes (CI / pre-install gate): 0 = TRUST, 1 = REVIEW, 2 = BLOCK.
"""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Optional

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from . import __version__
from .analyzer import analyze, CHECKS

_TAG = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}
_EXIT = {"TRUST": 0, "REVIEW": 1, "BLOCK": 2}
_BADGE = {"TRUST": "TRUST  ✓", "REVIEW": "REVIEW ⚠", "BLOCK": "BLOCK  ✗"}


def _render(v) -> str:
    L = [f"skillvet — {v.package}",
         "=" * 60,
         f"  verdict: {_BADGE.get(v.verdict, v.verdict)}    trust score: {v.score}/100",
         f"  {v.files_scanned} file(s) analyzed, {len(v.findings)} capability finding(s)"
         + (f", {v.content_matches} content signature match(es)" if v.content_matches else "")]
    if v.capabilities:
        L.append("  capabilities: " + ", ".join(v.capabilities))
    L.append("-" * 60)
    order = ["critical", "high", "medium", "low"]
    for f in sorted(v.findings, key=lambda x: order.index(x.severity) if x.severity in order else 9):
        rel = f.file.replace("\\", "/").split("/")[-1]
        L.append(f"  {_TAG.get(f.severity,'')} {f.capability:<18} {rel}:{f.line}  {f.why}")
    if not v.findings and not v.content_matches:
        L.append("  no risky capabilities detected — this package is inert.")
    L.append("-" * 60)
    if v.verdict == "BLOCK":
        L.append("  BLOCK: do not install without a manual review — this package can take actions")
        L.append("         (exec / exfiltrate / read credentials) that a skill should not need.")
    elif v.verdict == "REVIEW":
        L.append("  REVIEW: capable of more than a passive skill; read the flagged lines before trusting.")
    else:
        L.append("  TRUST: no dangerous capabilities found. Still your call, but nothing jumped out.")
    return "\n".join(L)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="skillvet",
        description="The trust gate for agent skills — vet a skill/MCP/plugin before you install it.")
    p.add_argument("--version", action="version", version=f"skillvet {__version__}")
    sub = p.add_subparsers(dest="cmd")
    pv = sub.add_parser("vet", help="analyze a package and return a verdict")
    pv.add_argument("path", help="package directory or file")
    pv.add_argument("--format", "-f", default="text", choices=["text", "json"])
    pv.add_argument("--no-content", action="store_true", help="skip the agentsigs content scan")
    pv.add_argument("--min", default="TRUST", choices=["TRUST", "REVIEW", "BLOCK"],
                    help="fail (nonzero) if verdict is worse than this gate")
    args = p.parse_args(argv)

    if args.cmd != "vet":
        p.print_help()
        return 0

    v = analyze(args.path, content_scan=not args.no_content)
    if args.format == "json":
        print(json.dumps({"package": v.package, "verdict": v.verdict, "score": v.score,
                          "capabilities": v.capabilities, "content_matches": v.content_matches,
                          "findings": [{"capability": f.capability, "severity": f.severity,
                                        "why": f.why, "file": f.file, "line": f.line, "atlas": f.atlas}
                                       for f in v.findings]}, indent=2))
    else:
        print(_render(v))
    return _EXIT.get(v.verdict, 0)


if __name__ == "__main__":
    raise SystemExit(main())
