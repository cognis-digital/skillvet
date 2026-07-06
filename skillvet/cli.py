"""skillvet command line — the trust gate.

    skillvet vet PATH                 analyze a skill/MCP/plugin package -> trust score + verdict
    skillvet vet PATH -f json         machine-readable
    skillvet vet PATH -f sarif        SARIF 2.1.0 for CI code-scanning
    skillvet vet PATH --policy p.json tune weights/thresholds/allow-deny
    skillvet vet PATH --baseline b.json   also diff against a recorded baseline (rug-pull check)
    skillvet baseline PATH -o b.json  record a fingerprint of a package you've reviewed
    skillvet diff b.json PATH         compare an update against a baseline -> what changed

Exit codes (CI / pre-install gate): 0 = TRUST, 1 = REVIEW, 2 = BLOCK.
`diff` exits 2 when it detects a rug-pull (new dangerous capability), 1 on any change, 0 if clean.
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
from .policy import Policy
from . import baseline as _baseline
from .sarif import to_sarif

_TAG = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}
_EXIT = {"TRUST": 0, "REVIEW": 1, "BLOCK": 2}
_BADGE = {"TRUST": "TRUST  ✓", "REVIEW": "REVIEW ⚠", "BLOCK": "BLOCK  ✗"}


def _load_policy(path: Optional[str]) -> Policy:
    if not path:
        return Policy()
    try:
        return Policy.load(path)
    except Exception as e:
        print(f"skillvet: could not load policy {path!r}: {e}", file=sys.stderr)
        raise SystemExit(3)


def _render(v) -> str:
    L = [f"skillvet — {v.package}",
         "=" * 60,
         f"  verdict: {_BADGE.get(v.verdict, v.verdict)}    trust score: {v.score}/100",
         f"  {v.files_scanned} file(s) analyzed, {len(v.findings)} capability finding(s)"
         + (f", {v.content_matches} content signature match(es)" if v.content_matches else "")]
    if v.policy and v.policy.name not in ("default",):
        L.append(f"  policy: {v.policy.name}")
    if v.capabilities:
        L.append("  capabilities: " + ", ".join(v.capabilities))
    L.append("-" * 60)
    order = ["critical", "high", "medium", "low"]
    for f in sorted(v.findings, key=lambda x: order.index(x.severity) if x.severity in order else 9):
        rel = f.file.replace("\\", "/").split("/")[-1]
        loc = f"{rel}:{f.line}" if f.line and f.line > 0 else rel
        L.append(f"  {_TAG.get(f.severity,'')} {f.capability:<20} {loc}  {f.why}")
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


def _verdict_json(v) -> dict:
    return {"package": v.package, "verdict": v.verdict, "score": v.score,
            "capabilities": v.capabilities, "content_matches": v.content_matches,
            "policy": v.policy.name,
            "findings": [{"capability": f.capability, "severity": f.severity,
                          "why": f.why, "file": f.file, "line": f.line, "atlas": f.atlas}
                         for f in v.findings]}


def _render_diff(d) -> str:
    L = [f"skillvet diff — {d.package}",
         "=" * 60,
         f"  score: {d.old_score} -> {d.new_score}"]
    if not d.integrity_ok:
        L.append("  ! baseline integrity check FAILED — the baseline file was modified.")
    if d.is_rugpull:
        L.append(f"  RUG-PULL: new dangerous capabilities appeared: {', '.join(d.new_dangerous)}")
    elif not d.changed:
        L.append("  no changes since baseline — package is identical.")
    L.append("-" * 60)
    if d.new_capabilities:
        L.append("  + new capabilities:     " + ", ".join(d.new_capabilities))
    if d.removed_capabilities:
        L.append("  - removed capabilities: " + ", ".join(d.removed_capabilities))
    for label, items in (("added", d.files_added), ("removed", d.files_removed),
                         ("changed", d.files_changed)):
        for f in items:
            L.append(f"  file {label}: {f}")
    L.append("-" * 60)
    if d.is_rugpull:
        L.append("  BLOCK this update: it gained capabilities it did not have when you trusted it.")
    elif d.changed:
        L.append("  REVIEW: the package changed since baseline; confirm the diff is expected.")
    else:
        L.append("  TRUST: unchanged since the baseline you recorded.")
    return "\n".join(L)


def _cmd_vet(args) -> int:
    policy = _load_policy(args.policy)
    v = analyze(args.path, content_scan=not args.no_content, policy=policy)
    fmt = args.format
    if fmt == "json":
        print(json.dumps(_verdict_json(v), indent=2))
    elif fmt == "sarif":
        print(json.dumps(to_sarif(v), indent=2))
    else:
        print(_render(v))
    # Optional baseline diff on top of the vet (rug-pull check in one command).
    if args.baseline:
        bl = _baseline.load(args.baseline)
        d = _baseline.diff(bl, args.path, content_scan=not args.no_content, policy=policy)
        if fmt in ("text",):
            print()
            print(_render_diff(d))
        if d.is_rugpull:
            return 2
    return _EXIT.get(v.verdict, 0)


def _cmd_baseline(args) -> int:
    policy = _load_policy(args.policy)
    bl = _baseline.record(args.path, content_scan=not args.no_content, policy=policy)
    _baseline.save(bl, args.output)
    print(f"skillvet: recorded baseline for {bl['package']} "
          f"(score {bl['score']}, {len(bl['files'])} file(s), "
          f"{len(bl['capabilities'])} capability(ies)) -> {args.output}")
    return 0


def _cmd_diff(args) -> int:
    policy = _load_policy(args.policy)
    bl = _baseline.load(args.baseline)
    d = _baseline.diff(bl, args.path, content_scan=not args.no_content, policy=policy)
    if args.format == "json":
        print(json.dumps(_baseline.diff_to_dict(d), indent=2))
    else:
        print(_render_diff(d))
    if d.is_rugpull:
        return 2
    return 1 if d.changed else 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="skillvet",
        description="The trust gate for agent skills — vet a skill/MCP/plugin before you install it.")
    p.add_argument("--version", action="version", version=f"skillvet {__version__}")
    sub = p.add_subparsers(dest="cmd")

    pv = sub.add_parser("vet", help="analyze a package and return a verdict")
    pv.add_argument("path", help="package directory or file")
    pv.add_argument("--format", "-f", default="text", choices=["text", "json", "sarif"])
    pv.add_argument("--no-content", action="store_true", help="skip the agentsigs content scan")
    pv.add_argument("--policy", help="policy JSON: tune weights/thresholds/allow-deny")
    pv.add_argument("--baseline", help="also diff against this baseline JSON (rug-pull check)")
    pv.add_argument("--min", default="TRUST", choices=["TRUST", "REVIEW", "BLOCK"],
                    help="fail (nonzero) if verdict is worse than this gate")

    pb = sub.add_parser("baseline", help="record a fingerprint of a reviewed package")
    pb.add_argument("path", help="package directory or file")
    pb.add_argument("--output", "-o", required=True, help="baseline JSON output path")
    pb.add_argument("--no-content", action="store_true")
    pb.add_argument("--policy", help="policy JSON")

    pd = sub.add_parser("diff", help="compare an update against a baseline (rug-pull check)")
    pd.add_argument("baseline", help="baseline JSON recorded earlier")
    pd.add_argument("path", help="package directory or file (the update)")
    pd.add_argument("--format", "-f", default="text", choices=["text", "json"])
    pd.add_argument("--no-content", action="store_true")
    pd.add_argument("--policy", help="policy JSON")

    args = p.parse_args(argv)

    if args.cmd == "vet":
        return _cmd_vet(args)
    if args.cmd == "baseline":
        return _cmd_baseline(args)
    if args.cmd == "diff":
        return _cmd_diff(args)
    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
