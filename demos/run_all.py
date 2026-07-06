#!/usr/bin/env python3
"""Run every skillvet demo offline and assert the expected outcome. Exits 0 iff all pass.

This is the living proof for the README's "See it work" blocks: every scenario here is real,
reproducible, and offline. skillvet never executes any demo package — it only reads it.

    python demos/run_all.py
"""
from __future__ import annotations
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from skillvet.analyzer import analyze          # noqa: E402
from skillvet.policy import Policy             # noqa: E402
from skillvet import baseline as bl            # noqa: E402
from skillvet.sarif import to_sarif            # noqa: E402

D = lambda *p: os.path.join(HERE, *p)          # noqa: E731
_OK, _FAIL = 0, 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global _OK, _FAIL
    mark = "PASS" if cond else "FAIL"
    if cond:
        _OK += 1
    else:
        _FAIL += 1
    print(f"  [{mark}] {label}" + (f"  ({detail})" if detail else ""))


def hr(title: str) -> None:
    print("\n" + title)
    print("-" * 66)


def main() -> int:
    hr("1. benign skill -> TRUST")
    v = analyze(D("benign-skill"), content_scan=False)
    check("verdict TRUST", v.verdict == "TRUST", f"score {v.score}")
    check("no findings", not v.findings)

    hr("2. malicious skill -> BLOCK (exec + exfil + install hook)")
    v = analyze(D("malicious-skill"), content_scan=False)
    check("verdict BLOCK", v.verdict == "BLOCK", f"score {v.score}")
    for cap in ("process_exec", "credential_access", "network_egress",
                "install_hook", "obfuscation", "exfiltration_surface"):
        check(f"detects {cap}", cap in v.capabilities)

    hr("3. over-broad manifest -> flagged (declared-vs-used mismatch)")
    v = analyze(D("overbroad-manifest-skill"), content_scan=False)
    check("manifest_overbroad present", "manifest_overbroad" in v.capabilities)
    check("verdict at least REVIEW", v.verdict in ("REVIEW", "BLOCK"), v.verdict)
    check("flags unused exec scope",
          any("does not appear to use" in f.why for f in v.findings))

    hr("4. exfiltration surface -> credential_access + network_egress correlated")
    v = analyze(D("exfiltration-skill"), content_scan=False)
    check("exfiltration_surface present", "exfiltration_surface" in v.capabilities)
    check("verdict BLOCK", v.verdict == "BLOCK", f"score {v.score}")

    hr("5. MCP server manifest -> declared exec surface from mcp.json")
    v = analyze(D("mcp-server-skill"), content_scan=False)
    check("manifest_overbroad from command", "manifest_overbroad" in v.capabilities)
    check("exec surface noted", any("process exec" in f.why for f in v.findings))

    hr("6. rug-pull -> baseline v1 (benign), diff v2 (update) flags new capabilities")
    with tempfile.TemporaryDirectory() as td:
        base = bl.record(D("rugpull", "v1-benign"), content_scan=False)
        blpath = os.path.join(td, "baseline.json")
        bl.save(base, blpath)
        check("v1 baseline is TRUST", base["verdict"] == "TRUST", f"score {base['score']}")
        check("baseline integrity ok", bl.verify_integrity(bl.load(blpath)))
        d = bl.diff(bl.load(blpath), D("rugpull", "v2-malicious"), content_scan=False)
        check("rug-pull detected", d.is_rugpull, f"new: {', '.join(d.new_dangerous)}")
        for cap in ("process_exec", "credential_access", "network_egress"):
            check(f"new capability {cap}", cap in d.new_capabilities)
        check("score dropped", d.new_score < d.old_score, f"{d.old_score} -> {d.new_score}")

    hr("7. SARIF 2.1.0 export -> valid structure for CI code-scanning")
    s = to_sarif(analyze(D("malicious-skill"), content_scan=False))
    check("version 2.1.0", s["version"] == "2.1.0")
    check("one rule per capability", len(s["runs"][0]["tool"]["driver"]["rules"]) >= 7)
    check("results emitted", len(s["runs"][0]["results"]) >= 6)

    hr("8. policy tuning -> allow network turns a REVIEW into TRUST")
    net = analyze(D("benign-skill"), content_scan=False)  # sanity baseline
    pol = Policy.load(D("policies", "allow-network.json"))
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "skill.py")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("import requests\ndef run(u):\n    return requests.get(u).text\n")
        default = analyze(td, content_scan=False)
        allowed = analyze(td, content_scan=False, policy=pol)
        check("default verdict REVIEW", default.verdict == "REVIEW", default.verdict)
        check("allow-network verdict TRUST", allowed.verdict == "TRUST", allowed.verdict)

    print("\n" + "=" * 66)
    total = _OK + _FAIL
    print(f"  {_OK}/{total} checks passed")
    if _FAIL:
        print(f"  {_FAIL} FAILED")
        return 1
    print("  all demos passed — skillvet is working as documented.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
