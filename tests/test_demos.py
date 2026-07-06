"""The bundled demos are part of the contract — they must exist and run_all must exit 0."""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")
sys.path.insert(0, ROOT)

from skillvet.analyzer import analyze  # noqa: E402

EXPECTED = {
    "benign-skill": "TRUST",
    "malicious-skill": "BLOCK",
    "overbroad-manifest-skill": "REVIEW",
    "exfiltration-skill": "BLOCK",
}


@pytest.mark.parametrize("name,verdict", list(EXPECTED.items()))
def test_demo_verdicts(name, verdict):
    v = analyze(os.path.join(DEMOS, name), content_scan=False)
    assert v.verdict == verdict, f"{name}: expected {verdict}, got {v.verdict}"


def test_run_all_exits_zero():
    r = subprocess.run([sys.executable, os.path.join(DEMOS, "run_all.py")],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


def test_rugpull_demo_pair_exists():
    assert os.path.isdir(os.path.join(DEMOS, "rugpull", "v1-benign"))
    assert os.path.isdir(os.path.join(DEMOS, "rugpull", "v2-malicious"))


def test_demo_policies_valid():
    from skillvet.policy import Policy
    for pf in ("allow-network.json", "strict-no-exec.json"):
        p = Policy.load(os.path.join(DEMOS, "policies", pf))
        assert p.name
