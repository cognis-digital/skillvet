"""Corpus-driven capability tests for skillvet's analyzer."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skillvet.analyzer import CHECKS, Finding, _scan_code, _scan_install_hooks, analyze  # noqa: E402
from corpus import (CAPABILITY_POSITIVES, BENIGN_SNIPPETS, INSTALL_HOOK_POSITIVES)  # noqa: E402

POS = [(cap, snip) for cap, snips in CAPABILITY_POSITIVES.items() for snip in snips]


@pytest.mark.parametrize("cap,snippet", POS)
def test_capability_detected(cap, snippet):
    out = []
    _scan_code(snippet, "x.py", out)
    caps = {f.capability for f in out}
    assert cap in caps, f"{cap} not detected in {snippet!r}; got {caps}"


@pytest.mark.parametrize("cap,snippet", POS)
def test_detected_capability_has_atlas(cap, snippet):
    out = []
    _scan_code(snippet, "x.py", out)
    for f in out:
        assert f.atlas.startswith("AML.T")


@pytest.mark.parametrize("snippet", BENIGN_SNIPPETS)
def test_benign_snippet_clean(snippet):
    out = []
    _scan_code(snippet, "x.py", out)
    assert out == [], f"false positive on benign snippet: {[f.capability for f in out]}"


@pytest.mark.parametrize("fname,content", INSTALL_HOOK_POSITIVES)
def test_install_hook_detected(fname, content):
    out = []
    _scan_install_hooks(fname, content, fname, out)
    assert any(f.capability == "install_hook" for f in out)


@pytest.mark.parametrize("cap", list(CHECKS))
def test_every_check_has_positive_coverage(cap):
    assert cap in CAPABILITY_POSITIVES, f"capability {cap} has no positive samples in the corpus"


class TestVerdictScenarios:
    def _pkg(self, tmp_path, files):
        for name, content in files.items():
            (tmp_path / name).write_text(content)
        return analyze(str(tmp_path), content_scan=False)

    def test_benign_package_trusts(self, tmp_path):
        v = self._pkg(tmp_path, {"skill.py": "def run(q):\n    return q.upper()",
                                 "SKILL.md": "# Upper\nUppercases text."})
        assert v.verdict == "TRUST"

    def test_network_only_reviews(self, tmp_path):
        v = self._pkg(tmp_path, {"skill.py": "import requests\ndef run(u):\n    return requests.get(u).text"})
        assert v.verdict in ("REVIEW", "BLOCK")

    def test_exec_package_blocks(self, tmp_path):
        v = self._pkg(tmp_path, {"skill.py": "import subprocess\ndef run(c):\n    subprocess.run(c, shell=True)"})
        assert v.verdict == "BLOCK"

    def test_credential_package_blocks(self, tmp_path):
        v = self._pkg(tmp_path, {"s.py": "k = open('/root/.ssh/id_rsa').read()"})
        assert v.verdict == "BLOCK"

    def test_score_monotonic(self, tmp_path):
        clean = self._pkg(tmp_path, {"a.py": "def f():\n    return 1"})
        assert clean.score == 100
