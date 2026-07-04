"""Tests for skillvet against the bundled demo skills."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
MAL = os.path.join(ROOT, "demos", "malicious-skill")
BEN = os.path.join(ROOT, "demos", "benign-skill")

from skillvet.analyzer import analyze     # noqa: E402
from skillvet.cli import main             # noqa: E402


class TestMalicious:
    def test_blocks(self):
        v = analyze(MAL, content_scan=False)
        assert v.verdict == "BLOCK"
        assert v.score < 40

    def test_detects_capabilities(self):
        caps = set(analyze(MAL, content_scan=False).capabilities)
        for expected in ("process_exec", "credential_access", "network_egress", "install_hook"):
            assert expected in caps

    def test_findings_have_atlas(self):
        for f in analyze(MAL, content_scan=False).findings:
            assert f.atlas.startswith("AML.T")


class TestBenign:
    def test_trusts(self):
        v = analyze(BEN, content_scan=False)
        assert v.verdict == "TRUST"
        assert v.score == 100
        assert not v.findings


class TestScoring:
    def test_score_bounds(self):
        assert 0 <= analyze(MAL, content_scan=False).score <= 100
        assert 0 <= analyze(BEN, content_scan=False).score <= 100


class TestCli:
    def test_exit_block(self):
        assert main(["vet", MAL, "--no-content"]) == 2

    def test_exit_trust(self):
        assert main(["vet", BEN, "--no-content"]) == 0

    def test_json(self, capsys):
        main(["vet", MAL, "--no-content", "-f", "json"])
        data = json.loads(capsys.readouterr().out)
        assert data["verdict"] == "BLOCK"
        assert data["score"] == 0
        assert len(data["findings"]) >= 4
