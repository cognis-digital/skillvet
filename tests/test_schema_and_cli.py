"""JSON schemas parse, and the CLI surface (help, subcommands, errors) behaves."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from skillvet.cli import main  # noqa: E402

SCHEMA = os.path.join(ROOT, "schema")
BEN = os.path.join(ROOT, "demos", "benign-skill")
MAL = os.path.join(ROOT, "demos", "malicious-skill")


class TestSchemas:
    @pytest.mark.parametrize("name", ["policy.schema.json", "baseline.schema.json"])
    def test_schema_is_valid_json(self, name):
        with open(os.path.join(SCHEMA, name), encoding="utf-8") as fh:
            doc = json.load(fh)
        assert doc["$schema"].startswith("https://json-schema.org")
        assert doc["type"] == "object"

    def test_baseline_matches_schema_shape(self, tmp_path):
        from skillvet import baseline as bl
        (tmp_path / "s.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        b = bl.record(str(tmp_path), content_scan=False)
        with open(os.path.join(SCHEMA, "baseline.schema.json"), encoding="utf-8") as fh:
            schema = json.load(fh)
        for key in schema["required"]:
            assert key in b


class TestCliSurface:
    def test_no_command_prints_help(self, capsys):
        assert main([]) == 0
        assert "trust gate" in capsys.readouterr().out.lower()

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as e:
            main(["--version"])
        assert e.value.code == 0

    def test_vet_json_has_policy_field(self, capsys):
        main(["vet", BEN, "--no-content", "-f", "json"])
        data = json.loads(capsys.readouterr().out)
        assert data["policy"] == "default"

    def test_bad_policy_exits_3(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(SystemExit) as e:
            main(["vet", BEN, "--no-content", "--policy", str(bad)])
        assert e.value.code == 3

    def test_vet_with_policy_file(self, tmp_path):
        pol = tmp_path / "p.json"
        pol.write_text(json.dumps({"name": "x", "deny": ["credential_access"]}), encoding="utf-8")
        # malicious has credential_access -> deny forces BLOCK -> exit 2
        assert main(["vet", MAL, "--no-content", "--policy", str(pol)]) == 2

    def test_every_capability_covered_in_json(self, capsys):
        main(["vet", MAL, "--no-content", "-f", "json"])
        data = json.loads(capsys.readouterr().out)
        caps = {f["capability"] for f in data["findings"]}
        assert {"process_exec", "credential_access", "network_egress"} <= caps
