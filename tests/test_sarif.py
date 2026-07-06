"""SARIF 2.1.0 output validity tests."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from skillvet.analyzer import analyze, ALL_CAPABILITIES  # noqa: E402
from skillvet.sarif import to_sarif, _RULE_HELP          # noqa: E402
from skillvet.cli import main                            # noqa: E402

MAL = os.path.join(ROOT, "demos", "malicious-skill")
BEN = os.path.join(ROOT, "demos", "benign-skill")


def _sarif(path):
    return to_sarif(analyze(path, content_scan=False))


class TestSarifStructure:
    def test_top_level_fields(self):
        s = _sarif(MAL)
        assert s["version"] == "2.1.0"
        assert s["$schema"].endswith("sarif-schema-2.1.0.json")
        assert isinstance(s["runs"], list) and len(s["runs"]) == 1

    def test_driver_metadata(self):
        driver = _sarif(MAL)["runs"][0]["tool"]["driver"]
        assert driver["name"] == "skillvet"
        assert "version" in driver
        assert driver["informationUri"].startswith("https://")

    def test_one_rule_per_capability(self):
        rules = _sarif(BEN)["runs"][0]["tool"]["driver"]["rules"]
        ids = {r["id"] for r in rules}
        assert ids == set(ALL_CAPABILITIES)
        assert len(rules) == len(ALL_CAPABILITIES)

    def test_rules_have_help_and_severity(self):
        for r in _sarif(MAL)["runs"][0]["tool"]["driver"]["rules"]:
            assert r["help"]["text"]
            assert r["fullDescription"]["text"]
            assert r["defaultConfiguration"]["level"] in ("error", "warning", "note")
            assert "security-severity" in r["properties"]

    def test_rule_ids_are_capabilities(self):
        for cap in ALL_CAPABILITIES:
            assert cap in _RULE_HELP, f"no SARIF help text for capability {cap}"


class TestSarifResults:
    def test_result_per_finding(self):
        v = analyze(MAL, content_scan=False)
        s = to_sarif(v)
        results = s["runs"][0]["results"]
        assert len(results) == len(v.findings)

    def test_results_reference_declared_rules(self):
        s = _sarif(MAL)
        rule_ids = {r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]}
        for res in s["runs"][0]["results"]:
            assert res["ruleId"] in rule_ids
            assert res["level"] in ("error", "warning", "note")
            assert res["message"]["text"]
            loc = res["locations"][0]["physicalLocation"]
            assert loc["artifactLocation"]["uri"]
            assert loc["region"]["startLine"] >= 1

    def test_uri_has_no_backslashes(self):
        for res in _sarif(MAL)["runs"][0]["results"]:
            uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert "\\" not in uri

    def test_atlas_tags_in_rule_properties(self):
        rules = {r["id"]: r for r in _sarif(MAL)["runs"][0]["tool"]["driver"]["rules"]}
        tags = rules["process_exec"]["properties"]["tags"]
        assert any(t.startswith("ATLAS/AML.T") for t in tags)

    def test_benign_has_zero_results(self):
        assert _sarif(BEN)["runs"][0]["results"] == []

    def test_run_properties_carry_verdict(self):
        props = _sarif(MAL)["runs"][0]["properties"]
        assert props["skillvet.verdict"] == "BLOCK"
        assert props["skillvet.score"] == 0
        assert "process_exec" in props["skillvet.capabilities"]


class TestSarifCli:
    def test_cli_emits_valid_json_sarif(self, capsys):
        import json
        main(["vet", MAL, "--no-content", "-f", "sarif"])
        out = capsys.readouterr().out
        s = json.loads(out)
        assert s["version"] == "2.1.0"
        assert s["runs"][0]["tool"]["driver"]["name"] == "skillvet"

    def test_cli_sarif_exit_code_matches_verdict(self):
        # sarif format still gates: malicious -> BLOCK -> exit 2
        assert main(["vet", MAL, "--no-content", "-f", "sarif"]) == 2
        assert main(["vet", BEN, "--no-content", "-f", "sarif"]) == 0
