"""Manifest / permission-scope vetting tests."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from skillvet.analyzer import analyze                                   # noqa: E402
from skillvet.manifest import (parse_frontmatter, scan_manifests,       # noqa: E402
                               _declared_permissions)


class TestFrontmatter:
    def test_flat_keyvalue(self):
        fm = parse_frontmatter("---\nname: helper\nversion: 1.0\n---\nbody")
        assert fm["name"] == "helper"
        assert fm["version"] == "1.0"

    def test_inline_list(self):
        fm = parse_frontmatter("---\npermissions: [shell, network]\n---\n")
        assert fm["permissions"] == ["shell", "network"]

    def test_block_list(self):
        fm = parse_frontmatter("---\npermissions:\n  - shell\n  - network\n---\n")
        assert fm["permissions"] == ["shell", "network"]

    def test_no_frontmatter(self):
        assert parse_frontmatter("# just markdown\ntext") == {}

    def test_quotes_stripped(self):
        fm = parse_frontmatter("---\nname: 'quoted'\n---\n")
        assert fm["name"] == "quoted"


class TestDeclaredPermissions:
    def test_maps_scope_keywords(self):
        parsed = {"permissions": ["shell", "network", "credentials", "filesystem"]}
        caps = _declared_permissions(parsed)
        assert {"process_exec", "network_egress", "credential_access", "filesystem_write"} <= caps

    def test_ignores_non_permission_keys(self):
        # "network" appearing in a description field must NOT be treated as a declared scope.
        parsed = {"description": "connects to the network to fetch data"}
        assert _declared_permissions(parsed) == set()

    def test_empty(self):
        assert _declared_permissions({}) == set()


class TestScanManifests:
    def _write(self, tmp_path, name, content):
        (tmp_path / name).write_text(content, encoding="utf-8")

    def test_skill_md_overbroad(self, tmp_path):
        self._write(tmp_path, "SKILL.md",
                    "---\nname: x\npermissions:\n  - shell\n  - network\n---\n# X\n")
        self._write(tmp_path, "skill.py", "def run(q):\n    return q\n")
        findings = scan_manifests(str(tmp_path), used_capabilities=set())
        caps = {f.capability for f in findings}
        assert caps == {"manifest_overbroad"}
        whys = " ".join(f.why for f in findings)
        assert "process exec" in whys and "network egress" in whys

    def test_declared_but_unused_flagged(self, tmp_path):
        self._write(tmp_path, "SKILL.md",
                    "---\nname: x\npermissions: [shell]\n---\n")
        findings = scan_manifests(str(tmp_path), used_capabilities=set())
        assert any("does not appear to use" in f.why for f in findings)

    def test_declared_and_used_no_mismatch_note(self, tmp_path):
        self._write(tmp_path, "SKILL.md",
                    "---\nname: x\npermissions: [shell]\n---\n")
        findings = scan_manifests(str(tmp_path), used_capabilities={"process_exec"})
        # still surfaced (broad), but not tagged as unused
        assert findings
        assert all("does not appear to use" not in f.why for f in findings)

    def test_package_json_scopes(self, tmp_path):
        self._write(tmp_path, "package.json",
                    '{"name":"x","permissions":["network","filesystem"]}')
        findings = scan_manifests(str(tmp_path), used_capabilities=set())
        caps_whys = " ".join(f.why for f in findings)
        assert "network egress" in caps_whys
        assert "filesystem write" in caps_whys

    def test_mcp_command_surface(self, tmp_path):
        self._write(tmp_path, "mcp.json",
                    '{"mcpServers":{"s":{"command":"python","args":["srv.py"]}}}')
        findings = scan_manifests(str(tmp_path), used_capabilities=set())
        assert any("process exec" in f.why for f in findings)

    def test_clean_manifest_no_findings(self, tmp_path):
        self._write(tmp_path, "package.json", '{"name":"x","version":"1.0.0"}')
        self._write(tmp_path, "SKILL.md", "---\nname: x\n---\n# X\nClean.")
        assert scan_manifests(str(tmp_path), used_capabilities=set()) == []

    def test_malformed_json_no_crash(self, tmp_path):
        self._write(tmp_path, "package.json", "{not valid json")
        assert scan_manifests(str(tmp_path), used_capabilities=set()) == []


class TestManifestInAnalyze:
    def test_overbroad_appears_in_verdict(self, tmp_path):
        (tmp_path / "SKILL.md").write_text(
            "---\nname: x\npermissions: [shell, network, credentials]\n---\n", encoding="utf-8")
        (tmp_path / "skill.py").write_text("def run(q):\n    return q.strip()\n", encoding="utf-8")
        v = analyze(str(tmp_path), content_scan=False)
        assert "manifest_overbroad" in v.capabilities
        assert v.verdict in ("REVIEW", "BLOCK")

    def test_manifest_only_does_not_false_positive_benign(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name":"x","version":"1.0.0"}', encoding="utf-8")
        (tmp_path / "skill.py").write_text("def run(q):\n    return q\n", encoding="utf-8")
        v = analyze(str(tmp_path), content_scan=False)
        assert "manifest_overbroad" not in v.capabilities
        assert v.verdict == "TRUST"
