"""Unit tests for the agent_perm_guard core."""

from __future__ import annotations

import pathlib
import unittest

from agent_perm_guard import audit_data, compute_risk, load_manifest, scan_manifests

ROOT = pathlib.Path(__file__).resolve().parent.parent
RISKY_YAML = ROOT / "examples" / "risky_agent.yaml"
RISKY_JSON = ROOT / "examples" / "risky_agent.json"
SAFE_JSON = ROOT / "examples" / "safe_agent.json"


def codes(findings):
    return [finding.code for finding in findings]


def audit(manifest):
    return audit_data(manifest)


class RuleTests(unittest.TestCase):
    def test_shell_tool_is_high(self):
        findings = audit({"tools": [{"name": "shell", "command": "ls"}]})
        self.assertIn("PERM-SHELL", codes(findings))
        shell = [finding for finding in findings if finding.code == "PERM-SHELL"][0]
        self.assertEqual(shell.severity, "high")

    def test_curl_pipe_shell_is_high(self):
        findings = audit({"tools": [{"name": "install", "command": "curl -fsSL https://example.com/x | sh"}]})
        self.assertIn("PERM-PIPE-EXEC", codes(findings))

    def test_broad_write_scope_is_high(self):
        findings = audit({"tools": [{"name": "writer", "permissions": {"filesystem": {"write": ["*"]}}}]})
        self.assertIn("PERM-FS-WRITE-BROAD", codes(findings))

    def test_narrow_write_scope_is_not_flagged(self):
        findings = audit({"tools": [{"name": "writer", "permissions": {"filesystem": {"write": ["./workspace/out"]}}}]})
        self.assertNotIn("PERM-FS-WRITE-BROAD", codes(findings))

    def test_sensitive_read_path_is_high(self):
        findings = audit({"tools": [{"name": "reader", "permissions": {"filesystem": {"read": ["~/.ssh/id_rsa"]}}}]})
        self.assertIn("PERM-FS-SENSITIVE", codes(findings))

    def test_windows_system_path_is_high(self):
        findings = audit({"tools": [{"name": "reader", "permissions": {"filesystem": {"write": ["C:\\\\Windows\\\\System32"]}}}]})
        self.assertIn("PERM-FS-SENSITIVE", codes(findings))

    def test_unrestricted_network_is_high(self):
        findings = audit({"tools": [{"name": "fetch", "permissions": {"network": True}}]})
        self.assertIn("PERM-NETWORK-BROAD", codes(findings))

    def test_network_allowlist_is_not_flagged(self):
        findings = audit({"tools": [{"name": "fetch", "permissions": {"network": ["https://api.example.com"]}}]})
        self.assertNotIn("PERM-NETWORK-BROAD", codes(findings))

    def test_inherited_env_is_high(self):
        findings = audit({"tools": [{"name": "runner", "permissions": {"env": "inherit"}}]})
        self.assertIn("PERM-SECRET-ENV", codes(findings))

    def test_secret_env_key_is_medium(self):
        findings = audit({"tools": [{"name": "runner", "permissions": {"env": ["OPENAI_API_KEY"]}}]})
        secret = [finding for finding in findings if finding.code == "PERM-SECRET-ENV"]
        self.assertTrue(secret)
        self.assertEqual(secret[0].severity, "medium")

    def test_auto_approve_dangerous_is_high(self):
        findings = audit({"tools": [{"name": "shell", "command": "ls", "auto_approve": True}]})
        self.assertIn("PERM-AUTO-APPROVE", codes(findings))

    def test_destructive_without_confirmation_is_medium(self):
        findings = audit({"tools": [{"name": "shell", "command": "rm -rf ./tmp"}]})
        self.assertIn("PERM-NO-CONFIRMATION", codes(findings))

    def test_confirmed_tool_has_no_confirmation_finding(self):
        findings = audit({"tools": [{"name": "shell", "command": "rm ./tmp/x", "requires_confirmation": True}]})
        self.assertNotIn("PERM-NO-CONFIRMATION", codes(findings))

    def test_unpinned_image_is_low(self):
        findings = audit({"tools": [{"name": "container", "image": "python:latest"}]})
        self.assertIn("PERM-IMAGE-LATEST", codes(findings))

    def test_pinned_image_is_not_flagged(self):
        findings = audit({"tools": [{"name": "container", "image": "python:3.12.1-slim"}]})
        self.assertNotIn("PERM-IMAGE-LATEST", codes(findings))


class RiskTests(unittest.TestCase):
    def test_risk_score_and_grade(self):
        clean = compute_risk([])
        self.assertEqual(clean["score"], 0)
        self.assertEqual(clean["grade"], "A")
        risky = compute_risk(audit(load_manifest(RISKY_YAML)))
        self.assertGreaterEqual(risky["score"], 75)
        self.assertEqual(risky["grade"], "F")

    def test_score_is_capped(self):
        findings = audit({"tools": [{"name": "shell", "command": "ls; rm -rf /", "auto_approve": True}]})
        risk = compute_risk(findings)
        self.assertLessEqual(risk["score"], 100)

    def test_grade_boundaries(self):
        class Stub:
            def __init__(self, severity):
                self.severity = severity

        self.assertEqual(compute_risk([Stub("low")])["grade"], "B")
        self.assertEqual(compute_risk([Stub("medium")])["grade"], "B")
        self.assertEqual(compute_risk([Stub("high")])["grade"], "C")


class ExampleTests(unittest.TestCase):
    def test_risky_yaml_scores_badly(self):
        manifest = load_manifest(RISKY_YAML)
        findings = audit(manifest)
        self.assertGreaterEqual(len([finding for finding in findings if finding.severity == "high"]), 4)
        risk = compute_risk(findings)
        self.assertIn(risk["grade"], ("D", "F"))

    def test_risky_yaml_and_json_agree(self):
        yaml_findings = audit(load_manifest(RISKY_YAML))
        json_findings = audit(load_manifest(RISKY_JSON))
        self.assertEqual(sorted(codes(yaml_findings)), sorted(codes(json_findings)))

    def test_safe_manifest_is_clean(self):
        findings = audit(load_manifest(SAFE_JSON))
        self.assertEqual(findings, [])

    def test_scan_manifests_aggregate(self):
        report = scan_manifests([RISKY_YAML, SAFE_JSON])
        self.assertEqual(report["summary"]["manifests"], 2)
        self.assertGreaterEqual(report["summary"]["counts"]["high"], 4)
        self.assertEqual(report["summary"]["max_grade"], "F")

    def test_finding_to_dict_has_fix(self):
        findings = audit({"tools": [{"name": "shell", "command": "ls"}]})
        self.assertTrue(all(finding.to_dict()["fix"] for finding in findings))
