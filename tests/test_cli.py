"""CLI behaviour tests for agent-perm-guard."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import unittest

from agent_perm_guard.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
RISKY_YAML = str(ROOT / "examples" / "risky_agent.yaml")
RISKY_JSON = str(ROOT / "examples" / "risky_agent.json")
SAFE_JSON = str(ROOT / "examples" / "safe_agent.json")


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_scan_yaml_json(self):
        code, out, _ = run(["scan", RISKY_YAML, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["manifests"], 1)
        self.assertGreaterEqual(payload["summary"]["counts"]["high"], 4)
        self.assertIn(payload["summary"]["max_grade"], ("D", "F"))

    def test_scan_multiple_manifests(self):
        code, out, _ = run(["scan", RISKY_YAML, RISKY_JSON, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["manifests"], 2)

    def test_gate_blocks_risky(self):
        code, _, err = run(["scan", RISKY_YAML, "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", err)

    def test_safe_passes(self):
        code, _, _ = run(["scan", SAFE_JSON, "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_report_prints_fixes(self):
        code, out, _ = run(["report", RISKY_YAML])
        self.assertEqual(code, 0)
        self.assertIn("least-privilege fixes:", out)

    def test_missing_path_exits_2(self):
        code, _, err = run(["scan", str(ROOT / "nope.yaml")])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_invalid_yaml_exits_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "bad.yaml"
            path.write_text("not a mapping\n", encoding="utf-8")
            code, _, err = run(["scan", str(path)])
            self.assertEqual(code, 2)
            self.assertIn("error", err)
