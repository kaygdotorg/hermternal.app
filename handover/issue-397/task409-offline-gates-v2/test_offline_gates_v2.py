#!/usr/bin/env python3
"""Offline tests: only Podman execution and local-image discovery are faked."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("offline_gates_v2", HERE / "offline_gates_v2.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MOD; SPEC.loader.exec_module(MOD)


class OfflineGatesV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name); os.chmod(self.root, 0o700)
        self.repository = self.root / "repository"; self.repository.mkdir(mode=0o700)
        files = {
            "apps/web/tests/e2e/ui-preview.spec.ts": "import AxeBuilder from 'axe'; test('native password activation clears live values', () => { if (activation === 'click') signIn.click(); if (activation === 'enter') password.press('Enter'); expect(x).toHaveValue(''); expect(y).toHaveValue(''); expect(z).toHaveValue(''); expect(q).toHaveValue(''); root.outerHTML; page.screenshot(); expect(value).not.toContain(passwordValue); expect(value).not.toContain(usernameValue); /* axe violations */ });\n",
            "apps/web/src/lib/live-artifact-policy.test.ts": "const LIVE_ARTIFACT_REDACTION = 'x'; const config = \"screenshot: 'off'\";\n",
            "apps/web/src/lib/live-screenshot-contract.test.ts": "blockedLiveScreenshotManifest({});\n",
        }
        for relative, content in files.items():
            path = self.repository / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content); os.chmod(path, 0o600)
        snap = lambda name: MOD.Snapshot(self.root / name, b"x", "a" * 64, (1, 2, 3, 0o600, 1, 1, 1, 1))
        self.chain = MOD.Chain(self.repository, "4" * 40, "5" * 40, "6" * 40, snap("result"), snap("completion"), snap("anchor"), snap("provenance"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def runner(self, argv, **_: object) -> subprocess.CompletedProcess[bytes]:
        gate = next(gate for gate in MOD.GATES if tuple(gate.command) == tuple(argv[-len(gate.command):]))
        output = {"git-head": self.chain.final_head, "git-tree": self.chain.final_tree, "git-main": self.chain.protected_main, "git-dev": self.chain.final_head, "git-clean": ""}.get(gate.gate_id, "PASS")
        return subprocess.CompletedProcess(argv, 0, (output + "\n").encode(), b"")

    def test_closed_podman_configuration_and_complete_semantic_report(self) -> None:
        argv = MOD.podman_argv(self.repository, MOD.GATES[0])
        self.assertIn("--pull=never", argv); self.assertIn("--network=none", argv)
        self.assertIn(MOD.IMAGE, argv); self.assertIn("--read-only", argv)
        self.assertNotIn("--privileged", argv); self.assertNotIn("--env-file", argv)
        records = MOD.run_gates(self.chain, self.runner, lambda image: image == MOD.IMAGE)
        self.assertEqual([item["id"] for item in records], [*(gate.gate_id for gate in MOD.GATES), "semantic-evidence"])
        self.assertTrue(all(records[-1]["evidence"]["checks"].values()))

    def test_absent_image_failure_and_gate_failure_reject(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "image"):
            MOD.run_gates(self.chain, self.runner, lambda _: False)
        def failed(argv, **kwargs):
            result = self.runner(argv, **kwargs); result.returncode = 1; return result
        with self.assertRaisesRegex(MOD.Reject, "git-head failed"):
            MOD.run_gates(self.chain, failed, lambda _: True)

    def test_semantic_evidence_rejects_missing_enter_or_redaction(self) -> None:
        source = self.repository / "apps/web/tests/e2e/ui-preview.spec.ts"
        source.write_text("activation === 'click'; signIn.click(); AxeBuilder; axe violations; toHaveValue(''); outerHTML; page.screenshot();\n")
        os.chmod(source, 0o600)
        with self.assertRaisesRegex(MOD.Reject, "semantic"):
            MOD.semantic_evidence(self.repository)

    def test_report_is_create_only_and_stably_read(self) -> None:
        report = self.root / "report.json"
        snapshot = MOD.write_report(report, self.chain, [{"id": "example"}])
        self.assertEqual(snapshot.path, report)
        with self.assertRaises(FileExistsError):
            MOD.write_report(report, self.chain, [])

    def test_strict_json_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "duplicate"):
            MOD.strict_json(b'{"a":1,"a":2}', "fixture")


if __name__ == "__main__":
    unittest.main(verbosity=2)
