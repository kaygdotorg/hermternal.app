#!/usr/bin/env python3
"""Fail-closed tests for the offline post-replay gate successor."""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("offline_gates", HERE / "offline_gates.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MOD; SPEC.loader.exec_module(MOD)


class OfflineGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        root = Path(self.temp.name); os.chmod(root, 0o700)
        repository = root / "repository"; repository.mkdir(mode=0o700)
        source = repository / "apps/web/tests/e2e/ui-preview.spec.ts"; source.parent.mkdir(parents=True)
        source.write_text("for (const activation of ['click','enter']) { axe; toHaveAccessibleName; await expect(x).toHaveValue(''); await expect(y).toHaveValue(''); outerHTML; page.screenshot; usernameValue; expect(usernameValue).not.toContain(); }\n")
        os.chmod(source, 0o600)
        self.authority = MOD.Authority("1" * 40, "2" * 40, "3" * 40, "4" * 40, "5" * 40, root, repository)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def runner(self, argv, **kwargs):
        gate = next(item for item in MOD.GATES if item.argv == tuple(argv))
        values = {"git-head": self.authority.final_head, "git-tree": self.authority.final_tree, "git-main-unchanged": MOD.MAIN_COMMIT, "git-dev-target": self.authority.final_head, "git-clean": ""}
        return subprocess.CompletedProcess(argv, 0, (values.get(gate.gate_id, "PASS") + "\n").encode(), b"")

    def test_complete_summary_and_exact_environment(self) -> None:
        calls = []
        def run(argv, **kwargs):
            calls.append((tuple(argv), kwargs)); return self.runner(argv, **kwargs)
        report = MOD.run_gates(self.authority, run)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["final_tree"], self.authority.final_tree)
        self.assertEqual(len(report["gates"]), len(MOD.GATES))
        self.assertEqual(len(calls), len(MOD.GATES) - 1)
        self.assertTrue(all(call[1]["env"] == MOD.SAFE_ENV for call in calls))

    def test_failure_unavailable_and_network_output_reject(self) -> None:
        def failed(argv, **kwargs): return subprocess.CompletedProcess(argv, 1, b"", b"failed")
        with self.assertRaisesRegex(MOD.Reject, "failed or was unavailable"):
            MOD.run_gates(self.authority, failed)
        def network(argv, **kwargs): return subprocess.CompletedProcess(argv, 0, b"fetching https://registry.example\n", b"")
        with self.assertRaisesRegex(MOD.Reject, "network indicator"):
            MOD.run_gates(self.authority, network)
        def unavailable(argv, **kwargs): raise FileNotFoundError("missing")
        with self.assertRaisesRegex(MOD.Reject, "unavailable"):
            MOD.run_gates(self.authority, unavailable)

    def test_skip_and_main_or_dev_substitution_reject(self) -> None:
        gates = MOD.GATES[:-1]
        with mock.patch.object(MOD, "GATES", gates), self.assertRaisesRegex(MOD.Reject, "skipped"):
            MOD.run_gates(self.authority, self.runner)
        def wrong_main(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if tuple(argv) == MOD.GATES[2].argv: result.stdout = ("f" * 40 + "\n").encode()
            return result
        with self.assertRaisesRegex(MOD.Reject, "main-unchanged"):
            MOD.run_gates(self.authority, wrong_main)

    def test_auth_hook_rejects_missing_enter_and_redaction(self) -> None:
        source = self.authority.repository / "apps/web/tests/e2e/ui-preview.spec.ts"
        source.write_text("'click'; axe; toHaveAccessibleName;\n"); os.chmod(source, 0o600)
        with self.assertRaisesRegex(MOD.Reject, "authentication source hook"):
            MOD.run_gates(self.authority, self.runner)

    def test_closed_input_schemas_and_complete_interlock(self) -> None:
        provenance = {"schema": MOD.PROVENANCE_SCHEMA, "issue": 397, "candidate": "five", "generation": {}, "repository_boundary": {"integrated_commit": "1"*40, "integrated_tree": "2"*40, "base_commit": MOD.BASE_COMMIT, "base_tree": "6"*40, "protected_main_commit": MOD.MAIN_COMMIT, "source_commit": "3"*40}, "dependencies": [], "source_inputs": [], "outputs": {}, "cross_format_authority": {}, "publication": {}, "safety_claims": {}}
        p_raw = (json.dumps(provenance) + "\n").encode()
        interlock = {"schema": MOD.INTERLOCK_SCHEMA, "state": "phase-b", "authority_provenance_sha256": MOD.hashlib.sha256(p_raw).hexdigest(), "integrated_commit": "1"*40, "integrated_tree": "2"*40, "source_commit": "3"*40, "base_commit": MOD.BASE_COMMIT, "base_tree": "6"*40, "protected_main_commit": MOD.MAIN_COMMIT, "runtime_parent": "/private/tmp/runtime", "replay_root": str(self.authority.replay_root), "events": [{"stage": "phase-a", "status": "PASS"}, {"stage": "anchor", "status": "PASS"}, {"stage": "replay", "status": "PASS", "evidence": {"repository": str(self.authority.repository), "final_head": "4"*40, "final_tree": "5"*40}}, {"stage": "phase-b", "status": "PASS", "evidence": {"execution": "not-run", "mutation": "not-run", "network": "not-used"}}], "tip_event_sha256": "a"*64}
        authority = MOD.validate_inputs(p_raw, json.dumps(interlock).encode())
        self.assertEqual(authority.final_head, "4"*40)
        provenance["extra"] = True
        with self.assertRaisesRegex(MOD.Reject, "schema"):
            MOD.validate_inputs(json.dumps(provenance).encode(), json.dumps(interlock).encode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
