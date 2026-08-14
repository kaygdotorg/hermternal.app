#!/usr/bin/env python3
"""Regression tests for the closed #406 v3 to #407 v2 boundary.

Only Git observations are mocked.  Evidence parsing, hashes, stable reads, and
the create-only plan/report writers use private temporary files for real.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("dev_update_v2", HERE / "dev_update_v2.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class DevUpdateV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.repository = self.root / "repository"
        self.repository.mkdir(mode=0o700)
        self.candidate, self.tree, self.source = "4" * 40, "5" * 40, "6" * 40
        self.remote_dev = MOD.BASE_DEV
        self.remote_main = MOD.PROTECTED_MAIN
        self.result = self.root / "replay-result.json"
        self.completion = self.root / "replay-completion.json"
        self.report = self.root / "offline-report.json"
        self.pin = self.root / "pin.json"
        self._write_inputs()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, path: Path, value: object) -> str:
        path.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.chmod(path, 0o600)
        return MOD.stable_read(path, path.name, mode=0o600).sha256

    def _write_inputs(self) -> None:
        result = {
            "schema": "task409-execution-preflight/replay-result/v2",
            "phase": "B-post-replay-detached-final-head", "lane": "candidate-4",
            "phase_a_manifest_sha256": "a" * 64, "phase_a_approval_digest": "b" * 64,
            "replay_root": "/private/replay-root", "replay_root_identity": {},
            "repository": str(self.repository), "repository_identity": {},
            "head_state": "detached", "final_head": self.candidate, "parent": "7" * 40,
            "tree": self.tree, "base_commit": MOD.BASE_DEV, "base_tree": MOD.BASE_DEV_TREE,
            "protected_main_commit": MOD.PROTECTED_MAIN, "required_ancestors": [MOD.BASE_DEV],
            "forbidden_ancestors": ["8" * 40],
        }
        result_sha = self._write(self.result, result)
        completion = {
            "schema": "hermternal.issue-397.replay-completion/v2", "completion_marker": "TASK409_RETAINED_REPLAY_OK=1",
            "stderr_policy": "empty", "returncode": 0, "result_path": str(self.result), "result_sha256": result_sha,
            "result_identity": {}, "pending_path": "/private/pending.json", "pending_sha256": "c" * 64,
            "pending_identity": {}, "driver_module_sha256": "d" * 64, "driver_source_sha256": "e" * 64,
            "markdown_sha256": "f" * 64, "json_sha256": "0" * 64, "shell_sha256": "1" * 64,
            "provenance_sha256": "2" * 64, "source_commit": self.source, "argv_sha256": "3" * 64,
            "argv_bytes": 1, "argv_count": 1, "stdin_sha256": "4" * 64, "stdin_bytes": 1,
            "stdout_sha256": "5" * 64, "stdout_bytes": 1, "stderr_sha256": "6" * 64,
            "stderr_bytes": 0, "phase_a_evidence_path": "/private/anchor.json", "phase_a_evidence_sha256": "7" * 64,
        }
        completion_sha = self._write(self.completion, completion)
        gates = [{"id": gate_id, "argv": ["podman", gate_id], "exit_code": 0, "stdout_sha256": "a" * 64, "stderr_sha256": "b" * 64, "stdout_bytes": 0, "stderr_bytes": 0} for gate_id in MOD.GATE_IDS]
        report = {
            "schema": MOD.OFFLINE_REPORT_SCHEMA, "status": "passed", "network": "not-used", "credentials": "not-used",
            "gate_list_sha256": "c" * 64, "repository": str(self.repository), "repository_identity": [1] * 8,
            "final_head": self.candidate, "final_tree": self.tree, "protected_main": MOD.PROTECTED_MAIN,
            "expected_dev_base": MOD.BASE_DEV, "dev_target": self.candidate,
            "inputs": {"result": {"path": str(self.result), "sha256": result_sha}, "completion": {"path": str(self.completion), "sha256": completion_sha}, "phase_a_anchor": {"path": "/private/anchor.json", "sha256": "d" * 64}, "provenance": {"path": "/private/provenance.json", "sha256": "e" * 64}},
            "semantic_evidence": {"checks": {"click": True, "enter": True, "clearing": True, "redaction": True, "accessibility": True, "privacy_policy": True, "screenshot_contract": True}, "sources": {label: {"path": f"/private/{label}", "sha256": "f" * 64, "identity": [1] * 8, "git_mode": "100644", "git_blob": "a" * 40} for label in ("auth", "privacy", "screenshots")}},
            "gates": gates,
        }
        report_sha = self._write(self.report, report)
        pin = {
            "schema": MOD.PIN_SCHEMA, "status": "final", "report": {"path": str(self.report), "sha256": report_sha, "schema": MOD.OFFLINE_REPORT_SCHEMA},
            "candidate": {"commit": self.candidate, "tree": self.tree, "source_commit": self.source},
            "chain": {"result": {"path": str(self.result), "sha256": result_sha}, "completion": {"path": str(self.completion), "sha256": completion_sha}},
        }
        self.pin.write_bytes((json.dumps(pin, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.chmod(self.pin, 0o644)

    def runner(self, argv, **_: object) -> subprocess.CompletedProcess[bytes]:
        args = tuple(argv[3:])
        values = {
            ("rev-parse", "--show-toplevel"): str(self.repository),
            ("rev-parse", "HEAD^{commit}"): self.candidate,
            ("rev-parse", f"{self.candidate}^{{commit}}"): self.candidate,
            ("rev-parse", f"{self.candidate}^{{tree}}"): self.tree,
            ("rev-parse", f"{self.source}^{{commit}}"): self.source,
            ("rev-parse", "refs/remotes/origin/dev^{commit}"): MOD.BASE_DEV,
            ("rev-parse", "refs/remotes/origin/dev^{tree}"): MOD.BASE_DEV_TREE,
            ("rev-parse", "refs/remotes/origin/main^{commit}"): MOD.PROTECTED_MAIN,
            ("status", "--porcelain=v1", "--untracked-files=all"): "",
            ("merge-base", "--is-ancestor", MOD.BASE_DEV, self.candidate): "",
            ("ls-remote", "--refs", "origin", "refs/heads/dev"): f"{self.remote_dev}\trefs/heads/dev",
            ("ls-remote", "--refs", "origin", "refs/heads/main"): f"{self.remote_main}\trefs/heads/main",
        }
        return subprocess.CompletedProcess(argv, 0, (values[args] + "\n").encode(), b"")

    def test_valid_report_yields_only_exact_non_force_plan_and_post_report(self) -> None:
        candidate = MOD.validate_offline_report(MOD.load_pin(self.pin))
        self.assertEqual(candidate.commit, self.candidate)
        plan = MOD.preflight(MOD.load_pin(self.pin), self.repository, self.runner)
        self.assertEqual(plan["push"]["argv"], ["/usr/bin/git", "push", "--porcelain", "origin", f"{self.candidate}:refs/heads/dev"])
        self.assertFalse(plan["push"]["executed"])
        path = self.root / "plan.json"
        snapshot = MOD.write_plan(path, plan)
        self.assertEqual(MOD.load_plan(path), snapshot)
        self.remote_dev = self.candidate
        report = MOD.verify_post_update(snapshot, self.repository, self.runner)
        report_path = self.root / "report.json"
        self.assertEqual(MOD.write_report(report_path, report).path, report_path)
        with self.assertRaises(MOD.Reject):
            MOD.write_plan(path, plan)

    def test_rejects_deferred_pin_old_schema_changed_report_and_bad_chain(self) -> None:
        deferred = json.loads(self.pin.read_text())
        deferred["status"] = "deferred"
        self.pin.write_text(json.dumps(deferred)); os.chmod(self.pin, 0o644)
        with self.assertRaisesRegex(MOD.Reject, "not final"):
            MOD.load_pin(self.pin)
        self._write_inputs()
        changed = json.loads(self.report.read_text())
        changed["schema"] = "hermternal.issue-397.offline-gates.v1"
        self._write(self.report, changed)
        with self.assertRaisesRegex(MOD.Reject, "SHA-256"):
            MOD.validate_offline_report(MOD.load_pin(self.pin))
        self._write_inputs()
        bad = json.loads(self.completion.read_text())
        bad["source_commit"] = "9" * 40
        self._write(self.completion, bad)
        with self.assertRaisesRegex(MOD.Reject, "SHA-256"):
            MOD.validate_offline_report(MOD.load_pin(self.pin))

    def test_no_plan_when_each_git_gate_or_remote_readback_fails(self) -> None:
        for failure in range(12):
            calls: list[tuple[str, ...]] = []
            def run(argv, **kwargs):
                calls.append(tuple(argv))
                result = self.runner(argv, **kwargs)
                if len(calls) - 1 == failure:
                    result.returncode = 1
                return result
            with self.subTest(failure=failure), self.assertRaises(MOD.Reject):
                MOD.preflight(MOD.load_pin(self.pin), self.repository, run)
            self.assertFalse(any("push" in call for call in calls))

    def test_rejects_changed_semantic_source_contract(self) -> None:
        cases = {
            "missing": lambda source: source.pop("git_blob"),
            "extra": lambda source: source.update({"unexpected": True}),
            "bad mode": lambda source: source.update({"git_mode": "100755"}),
            "bad OID": lambda source: source.update({"git_blob": "A" * 40}),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self._write_inputs()
                report = json.loads(self.report.read_text())
                mutate(report["semantic_evidence"]["sources"]["auth"])
                report_sha = self._write(self.report, report)
                pin = json.loads(self.pin.read_text())
                pin["report"]["sha256"] = report_sha
                self.pin.write_bytes((json.dumps(pin, sort_keys=True, separators=(",", ":")) + "\n").encode())
                os.chmod(self.pin, 0o644)
                with self.assertRaisesRegex(MOD.Reject, "semantic auth"):
                    MOD.validate_offline_report(MOD.load_pin(self.pin))

    def test_rejects_dirty_local_state_wrong_tree_and_post_main_change(self) -> None:
        def dirty(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if tuple(argv[3:]) == ("status", "--porcelain=v1", "--untracked-files=all"):
                result.stdout = b"?? unsafe\n"
            return result
        with self.assertRaisesRegex(MOD.Reject, "local candidate"):
            MOD.preflight(MOD.load_pin(self.pin), self.repository, dirty)
        plan = MOD.write_plan(self.root / "plan.json", MOD.preflight(MOD.load_pin(self.pin), self.repository, self.runner))
        self.remote_dev = self.candidate
        def moved_main(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if tuple(argv[3:]) == ("ls-remote", "--refs", "origin", "refs/heads/main"):
                result.stdout = ("f" * 40 + "\trefs/heads/main\n").encode()
            return result
        with self.assertRaisesRegex(MOD.Reject, "post-update"):
            MOD.verify_post_update(plan, self.repository, moved_main)


if __name__ == "__main__":
    unittest.main(verbosity=2)
