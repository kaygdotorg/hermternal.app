#!/usr/bin/env python3
"""Unit tests for retained replay-result creation; no driver or Git is executed."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("replay_result_successor", HERE / "replay_result_successor.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)
S64 = "a" * 64
O40 = "1" * 40


class ReplayResultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_parent = Path(self.tmp.name).resolve() / "run"
        self.run_parent.mkdir(mode=0o700)
        self.replay_root = self.run_parent / "replay-root"; self.replay_root.mkdir(mode=0o700)
        self.repository = self.run_parent / "repository"; self.repository.mkdir(mode=0o700)
        self.contract = MOD.DriverContract(("/usr/bin/env", "-i", "/bin/bash", "-s"), b"#!/bin/bash\n", S64, S64, S64, MOD.hashlib.sha256(b"#!/bin/bash\n").hexdigest(), "b" * 64)
        self.facts = MOD.ReplayFacts(S64, "b" * 64, O40, "2" * 40, "3" * 40, "4" * 40, "5" * 40, "6" * 40, "9" * 40, ("7" * 40,), ("8" * 40,))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def command(self):
        return MOD.invoke_driver(self.contract, lambda argv, stdin: MOD.ProcessResult(0, b"before\nreplay-complete-retained\n", b""))

    def publish(self):
        return MOD.publish_retained_result(self.run_parent, self.replay_root, self.repository, self.facts, self.contract, lambda argv, stdin: MOD.ProcessResult(0, b"before\nreplay-complete-retained\n", b""))

    def test_success_retains_exact_result_and_completion(self) -> None:
        published = self.publish()
        self.assertTrue(published.result.path.exists()); self.assertTrue(published.completion.path.exists())
        self.assertTrue(self.replay_root.exists()); self.assertTrue(self.repository.exists())
        result = json.loads(published.result.raw)
        self.assertEqual(set(result), MOD.RESULT_KEYS)
        self.assertEqual(result["repository"], str(self.repository))
        completion = json.loads(published.completion.raw)
        self.assertEqual(set(completion), MOD.COMPLETION_KEYS)
        self.assertEqual(completion["result_sha256"], published.result.sha256)
        self.assertEqual(completion["source_commit"], "9" * 40)

    def test_failure_creates_no_false_result(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "did not succeed"):
            MOD.publish_retained_result(self.run_parent, self.replay_root, self.repository, self.facts, self.contract, lambda argv, stdin: MOD.ProcessResult(7, b"", b"failed"))
        self.assertFalse((self.replay_root / MOD.RESULT_NAME).exists())
        self.assertFalse((self.replay_root / MOD.COMPLETION_NAME).exists())

    def test_process_double_receives_only_authenticated_argv_and_stdin(self) -> None:
        calls = []
        def observe(argv, stdin):
            calls.append((argv, stdin))
            return MOD.ProcessResult(0, b"replay-complete-retained\n", b"")
        evidence = MOD.invoke_driver(self.contract, observe)
        self.assertEqual(calls, [(self.contract.argv, self.contract.stdin)])
        self.assertEqual(evidence.stdin_sha256, self.contract.shell_sha256)

    def test_preexisting_record_rejects_without_overwrite(self) -> None:
        target = self.replay_root / MOD.RESULT_NAME
        target.write_bytes(b"foreign\n"); os.chmod(target, 0o600)
        with self.assertRaisesRegex(MOD.Reject, "already exists"):
            self.publish()
        self.assertEqual(target.read_bytes(), b"foreign\n")

    def test_overlap_and_noncanonical_layout_reject(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "direct run-parent children"):
            MOD.validate_layout(self.run_parent, self.replay_root, self.replay_root / "repository")
        linked = self.run_parent / "linked"
        linked.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaisesRegex(MOD.Reject, "canonical"):
            MOD.validate_layout(self.run_parent, self.replay_root, linked)

    def test_path_swap_and_result_mutation_reject(self) -> None:
        published = self.publish()
        replacement = self.replay_root / "replacement"
        replacement.write_bytes(published.result.raw); os.chmod(replacement, 0o600)
        os.replace(replacement, published.result.path)
        with self.assertRaisesRegex(MOD.Reject, "changed"):
            MOD.verify_publication(published, self.run_parent, self.replay_root, self.repository)

    def test_completion_mutation_rejects(self) -> None:
        published = self.publish()
        value = json.loads(published.completion.raw); value["stdout_sha256"] = "c" * 64
        published.completion.path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaisesRegex(MOD.Reject, "changed"):
            MOD.verify_publication(published, self.run_parent, self.replay_root, self.repository)

    def test_cleanup_is_never_implicit_or_implemented(self) -> None:
        self.publish()
        with self.assertRaisesRegex(MOD.Reject, "disabled"):
            MOD.request_cleanup()
        with self.assertRaisesRegex(MOD.Reject, "no implementation"):
            MOD.request_cleanup(enable_cleanup=True)
        self.assertTrue(self.replay_root.exists()); self.assertTrue(self.repository.exists())

    def test_exact_schema_rejects_extra_result_field(self) -> None:
        published = self.publish()
        value = json.loads(published.result.raw); value["extra"] = True
        published.result.path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        changed = MOD.stable_read(published.result.path, "replay result")
        with self.assertRaisesRegex(MOD.Reject, "schema"):
            MOD.verify_publication(MOD.Publication(changed, published.completion), self.run_parent, self.replay_root, self.repository)


if __name__ == "__main__":
    unittest.main(verbosity=2)
