#!/usr/bin/env python3
"""Tests for the dry Phase A, anchor, replay, and Phase B interlock."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("execution_interlock", HERE / "execution_interlock.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MOD; SPEC.loader.exec_module(MOD)
S64 = "a" * 64


def provenance() -> bytes:
    value = {
        "schema": MOD.PROVENANCE_SCHEMA, "issue": 397, "candidate": "five", "generation": {},
        "repository_boundary": {"integrated_commit": "1" * 40, "integrated_tree": "2" * 40, "base_commit": MOD.BASE_COMMIT, "base_tree": MOD.BASE_TREE, "protected_main_commit": MOD.MAIN_COMMIT, "source_commit": "3" * 40},
        "dependencies": [], "source_inputs": [],
        "outputs": {role: {"path": str(MOD.FINAL_ROOT / name), "sha256": S64} for role, name in (("markdown", "candidate-five.md"), ("json", "candidate-five.json"), ("shell", "candidate-five.sh"))},
        "cross_format_authority": {}, "publication": {},
        "safety_claims": {"shell_executed": False, "replay_run": False, "hermes_used": False},
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class InterlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = MOD.validate_provenance(provenance())
        self.plan = MOD.new_plan(self.authority, "/private/tmp/issue397-runtime-test", "/private/tmp/issue397-replay-test")

    def test_installs_git_hardening_in_phase_b(self) -> None:
        lifecycle, hardened = MOD.install_reviewers()
        self.assertIs(lifecycle.PHASE_B.REVIEW, hardened)
        self.assertTrue(callable(hardened._git_argv))

    def test_exact_sequence_and_resume_chain(self) -> None:
        phase_a = {"manifest_path": "/private/tmp/issue397-runtime-test/phase-a/input-manifest.json", "manifest_sha256": S64, "approval_digest": "b" * 64, "policy_sha256": "c" * 64, "authority_provenance_sha256": self.authority.sha256}
        anchor = {"anchor_path": "/private/tmp/issue397-runtime-test/external-review/phase-a-approval-anchor.json", "anchor_sha256": "d" * 64, "manifest_sha256": S64, "approval_digest": "b" * 64, "policy_sha256": "c" * 64}
        replay = {"replay_root": "/private/tmp/issue397-replay-test", "repository": "/private/tmp/issue397-replay-test/repository", "result_path": "/private/tmp/issue397-replay-test/replay-result.json", "result_sha256": "e" * 64, "final_head": "4" * 40, "final_parent": MOD.BASE_COMMIT, "final_tree": "5" * 40}
        phase_b = {"result_sha256": "e" * 64, "manifest_sha256": S64, "anchor_sha256": "d" * 64, "phase_a_validation_calls": 1, "git_config_calls": 1, "execution": "not-run", "mutation": "not-run", "network": "not-used", "approval": "not-claimed"}
        plan = MOD.accept_observation(self.plan, "phase-a", phase_a)
        plan = MOD.accept_observation(plan, "anchor", anchor)
        plan = MOD.accept_observation(plan, "replay", replay)
        plan = MOD.accept_observation(plan, "phase-b", phase_b)
        MOD.validate_plan(json.loads(json.dumps(plan)))
        with self.assertRaisesRegex(MOD.Reject, "complete"):
            MOD.command_for_next(plan)

    def test_rejects_skip_repeat_and_changed_resume_evidence(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "out of order"):
            MOD.accept_observation(self.plan, "replay", {})
        phase_a = {"manifest_path": "/private/tmp/issue397-runtime-test/phase-a/input-manifest.json", "manifest_sha256": S64, "approval_digest": "b" * 64, "policy_sha256": "c" * 64, "authority_provenance_sha256": self.authority.sha256}
        plan = MOD.accept_observation(self.plan, "phase-a", phase_a)
        with self.assertRaisesRegex(MOD.Reject, "out of order"):
            MOD.accept_observation(plan, "phase-a", phase_a)
        plan["events"][0]["evidence"]["manifest_sha256"] = "f" * 64
        with self.assertRaisesRegex(MOD.Reject, "state|chain|tip"):
            MOD.validate_plan(plan)

    def test_rejects_provenance_and_root_substitution(self) -> None:
        hostile = json.loads(provenance()); hostile["extra"] = True
        with self.assertRaisesRegex(MOD.Reject, "fields"):
            MOD.validate_provenance(json.dumps(hostile).encode())
        with self.assertRaisesRegex(MOD.Reject, "outside"):
            MOD.new_plan(self.authority, "/tmp/not-approved", "/private/tmp/replay")
        with self.assertRaisesRegex(MOD.Reject, "overlap"):
            MOD.new_plan(self.authority, "/private/tmp/same", "/private/tmp/same/replay")

    def test_command_is_stop_marker_not_an_execution_argv(self) -> None:
        self.assertEqual(MOD.command_for_next(self.plan), ("STOP-BEFORE-EXECUTION", "phase-a"))

    def test_rejects_bad_digest_and_runtime_manifest_path(self) -> None:
        evidence = {"manifest_path": "x", "manifest_sha256": "not-a-hash", "approval_digest": "b" * 64, "policy_sha256": "c" * 64, "authority_provenance_sha256": self.authority.sha256}
        with self.assertRaisesRegex(MOD.Reject, "64hex"):
            MOD.accept_observation(self.plan, "phase-a", evidence)
        evidence["manifest_sha256"] = S64
        with self.assertRaisesRegex(MOD.Reject, "manifest path"):
            MOD.accept_observation(self.plan, "phase-a", evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
