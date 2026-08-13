#!/usr/bin/env python3
"""Offline retained-driver tests with mocked process and Git observations."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "issue397_retained_driver_successor_tests",
    HERE / "retained_driver_successor.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load retained-driver successor")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def write_private(path: Path, value: object) -> bytes:
    """Create one isolated private fixture file."""
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


class RetainedDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = MODULE.load_frozen_authority()
        cls.derived = MODULE.transform_shell(cls.authority)

    def test_exact_frozen_authority_and_generator_chain(self) -> None:
        self.assertEqual(self.authority.shell.sha256, MODULE.PINNED_SHA256[MODULE.FINAL_SHELL])
        self.assertEqual(self.authority.provenance.sha256, MODULE.PINNED_SHA256[MODULE.PROVENANCE])
        self.assertEqual(self.authority.document["execution_driver"]["shell"].encode(), self.authority.shell.raw)
        self.assertEqual(MODULE.derive(), self.derived)

    def test_structured_transform_changes_only_lifecycle_anchors(self) -> None:
        text = self.derived.decode()
        self.assertIn('readonly RESULT_ROOT="$REPLAY_ROOT/replay-root"', text)
        self.assertIn('readonly REPLAY="$REPLAY_ROOT/repository"', text)
        self.assertIn('cleanup_success_only() {\n  fail "retained driver forbids replay repository cleanup"', text)
        self.assertIn('cleanup_clean_primary_success_only() {\n  fail "retained driver forbids clean-primary cleanup"', text)
        self.assertNotIn('cleanup_success_only "$REPLAY"', text)
        self.assertNotIn("CLEAN_PRIMARY_REMOVED=1", text)
        self.assertEqual(text.count(MODULE.RESULT_SCHEMA), 1)
        self.assertEqual(text.count(MODULE.COMPLETION_SCHEMA), 1)
        self.assertEqual(text.count(MODULE.SUCCESS_MARKER), 3)

    def test_anchor_count_drift_rejects(self) -> None:
        document = json.loads(json.dumps(self.authority.document))
        document["execution_driver"]["shell"] = document["execution_driver"]["shell"].replace(
            'readonly REPLAY="$REPLAY_ROOT/replay"\n', "", 1
        )
        changed = replace(
            self.authority,
            document=document,
        )
        with self.assertRaisesRegex(MODULE.Reject, "anchor count differs"):
            MODULE.transform_shell(changed)

    def test_all_python_heredocs_compile_without_shell_execution(self) -> None:
        bodies = MODULE.extract_python_heredocs(self.derived)
        self.assertEqual(len(bodies), 41)
        MODULE.compile_derived(self.derived)
        writer = next(body for body in bodies if MODULE.COMPLETION_SCHEMA in body)
        self.assertNotIn("subprocess", writer)
        self.assertNotIn("os.system", writer)
        self.assertNotIn("os.popen", writer)

    def test_optional_derived_output_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-derived-output-") as temporary:
            output = Path(temporary).resolve() / "retained-driver.sh"
            with mock.patch("builtins.print"):
                self.assertEqual(MODULE.main(["--output", str(output)]), 0)
            self.assertEqual(output.read_bytes(), self.derived)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaisesRegex(MODULE.Reject, "already exists"):
                MODULE.main(["--output", str(output)])

    def _phase_a_fixture(self, root: Path) -> tuple[Path, Path]:
        base = self.authority.document["base"]
        forbidden = self.authority.document["forbidden_ancestry"]
        policy = {
            "base_ref": "origin/dev",
            "base_commit": base["commit"],
            "base_tree": base["tree"],
            "main_ref": "origin/main",
            "main_commit": base["protected_main_commit"],
            "required_ancestors": [base["commit"]],
            "forbidden_ancestors": list(
                dict.fromkeys(
                    [*forbidden["commits"], *forbidden["raw_semantic_source_commits"]]
                )
            ),
            "lane_chain": [],
        }
        manifest = {
            "schema": "task409-execution-preflight/v3",
            "phase": "A-consistency-only-no-git-no-replay",
            "artifacts": {},
            "shell_metadata": {},
            "normalized_json_sha256": "0" * 64,
            "inputs": {},
            "stale": {},
            "policy": policy,
            "approval": {
                "status": "consistency-only",
                "manifest_sha256": "not-bound-in-phase-a",
                "policy_sha256": "0" * 64,
            },
        }
        manifest_path = root / "phase-a-manifest.json"
        manifest_raw = write_private(manifest_path, manifest)
        approval_payload = {
            key: manifest[key]
            for key in (
                "schema", "phase", "artifacts", "shell_metadata",
                "normalized_json_sha256", "inputs", "stale", "policy",
            )
        }
        approval = hashlib.sha256(
            json.dumps(
                approval_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode()
        ).hexdigest()
        policy_sha = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        anchor = {
            "schema": "task409-execution-preflight/phase-a-approval-anchor/v1",
            "phase": "external-review-of-phase-a-consistency",
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "phase_a_approval_digest": approval,
            "policy_sha256": policy_sha,
            "decision": "approve-consistency-only",
            "provisioning_boundary": "external-review-input",
        }
        anchor_path = root / "phase-a-anchor.json"
        write_private(anchor_path, anchor)
        return manifest_path, anchor_path

    def _execute_writer(
        self,
        run_parent: Path,
        manifest_path: Path,
        anchor_path: Path,
        *,
        parent: str = "1" * 40,
    ) -> None:
        """Execute only the isolated Python writer with mocked Git values."""
        writer_shell = MODULE._result_writer_heredoc(
            self.authority,
            phase_a_manifest_path=str(manifest_path),
            phase_a_anchor_path=str(anchor_path),
        ).encode()
        body = MODULE.extract_python_heredocs(writer_shell)[0]
        arguments = [
            "retained-writer",
            str(run_parent / "replay-root"),
            str(run_parent / "repository"),
            "2" * 40,
            "3" * 40,
            parent,
            str(manifest_path),
            str(anchor_path),
        ]
        with mock.patch.object(sys, "argv", arguments):
            exec(compile(body, "isolated-retained-writer.py", "exec"), {"__name__": "__main__"})

    def test_isolated_writer_emits_exact_create_only_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-retained-test-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            run_parent = root / "run-parent"
            run_parent.mkdir(mode=0o700)
            repository = run_parent / "repository"
            repository.mkdir(mode=0o700)
            manifest_path, anchor_path = self._phase_a_fixture(root)
            self._execute_writer(run_parent, manifest_path, anchor_path)
            replay_root = run_parent / "replay-root"
            result_path = replay_root / "replay-result.json"
            completion_path = replay_root / "replay-completion.json"
            result = json.loads(result_path.read_bytes())
            completion = json.loads(completion_path.read_bytes())
            self.assertEqual(set(result), MODULE.RESULT_KEYS)
            self.assertEqual(result["schema"], MODULE.RESULT_SCHEMA)
            self.assertEqual(result["repository"], str(repository))
            self.assertEqual(result["replay_root"], str(replay_root))
            self.assertEqual(result["final_head"], "2" * 40)
            self.assertEqual(result["parent"], "1" * 40)
            self.assertEqual(result["tree"], "3" * 40)
            self.assertEqual(set(completion), MODULE.COMPLETION_KEYS)
            self.assertEqual(completion["completion_marker"], MODULE.COMPLETION_MARKER)
            self.assertEqual(completion["source_commit"], "d3c40687659ee645a5f03bc80cbf61ec8c49979a")
            self.assertEqual(completion["result_sha256"], hashlib.sha256(result_path.read_bytes()).hexdigest())
            expected_stdout = (
                f'FINAL_HEAD={"2" * 40}\n'
                f'REMOTE_DEV={self.authority.document["base"]["commit"]}\n'
                'INDEPENDENT_APPROVAL_REQUIRED=1\nNO_PUSH_PERFORMED=1\n'
            ).encode() + MODULE.SUCCESS_OUTPUT
            self.assertEqual(completion["stdout_sha256"], hashlib.sha256(expected_stdout).hexdigest())
            self.assertEqual(completion["stdout_bytes"], len(expected_stdout))
            self.assertEqual(completion["stderr_sha256"], hashlib.sha256(b"").hexdigest())
            self.assertEqual(completion["stderr_bytes"], 0)
            self.assertTrue(repository.is_dir())
            self.assertEqual(stat.S_IMODE(replay_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(result_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(completion_path.stat().st_mode), 0o600)
            with self.assertRaises(SystemExit):
                self._execute_writer(run_parent, manifest_path, anchor_path)

    def test_isolated_writer_rejects_bad_phase_a_before_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-retained-reject-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            run_parent = root / "run-parent"
            run_parent.mkdir(mode=0o700)
            (run_parent / "repository").mkdir(mode=0o700)
            manifest_path, anchor_path = self._phase_a_fixture(root)
            manifest = json.loads(manifest_path.read_bytes())
            manifest["policy"]["base_commit"] = "9" * 40
            write_private(manifest_path, manifest)
            with self.assertRaises(SystemExit):
                self._execute_writer(run_parent, manifest_path, anchor_path)
            self.assertFalse((run_parent / "replay-root").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
