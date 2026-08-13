#!/usr/bin/env python3
"""Offline retained-driver tests with isolated repository observations."""
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

    def test_derived_contract_binds_argv_and_changed_stdin_hash(self) -> None:
        contract = MODULE.derive_contract()
        self.assertEqual(contract.argv, tuple(self.authority.document["execution_driver"]["argv"]))
        self.assertEqual(contract.stdin, self.derived)
        self.assertEqual(contract.source_sha256, self.authority.shell.sha256)
        self.assertEqual(contract.derived_sha256, hashlib.sha256(self.derived).hexdigest())
        self.assertNotEqual(contract.derived_sha256, contract.source_sha256)
        self.assertEqual(MODULE.SUCCESS_OUTPUT, b"TASK409_RETAINED_REPLAY_OK=1\n")

    def test_structured_transform_has_pending_only_terminal_contract(self) -> None:
        text = self.derived.decode()
        self.assertIn('readonly RESULT_ROOT="$REPLAY_ROOT/replay-root"', text)
        self.assertIn('readonly REPLAY="$REPLAY_ROOT/repository"', text)
        self.assertIn('cleanup_success_only() {\n  fail "retained driver forbids replay repository cleanup"', text)
        self.assertIn('cleanup_clean_primary_success_only() {\n  fail "retained driver forbids clean-primary cleanup"', text)
        self.assertNotIn('cleanup_success_only "$REPLAY"', text)
        self.assertNotIn("CLEAN_PRIMARY_REMOVED=1", text)
        self.assertEqual(text.count(MODULE.PENDING_SCHEMA), 1)
        self.assertEqual(text.count("replay-result.pending.json"), 1)
        self.assertNotIn("replay-result.json", text)
        self.assertNotIn("replay-completion.json", text)
        self.assertTrue(text.endswith(f"printf '{MODULE.SUCCESS_MARKER}\\n'\n"))
        tail = text.rsplit("publish_retained_replay_pending", 1)[1]
        self.assertEqual(tail, f' "$RETAINED_PARENT"\nprintf \'{MODULE.SUCCESS_MARKER}\\n\'\n')

    def test_anchor_count_drift_rejects(self) -> None:
        document = json.loads(json.dumps(self.authority.document))
        document["execution_driver"]["shell"] = document["execution_driver"]["shell"].replace(
            'readonly REPLAY="$REPLAY_ROOT/replay"\n', "", 1
        )
        changed = replace(self.authority, document=document)
        with self.assertRaisesRegex(MODULE.Reject, "anchor count differs"):
            MODULE.transform_shell(changed)

    def test_all_python_heredocs_compile_without_shell_execution(self) -> None:
        bodies = MODULE.extract_python_heredocs(self.derived)
        self.assertEqual(len(bodies), 41)
        MODULE.compile_derived(self.derived)
        writer = next(body for body in bodies if MODULE.PENDING_SCHEMA in body)
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

    def _execute_writer(
        self,
        run_parent: Path,
        *,
        parent: str = "1" * 40,
        fsync: object | None = None,
    ) -> None:
        """Execute only the isolated pending writer with supplied observations."""
        body = MODULE.extract_python_heredocs(
            MODULE._result_writer_heredoc(self.authority).encode()
        )[0]
        arguments = [
            "retained-writer",
            str(run_parent / "replay-root"),
            str(run_parent / "repository"),
            "2" * 40,
            "3" * 40,
            parent,
        ]
        patches = [mock.patch.object(sys, "argv", arguments)]
        if fsync is not None:
            patches.append(mock.patch.object(os, "fsync", fsync))
        with patches[0]:
            if len(patches) == 1:
                exec(compile(body, "isolated-retained-writer.py", "exec"), {"__name__": "__main__"})
            else:
                with patches[1]:
                    exec(compile(body, "isolated-retained-writer.py", "exec"), {"__name__": "__main__"})

    def _run_parent(self, root: Path) -> Path:
        run_parent = root / "run-parent"
        run_parent.mkdir(mode=0o700)
        (run_parent / "repository").mkdir(mode=0o700)
        return run_parent

    def test_isolated_writer_emits_exact_create_only_pending_observations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-retained-test-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            run_parent = self._run_parent(root)
            repository = run_parent / "repository"
            self._execute_writer(run_parent)
            replay_root = run_parent / "replay-root"
            pending_path = replay_root / "replay-result.pending.json"
            pending = json.loads(pending_path.read_bytes())
            self.assertEqual(set(pending), MODULE.PENDING_KEYS)
            self.assertEqual(pending["schema"], MODULE.PENDING_SCHEMA)
            self.assertEqual(pending["repository"], str(repository))
            self.assertEqual(pending["replay_root"], str(replay_root))
            self.assertEqual(pending["final_head"], "2" * 40)
            self.assertEqual(pending["parent"], "1" * 40)
            self.assertEqual(pending["tree"], "3" * 40)
            self.assertTrue(repository.is_dir())
            self.assertEqual(stat.S_IMODE(replay_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(pending_path.stat().st_mode), 0o600)
            self.assertFalse((replay_root / "replay-result.json").exists())
            self.assertFalse((replay_root / "replay-completion.json").exists())
            with self.assertRaises(SystemExit):
                self._execute_writer(run_parent)

    def test_late_fsync_failure_leaves_pending_residue_without_final_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-retained-late-failure-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            run_parent = self._run_parent(root)
            real_fsync = os.fsync
            calls = 0

            def fail_late(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("mock late directory fsync failure")
                real_fsync(descriptor)

            with self.assertRaisesRegex(OSError, "mock late"):
                self._execute_writer(run_parent, fsync=fail_late)
            replay_root = run_parent / "replay-root"
            self.assertTrue((replay_root / "replay-result.pending.json").exists())
            self.assertTrue((run_parent / "repository").is_dir())
            self.assertFalse((replay_root / "replay-result.json").exists())
            self.assertFalse((replay_root / "replay-completion.json").exists())

    def test_invalid_observation_rejects_before_pending_publication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-retained-reject-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            run_parent = self._run_parent(root)
            with self.assertRaises(SystemExit):
                self._execute_writer(run_parent, parent="not-an-object-id")
            self.assertFalse((run_parent / "replay-root").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
