#!/usr/bin/env python3
"""Offline retained-driver tests with isolated repository observations."""
from __future__ import annotations

import ast
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
        self.assertEqual(len(bodies), 42)
        MODULE.compile_derived(self.derived)
        writer = next(body for body in bodies if MODULE.PENDING_SCHEMA in body)
        self.assertNotIn("subprocess", writer)
        self.assertNotIn("os.system", writer)
        self.assertNotIn("os.popen", writer)

    def _self_contained_body(self) -> str:
        return next(
            body
            for body in MODULE.extract_python_heredocs(self.derived)
            if "non-thin self-contained object pack" in body
        )

    def _isolated_helper_functions(self) -> dict[str, object]:
        """Load helper definitions only. Do not run the generated script body."""
        wanted = {
            "reject",
            "snapshot",
            "assert_snapshot",
            "require_empty_pack_directory",
            "file_identity",
            "read_descriptor",
            "unlink_bound_alternate",
        }
        parsed = ast.parse(self._self_contained_body())
        definitions = [
            node
            for node in parsed.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in wanted
        ]
        module = ast.Module(body=definitions, type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {
            "hashlib": hashlib,
            "os": os,
            "stat": stat,
            "MAX_PACK": 1024 * 1024 * 1024,
        }
        exec(compile(module, "isolated-self-contained-helpers.py", "exec"), namespace)
        self.assertEqual(wanted, set(namespace).intersection(wanted))
        return namespace

    def test_proof_roots_are_complete_and_missing_source_or_forbidden_rejects(self) -> None:
        roots = MODULE._proof_commit_roots(self.authority)
        required = MODULE._required_proof_commit_roots(self.authority)
        self.assertTrue(required <= set(roots))
        source = next(
            lane["source_commit"]["commit"]
            for lane in self.authority.document["ordered_lanes"]
            if isinstance(lane.get("source_commit"), dict)
        )
        forbidden = self.authority.document["forbidden_ancestry"]["commits"][0]
        for missing in (source, forbidden):
            with self.subTest(missing=missing):
                changed = tuple(value for value in roots if value != missing)
                with self.assertRaisesRegex(MODULE.Reject, "inventory is incomplete"):
                    MODULE._validate_proof_commit_roots(self.authority, changed)

    def test_pack_contract_is_non_thin_local_and_rechecks_without_alternates(self) -> None:
        body = self._self_contained_body()
        self.assertIn("run(['pack-objects', pack_prefix]", body)
        self.assertNotIn("'--thin'", body)
        self.assertNotIn("'--local'", body)
        unlink = body.index("unlink_bound_alternate(alternates")
        fsck = body.index("run(['fsck', '--strict'", unlink)
        roots = body.index("for root in ROOTS:", fsck)
        final_pack = body.index("assert_snapshot(pack_path", roots)
        self.assertLess(unlink, fsck)
        self.assertLess(fsck, roots)
        self.assertLess(roots, final_pack)
        self.assertIn("if os.path.lexists(alternates):", body[unlink:])

    def test_pack_and_index_mutation_are_detected(self) -> None:
        helpers = self._isolated_helper_functions()
        snapshot = helpers["snapshot"]
        assert_snapshot = helpers["assert_snapshot"]
        with tempfile.TemporaryDirectory(prefix="issue397-pack-snapshot-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            for name in ("pack-a.pack", "pack-a.idx"):
                path = root / name
                path.write_bytes(b"bound bytes\n")
                path.chmod(0o600)
                expected = snapshot(str(path), name)
                with path.open("ab") as stream:
                    stream.write(b"changed")
                    stream.flush()
                    os.fsync(stream.fileno())
                with self.assertRaisesRegex(SystemExit, "changed"):
                    assert_snapshot(str(path), expected, name)

    def _alternate_fixture(self, root: Path, raw: bytes = b"/bound/objects\n") -> Path:
        info = root / "objects" / "info"
        info.mkdir(parents=True, mode=0o700)
        info.parent.chmod(0o700)
        path = info / "alternates"
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def test_alternates_content_hardlink_and_swap_reject(self) -> None:
        unlink = self._isolated_helper_functions()["unlink_bound_alternate"]
        expected = b"/bound/objects\n"
        with tempfile.TemporaryDirectory(prefix="issue397-alternate-content-") as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            path = self._alternate_fixture(root, b"/wrong/objects\n")
            with self.assertRaisesRegex(RuntimeError, "bytes differ"):
                unlink(str(path), expected)
            self.assertTrue(path.exists())
        with tempfile.TemporaryDirectory(prefix="issue397-alternate-hardlink-") as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            path = self._alternate_fixture(root, expected)
            os.link(path, path.with_name("second-link"))
            with self.assertRaisesRegex(RuntimeError, "single-link"):
                unlink(str(path), expected)
            self.assertTrue(path.exists())
        with tempfile.TemporaryDirectory(prefix="issue397-alternate-swap-") as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            path = self._alternate_fixture(root, expected)
            replacement = path.with_name("replacement")
            replacement.write_bytes(expected); replacement.chmod(0o600)
            real_read = os.read
            swapped = False

            def swap_after_read(descriptor: int, count: int) -> bytes:
                nonlocal swapped
                block = real_read(descriptor, count)
                if block and not swapped:
                    swapped = True
                    os.replace(replacement, path)
                return block

            with mock.patch.object(os, "read", side_effect=swap_after_read):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    unlink(str(path), expected)
            self.assertEqual(path.read_bytes(), expected)

    def test_alternates_unlink_fsync_failure_fails_after_exact_unlink(self) -> None:
        unlink = self._isolated_helper_functions()["unlink_bound_alternate"]
        expected = b"/bound/objects\n"
        with tempfile.TemporaryDirectory(prefix="issue397-alternate-fsync-") as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            path = self._alternate_fixture(root, expected)
            with mock.patch.object(os, "fsync", side_effect=OSError("injected fsync failure")):
                with self.assertRaisesRegex(OSError, "injected fsync failure"):
                    unlink(str(path), expected)
            self.assertFalse(os.path.lexists(path))

    def test_exact_alternates_inode_is_unlinked_and_parent_is_synced(self) -> None:
        unlink = self._isolated_helper_functions()["unlink_bound_alternate"]
        expected = b"/bound/objects\n"
        with tempfile.TemporaryDirectory(prefix="issue397-alternate-success-") as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            path = self._alternate_fixture(root, expected)
            observed = os.lstat(path)
            calls = 0
            real_fsync = os.fsync

            def count_fsync(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                real_fsync(descriptor)

            with mock.patch.object(os, "fsync", side_effect=count_fsync):
                unlink(str(path), expected)
            self.assertEqual(calls, 1)
            self.assertFalse(os.path.lexists(path))
            self.assertEqual(observed.st_nlink, 1)

    def test_preexisting_pack_collision_rejects(self) -> None:
        require_empty = self._isolated_helper_functions()["require_empty_pack_directory"]
        with tempfile.TemporaryDirectory(prefix="issue397-pack-collision-") as temporary:
            pack = Path(temporary).resolve() / "pack"
            pack.mkdir(mode=0o700)
            collision = pack / "pack-foreign.pack"
            collision.write_bytes(b"foreign\n"); collision.chmod(0o600)
            with self.assertRaisesRegex(SystemExit, "pre-existing"):
                require_empty(str(pack))
            self.assertEqual(collision.read_bytes(), b"foreign\n")

    def test_self_contained_helper_captures_output_without_stdout_leakage(self) -> None:
        body = self._self_contained_body()
        self.assertIn("stdout=subprocess.PIPE, stderr=subprocess.PIPE", body)
        self.assertIn("packed.stdout", body)
        self.assertNotIn("print(", body)
        text = self.derived.decode()
        self.assertIn(
            'git_replay merge-base --is-ancestor "$BASE" "$CURRENT_HEAD"', text
        )
        self.assertEqual(text.count(MODULE.SUCCESS_MARKER), 1)
        self.assertTrue(text.endswith(f"printf '{MODULE.SUCCESS_MARKER}\\n'\n"))

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
