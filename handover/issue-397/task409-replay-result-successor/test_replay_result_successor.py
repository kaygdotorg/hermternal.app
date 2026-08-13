#!/usr/bin/env python3
"""Offline outer-wrapper tests. No replay or Git command is run."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "issue397_replay_result_successor_tests", HERE / "replay_result_successor.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load replay-result successor")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

OIDS = {
    "head": "1" * 40,
    "parent": "2" * 40,
    "tree": "3" * 40,
    "base": "4" * 40,
    "base_tree": "5" * 40,
    "main": "6" * 40,
    "source": "7" * 40,
    "required": "4" * 40,
    "forbidden": "8" * 40,
}


class WrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # This loads all real pinned modules and derives the real stdin. It does
        # not call the process boundary or Git reviewer commands.
        cls.real_authority = MODULE.load_authority()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="issue397-wrapper-test-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.run_parent = self.root / "runs"
        self.run_parent.mkdir(mode=0o700)
        self.pid = 4242
        self.authority = MODULE.Authority(
            driver=types.ModuleType("test_driver"),
            reviewer=types.ModuleType("test_reviewer"),
            argv=("/usr/bin/env", "-i", "/bin/bash", "-s"),
            stdin=b"#!/bin/bash\nprintf test\n",
            driver_source_sha256="a" * 64,
            derived_stdin_sha256=hashlib.sha256(
                b"#!/bin/bash\nprintf test\n"
            ).hexdigest(),
            markdown_sha256="b" * 64,
            json_sha256="c" * 64,
            shell_sha256="d" * 64,
            provenance_sha256="e" * 64,
            base_commit=OIDS["base"],
            base_tree=OIDS["base_tree"],
            protected_main_commit=OIDS["main"],
            source_commit=OIDS["source"],
            required_ancestors=(OIDS["required"],),
            forbidden_ancestors=(OIDS["forbidden"],),
        )
        evidence_path = self.root / "anchor.json"
        evidence_path.write_bytes(b"{}\n")
        evidence_path.chmod(0o600)
        self.phase_a = MODULE.PhaseAEvidence(
            MODULE.Snapshot(
                evidence_path,
                evidence_path.read_bytes(),
                hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
                MODULE._identity(os.lstat(evidence_path)),
            ),
            "f" * 64,
            "9" * 64,
        )
        self.patches = [
            mock.patch.object(MODULE, "RUN_PARENT", self.run_parent),
            mock.patch.object(MODULE, "load_authority", return_value=self.authority),
            mock.patch.object(
                MODULE, "load_phase_a_evidence", return_value=self.phase_a
            ),
            mock.patch.object(
                MODULE,
                "reobserve_repository",
                return_value={
                    "final_head": OIDS["head"],
                    "parent": OIDS["parent"],
                    "tree": OIDS["tree"],
                },
            ),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary.cleanup()

    def _layout(self) -> tuple[Path, Path, Path]:
        run_root = self.run_parent / f"{MODULE.RUN_PREFIX}{self.pid}"
        run_root.mkdir(mode=0o700)
        replay_root = run_root / "replay-root"
        replay_root.mkdir(mode=0o700)
        repository = run_root / "repository"
        repository.mkdir(mode=0o700)
        return run_root, replay_root, repository

    def _pending_value(self, replay_root: Path, repository: Path) -> dict:
        return {
            "schema": MODULE.PENDING_SCHEMA,
            "replay_root": str(replay_root),
            "replay_root_identity": MODULE._directory_identity(
                replay_root, "test replay root"
            ),
            "repository": str(repository),
            "repository_identity": MODULE._directory_identity(
                repository, "test repository"
            ),
            "head_state": "detached",
            "final_head": OIDS["head"],
            "parent": OIDS["parent"],
            "tree": OIDS["tree"],
            "base_commit": self.authority.base_commit,
            "base_tree": self.authority.base_tree,
            "protected_main_commit": self.authority.protected_main_commit,
            "required_ancestors": list(self.authority.required_ancestors),
            "forbidden_ancestors": list(self.authority.forbidden_ancestors),
        }

    def _create_pending(self, *, change=None) -> Path:
        _, replay_root, repository = self._layout()
        value = self._pending_value(replay_root, repository)
        if change is not None:
            change(value)
        path = replay_root / MODULE.PENDING_NAME
        path.write_bytes(MODULE._canonical_json(value))
        path.chmod(0o600)
        return path

    def _successful_boundary(self, calls: list | None = None):
        def boundary(argv, stdin, environment):
            if calls is not None:
                calls.append((argv, stdin, dict(environment)))
            self._create_pending()
            return MODULE.ProcessResult(
                self.pid, 0, MODULE.SUCCESS_OUTPUT, b""
            )

        return boundary

    def _execute(self, boundary=None):
        return MODULE.execute_and_publish(
            self.phase_a.snapshot.path,
            self.phase_a.snapshot.sha256,
            process_boundary=boundary or self._successful_boundary(),
        )

    def _assert_no_finals(self) -> None:
        replay_root = (
            self.run_parent
            / f"{MODULE.RUN_PREFIX}{self.pid}"
            / "replay-root"
        )
        self.assertFalse((replay_root / MODULE.RESULT_NAME).exists())
        self.assertFalse((replay_root / MODULE.COMPLETION_NAME).exists())

    def test_real_driver_contract_is_derived_and_pinned(self) -> None:
        authority = self.real_authority
        self.assertEqual(
            MODULE.DRIVER_SHA256,
            "3e3dc1444879b416fa7e8e884a3523566ba9f4a9a96f2857380d8c4869917e20",
        )
        self.assertEqual(
            MODULE.PHASE_A_RUNNER_SHA256,
            "fb11d84062c05a2054a2f4162908de54ed15a530538fbf671ee54ff999baaf84",
        )
        self.assertEqual(
            authority.derived_stdin_sha256,
            hashlib.sha256(authority.stdin).hexdigest(),
        )
        self.assertEqual(authority.derived_stdin_sha256, MODULE.DERIVED_STDIN_SHA256)
        self.assertNotEqual(
            authority.derived_stdin_sha256, authority.driver_source_sha256
        )
        self.assertEqual(authority.argv[-1], "-s")
        self.assertEqual(authority.driver_source_sha256, authority.shell_sha256)

    def test_success_uses_exact_argv_stdin_and_empty_environment(self) -> None:
        calls = []
        publication = self._execute(self._successful_boundary(calls))
        self.assertEqual(
            calls, [(self.authority.argv, self.authority.stdin, {})]
        )
        result = json.loads(publication.result.raw)
        completion = json.loads(publication.completion.raw)
        self.assertEqual(set(result), MODULE.RESULT_KEYS)
        self.assertEqual(set(completion), MODULE.COMPLETION_KEYS)
        self.assertEqual(result["schema"], MODULE.RESULT_SCHEMA)
        self.assertEqual(result["final_head"], OIDS["head"])
        self.assertEqual(
            result["phase_a_manifest_sha256"], self.phase_a.manifest_sha256
        )
        self.assertEqual(completion["returncode"], 0)
        self.assertEqual(completion["stderr_policy"], "empty")
        self.assertEqual(
            completion["stdin_sha256"],
            hashlib.sha256(self.authority.stdin).hexdigest(),
        )
        self.assertEqual(completion["stdin_bytes"], len(self.authority.stdin))
        self.assertEqual(completion["stdout_bytes"], len(MODULE.SUCCESS_OUTPUT))
        self.assertEqual(completion["stderr_bytes"], 0)

    def test_nonzero_reports_pending_residue_and_publishes_no_final(self) -> None:
        def boundary(argv, stdin, environment):
            pending = self._create_pending()
            self.assertTrue(pending.exists())
            return MODULE.ProcessResult(self.pid, 7, b"", b"failed")

        with self.assertRaisesRegex(MODULE.Reject, "rc=7") as caught:
            self._execute(boundary)
        self.assertIsNotNone(caught.exception.pending_residue)
        self._assert_no_finals()

    def test_missing_extra_and_late_markers_publish_no_final(self) -> None:
        outputs = (
            b"",
            MODULE.SUCCESS_OUTPUT + b"extra\n",
            b"early\n" + MODULE.SUCCESS_OUTPUT,
        )
        for index, output in enumerate(outputs):
            with self.subTest(output=output):
                self.pid = 4300 + index

                def boundary(argv, stdin, environment, observed=output):
                    self._create_pending()
                    return MODULE.ProcessResult(self.pid, 0, observed, b"")

                with self.assertRaisesRegex(MODULE.Reject, "sole success marker"):
                    self._execute(boundary)
                self._assert_no_finals()

    def test_stderr_rejects_and_publishes_no_final(self) -> None:
        def boundary(argv, stdin, environment):
            self._create_pending()
            return MODULE.ProcessResult(
                self.pid, 0, MODULE.SUCCESS_OUTPUT, b"warning\n"
            )

        with self.assertRaisesRegex(MODULE.Reject, "stderr is not empty"):
            self._execute(boundary)
        self._assert_no_finals()

    def test_pending_mutation_after_review_publishes_no_final(self) -> None:
        original = MODULE.reobserve_repository

        def mutate(pending, authority):
            result = original(pending, authority)
            with pending.snapshot.path.open("ab") as stream:
                stream.write(b" ")
                stream.flush()
                os.fsync(stream.fileno())
            return result

        with mock.patch.object(MODULE, "reobserve_repository", side_effect=mutate):
            with self.assertRaisesRegex(MODULE.Reject, "changed"):
                self._execute()
        self._assert_no_finals()

    def test_repository_drift_publishes_no_final(self) -> None:
        with mock.patch.object(
            MODULE,
            "reobserve_repository",
            side_effect=MODULE.Reject("#400 observed repository drift"),
        ):
            with self.assertRaisesRegex(MODULE.Reject, "repository drift"):
                self._execute()
        self._assert_no_finals()

    def test_repository_late_drift_publishes_no_final(self) -> None:
        first = {
            "final_head": OIDS["head"],
            "parent": OIDS["parent"],
            "tree": OIDS["tree"],
        }
        second = dict(first)
        second["tree"] = "0" * 40
        with mock.patch.object(
            MODULE, "reobserve_repository", side_effect=(first, second)
        ):
            with self.assertRaisesRegex(MODULE.Reject, "observations changed"):
                self._execute()
        self._assert_no_finals()

    def test_400_boundary_accepts_self_contained_repository_facts(self) -> None:
        """Exercise the complete #400 call path with no alternates exception."""
        self.patches[-1].stop()
        self.patches.pop()
        _, replay_root, repository = self._layout()
        value = self._pending_value(replay_root, repository)
        pending_path = replay_root / MODULE.PENDING_NAME
        pending_path.write_bytes(MODULE._canonical_json(value))
        pending_path.chmod(0o600)
        pending = MODULE.PendingFacts(
            MODULE.stable_read(pending_path, "test pending"),
            replay_root,
            repository,
            value,
        )

        class ReviewReject(Exception):
            pass

        reviewer = types.SimpleNamespace()
        reviewer.Reject = ReviewReject
        reviewer.require = lambda condition, message: (
            None if condition else (_ for _ in ()).throw(ReviewReject(message))
        )
        head_snapshot = types.SimpleNamespace(
            identity=(1, 2),
            sha256=hashlib.sha256((OIDS["head"] + "\n").encode()).hexdigest(),
            raw=(OIDS["head"] + "\n").encode(),
        )
        identity = types.SimpleNamespace(head_snapshot=head_snapshot)
        guard = types.SimpleNamespace(assert_stable=mock.Mock())
        reviewer.inspect_metadata = mock.Mock(return_value=identity)
        reviewer.RepoGuard = mock.Mock(return_value=guard)
        reviewer.check_worktree_registry = mock.Mock()
        reviewer.check_clean = mock.Mock()
        reviewer.check_index_flags = mock.Mock()
        reviewer._check_repo_shape = mock.Mock()
        reviewer._check_origin_and_base = mock.Mock()
        reviewer.read_bound_file = mock.Mock(return_value=head_snapshot)
        reviewer.run_git = mock.Mock(
            return_value=types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        )
        reviewer._assert_oid_type = mock.Mock()
        reviewer.git_output = mock.Mock(
            return_value=f'{OIDS["head"]} {OIDS["parent"]}\n'.encode()
        )
        reviewer._decode = lambda raw, _label: raw.decode()
        reviewer._rev_parse = mock.Mock(return_value=OIDS["tree"])
        reviewer._check_ancestry = mock.Mock()
        reviewer._check_fsck = mock.Mock()
        reviewer._check_explicit_closure = mock.Mock()
        reviewer.directory_identity = mock.Mock(
            return_value=value["repository_identity"]
        )
        authority = MODULE.Authority(
            **{**self.authority.__dict__, "reviewer": reviewer}
        )
        observed = MODULE.reobserve_repository(pending, authority)
        self.assertEqual(
            observed,
            {
                "final_head": OIDS["head"],
                "parent": OIDS["parent"],
                "tree": OIDS["tree"],
            },
        )
        reviewer._check_repo_shape.assert_called_once()
        reviewer._check_fsck.assert_called_once()
        reviewer._check_explicit_closure.assert_called_once()
        guard.assert_stable.assert_called_once()

    def test_pending_policy_drift_publishes_no_final(self) -> None:
        def boundary(argv, stdin, environment):
            self._create_pending(
                change=lambda value: value.__setitem__("base_tree", "0" * 40)
            )
            return MODULE.ProcessResult(self.pid, 0, MODULE.SUCCESS_OUTPUT, b"")

        with self.assertRaisesRegex(MODULE.Reject, "base tree differs") as caught:
            self._execute(boundary)
        self.assertIsNotNone(caught.exception.pending_residue)
        self._assert_no_finals()

    def test_preexisting_result_or_completion_is_never_overwritten(self) -> None:
        for name in (MODULE.RESULT_NAME, MODULE.COMPLETION_NAME):
            with self.subTest(name=name):
                self.pid += 1

                def boundary(argv, stdin, environment, target=name):
                    pending = self._create_pending()
                    foreign = pending.parent / target
                    foreign.write_bytes(b"foreign\n")
                    foreign.chmod(0o600)
                    return MODULE.ProcessResult(
                        self.pid, 0, MODULE.SUCCESS_OUTPUT, b""
                    )

                with self.assertRaisesRegex(MODULE.Reject, "already exists"):
                    self._execute(boundary)
                replay_root = (
                    self.run_parent
                    / f"{MODULE.RUN_PREFIX}{self.pid}"
                    / "replay-root"
                )
                self.assertEqual((replay_root / name).read_bytes(), b"foreign\n")
                other = (
                    MODULE.COMPLETION_NAME
                    if name == MODULE.RESULT_NAME
                    else MODULE.RESULT_NAME
                )
                self.assertFalse((replay_root / other).exists())

    def test_late_publication_fsync_failure_rolls_back_both_finals(self) -> None:
        genuine = os.fsync
        calls = 0

        def fail_final_parent(descriptor):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("injected late final fsync failure")
            return genuine(descriptor)

        with mock.patch.object(MODULE.os, "fsync", side_effect=fail_final_parent):
            with self.assertRaisesRegex(MODULE.Reject, "late final fsync"):
                self._execute()
        self._assert_no_finals()
        pending = (
            self.run_parent
            / f"{MODULE.RUN_PREFIX}{self.pid}"
            / "replay-root"
            / MODULE.PENDING_NAME
        )
        self.assertTrue(pending.exists())

    def test_phase_a_interface_requires_independent_hash_and_real_path(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.patches = []
        with self.assertRaisesRegex(MODULE.Reject, "64 lowercase"):
            MODULE.load_phase_a_evidence(self.root / "missing.json", "bad")
        with self.assertRaisesRegex(MODULE.Reject, "v2 authority"):
            MODULE.load_phase_a_evidence(self.root / "missing.json", "0" * 64)

    def test_genuine_disposable_v2_anchor_evidence_is_accepted(self) -> None:
        """Create real v2 evidence, then parse it through the pinned wrapper."""
        for patcher in reversed(self.patches):
            patcher.stop()
        self.patches = []
        runner = MODULE._verified_module(
            MODULE.PHASE_A_RUNNER_PATH,
            MODULE.PHASE_A_RUNNER_SHA256,
            "issue397_wrapper_test_phase_a_runner",
        )
        external_root = self.root / "phase-a-v2"
        modules = runner.load_modules(HERE.parents[2])

        def guarded_observation():
            identity = {
                "st_dev": 1,
                "st_ino": 2,
                "st_uid": os.getuid(),
                "st_gid": os.getgid(),
                "st_mode": 0o700,
                "st_size": 4096,
                "st_nlink": 2,
                "st_mtime_ns": 3,
                "st_ctime_ns": 4,
            }
            binding = runner._binding_record(identity)
            return {
                "path": os.fspath(runner.REPOSITORY_ROOT),
                "binding": binding,
                "parent_binding": {**binding, "st_ino": 5},
                "head": runner.FROZEN_COMMIT,
                "tree": runner.FROZEN_TREE,
                "detached": True,
                "source_repository": {
                    "path": os.fspath(runner.SOURCE_REPOSITORY_ROOT),
                    "binding": {**binding, "st_ino": 6},
                },
                "git_common_dir": {
                    "path": os.fspath(runner.GIT_COMMON_DIR),
                    "binding": {**binding, "st_ino": 7},
                },
                "git_object_dir": {
                    "path": os.fspath(runner.GIT_OBJECT_DIR),
                    "binding": {**binding, "st_ino": 8},
                },
                "git_worktree_dir": {
                    "path": os.fspath(runner.GIT_WORKTREE_DIR),
                    "binding": {**binding, "st_ino": 9},
                },
            }

        with mock.patch.object(runner, "EXTERNAL_ROOT", external_root), mock.patch.dict(
            os.environ,
            {"HERMTERNAL_PHASE_A_TEST_ROOT": os.fspath(external_root)},
            clear=False,
        ), mock.patch.object(
            runner.subprocess,
            "run",
            side_effect=AssertionError("v2 fixture attempted a process"),
        ):
            runner.phase_a(
                modules,
                repository_root=runner.REPOSITORY_ROOT,
                external_root=external_root,
                worktree_verifier=guarded_observation,
            )
            phase_sha = runner.stable_read(
                external_root / "evidence" / runner.PHASE_A_RECORD,
                "fixture Phase A evidence",
            ).sha256
            runner.anchor(
                modules,
                repository_root=runner.REPOSITORY_ROOT,
                external_root=external_root,
                expected_phase_a_sha256=phase_sha,
                worktree_verifier=guarded_observation,
            )
            anchor_path = external_root / "evidence" / runner.ANCHOR_RECORD
            anchor_snapshot = runner.stable_read(anchor_path, "fixture anchor evidence")
            genuine_verified_module = MODULE._verified_module

            def verified(path, digest, name):
                if Path(path) == MODULE.PHASE_A_RUNNER_PATH:
                    self.assertEqual(digest, MODULE.PHASE_A_RUNNER_SHA256)
                    return runner
                return genuine_verified_module(path, digest, name)

            with mock.patch.object(MODULE, "_verified_module", side_effect=verified):
                evidence = MODULE.load_phase_a_evidence(
                    anchor_path, anchor_snapshot.sha256
                )
            record = json.loads(anchor_snapshot.raw)
            self.assertEqual(record["schema"], runner.EVIDENCE_SCHEMA)
            self.assertEqual(evidence.snapshot.sha256, anchor_snapshot.sha256)
            self.assertEqual(
                evidence.manifest_sha256,
                record["inputs"]["phase_a_manifest_sha256"],
            )
            self.assertEqual(
                evidence.approval_digest,
                record["inputs"]["phase_a_approval_digest"],
            )

    def test_parser_requires_both_phase_a_arguments(self) -> None:
        with self.assertRaises(SystemExit):
            MODULE.build_parser().parse_args([])
        parsed = MODULE.build_parser().parse_args(
            [
                "--phase-a-evidence",
                "/tmp/anchor.json",
                "--expected-phase-a-evidence-sha256",
                "0" * 64,
            ]
        )
        self.assertEqual(parsed.phase_a_evidence, Path("/tmp/anchor.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
