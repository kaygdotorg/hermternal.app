#!/usr/bin/env python3
"""Focused offline tests for the genuine Phase-A and anchor runner."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
RUNNER_PATH = HERE / "phase_a_anchor_runner.py"
SPEC = importlib.util.spec_from_file_location("issue397_test_phase_a_anchor_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load runner: {RUNNER_PATH}")
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class PhaseAAnchorRunnerTests(unittest.TestCase):
    """Use real frozen modules and only wrap genuine calls to count them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.checkout = HERE.parents[2]
        cls.modules = RUNNER.load_modules(cls.checkout)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".hermternal-phase-a-anchor-test-", dir=Path("/home/kayg/Developer")
        )
        self.external_root = Path(self.temporary.name) / "external"
        self.environment = mock.patch.dict(
            os.environ,
            {"HERMTERNAL_PHASE_A_TEST_ROOT": os.fspath(self.external_root)},
            clear=False,
        )
        self.environment.start()
        self.external_constant = mock.patch.object(RUNNER, "EXTERNAL_ROOT", self.external_root)
        self.external_constant.start()

    def tearDown(self) -> None:
        self.external_constant.stop()
        self.environment.stop()
        self.temporary.cleanup()

    def _phase_a(self, **kwargs):
        return RUNNER.phase_a(
            self.modules,
            repository_root=RUNNER.REPOSITORY_ROOT,
            external_root=self.external_root,
            worktree_verifier=self._guarded_observation,
            **kwargs,
        )

    def _phase_sha(self) -> str:
        return RUNNER.stable_read(
            self.external_root / "evidence" / RUNNER.PHASE_A_RECORD,
            "test Phase A evidence",
        ).sha256

    def _anchor(self, expected_phase_a_sha256=None, **kwargs):
        return RUNNER.anchor(
            self.modules,
            repository_root=RUNNER.REPOSITORY_ROOT,
            external_root=self.external_root,
            expected_phase_a_sha256=expected_phase_a_sha256 or self._phase_sha(),
            worktree_verifier=self._guarded_observation,
            **kwargs,
        )

    @staticmethod
    def _guarded_observation():
        identity = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        binding = RUNNER._binding_record(identity)
        return {"path": os.fspath(RUNNER.REPOSITORY_ROOT), "binding": binding, "parent_binding": {**binding, "st_ino": 5}, "head": RUNNER.FROZEN_COMMIT, "tree": RUNNER.FROZEN_TREE, "detached": True, "source_repository": {"path": os.fspath(RUNNER.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}}, "git_common_dir": {"path": os.fspath(RUNNER.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}}, "git_object_dir": {"path": os.fspath(RUNNER.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}}, "git_worktree_dir": {"path": os.fspath(RUNNER.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}}}

    def _rewrite_phase_record(self, change) -> str:
        path = self.external_root / "evidence" / RUNNER.PHASE_A_RECORD
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.unlink()
        snapshot = RUNNER._publish_record(path, value)
        return snapshot.sha256

    def test_full_genuine_chain_has_exact_calls_and_closed_evidence(self) -> None:
        phase_wrapper_calls = 0
        anchor_wrapper_calls = 0

        def phase_wrapper(genuine):
            def call(value):
                nonlocal phase_wrapper_calls
                phase_wrapper_calls += 1
                return genuine(value)
            return call

        def anchor_wrapper(genuine):
            def call(*args, **kwargs):
                nonlocal anchor_wrapper_calls
                anchor_wrapper_calls += 1
                return genuine(*args, **kwargs)
            return call

        with mock.patch.object(
            RUNNER.subprocess,
            "run",
            side_effect=AssertionError("a stage attempted a process"),
        ):
            phase_record = self._phase_a(validator_wrapper=phase_wrapper)
            anchor_record = self._anchor(provisioner_wrapper=anchor_wrapper)

        self.assertEqual(phase_wrapper_calls, 1)
        self.assertEqual(anchor_wrapper_calls, 1)
        self.assertEqual(phase_record["observations"]["phase_a_validator_calls"], 1)
        self.assertEqual(anchor_record["observations"]["anchor_provisioner_calls"], 1)
        self.assertEqual(anchor_record["observations"]["anchor_genuine_phase_a_validator_calls"], 1)
        self.assertEqual(phase_record["safety"], RUNNER._safety())
        self.assertEqual(anchor_record["safety"], RUNNER._safety())

        expected = {
            "phase-a/.owner",
            "phase-a/input-manifest.json",
            "external-review/phase-a-approval-anchor.json",
            "evidence/phase-a.json",
            "evidence/anchor.json",
        }
        observed = {
            os.fspath(path.relative_to(self.external_root))
            for path in self.external_root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(observed, expected)
        for relative in expected:
            item = self.external_root / relative
            metadata = os.lstat(item)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_nlink, 1)

        phase_snapshot = RUNNER.stable_read(
            self.external_root / "evidence" / RUNNER.PHASE_A_RECORD,
            "Phase A evidence",
        )
        anchor_snapshot = RUNNER.stable_read(
            self.external_root / "evidence" / RUNNER.ANCHOR_RECORD,
            "anchor evidence",
        )
        self.assertEqual(anchor_record["prior_sha256"], phase_snapshot.sha256)
        self.assertEqual(anchor_record["inputs"]["expected_phase_a_sha256"], phase_snapshot.sha256)
        self.assertEqual(anchor_snapshot.raw, RUNNER._canonical_json(anchor_record))
        self.assertTrue(anchor_snapshot.raw.endswith(b"\n"))
        self.assertFalse(anchor_snapshot.raw.endswith(b"\n\n"))

    def test_non_mocked_lifecycle_accepts_benign_directory_timestamps(self) -> None:
        """Run genuine Phase A and anchor while directory timestamps change."""
        phase_record = self._phase_a()
        for path in (self.external_root, self.external_root / "phase-a", self.external_root / "external-review", self.external_root / "evidence"):
            os.utime(path, None)
        anchor_record = self._anchor()
        self.assertEqual(phase_record["schema"], RUNNER.EVIDENCE_SCHEMA)
        self.assertEqual(anchor_record["schema"], RUNNER.EVIDENCE_SCHEMA)

    def test_v1_durable_root_is_rejected_and_untouched(self) -> None:
        before = os.path.lexists(RUNNER.V1_EXTERNAL_ROOT)
        with self.assertRaisesRegex(RUNNER.Reject, "fixed v2 authority"):
            RUNNER.phase_a(
                self.modules,
                repository_root=RUNNER.REPOSITORY_ROOT,
                external_root=RUNNER.V1_EXTERNAL_ROOT,
                worktree_verifier=self._guarded_observation,
            )
        self.assertEqual(os.path.lexists(RUNNER.V1_EXTERNAL_ROOT), before)

    def test_anchor_is_create_only_and_preserves_collision(self) -> None:
        self._phase_a()
        target = self.external_root / "external-review" / RUNNER.ANCHOR_NAME
        collision = RUNNER._publish_record(target, {"collision": True})
        with self.assertRaisesRegex(RUNNER.Reject, "genuine anchor rejected"):
            self._anchor()
        after = RUNNER.stable_read(target, "collision")
        self.assertEqual(after, collision)
        self.assertFalse(os.path.lexists(self.external_root / "evidence" / RUNNER.ANCHOR_RECORD))

    def test_anchor_rejects_changed_phase_a_evidence(self) -> None:
        self._phase_a()
        evidence = self.external_root / "evidence" / RUNNER.PHASE_A_RECORD
        with evidence.open("ab") as stream:
            stream.write(b"{}\n")
            stream.flush()
            os.fsync(stream.fileno())
        with self.assertRaisesRegex(RUNNER.Reject, "strict JSON"):
            self._anchor()
        self.assertFalse(os.path.lexists(self.external_root / "external-review" / RUNNER.ANCHOR_NAME))

    def test_anchor_requires_the_separately_reviewed_phase_a_digest(self) -> None:
        self._phase_a()
        with self.assertRaisesRegex(RUNNER.Reject, "reviewed handoff"):
            self._anchor(expected_phase_a_sha256="f" * 64)
        with self.assertRaisesRegex(RUNNER.Reject, "expected Phase A SHA-256 is invalid"):
            self._anchor(expected_phase_a_sha256="missing")
        with self.assertRaises(SystemExit):
            RUNNER.build_parser().parse_args(["anchor"])
        self.assertFalse(os.path.lexists(self.external_root / "external-review" / RUNNER.ANCHOR_NAME))

    def test_anchor_rejects_scalar_type_and_single_field_rewrites(self) -> None:
        self._phase_a()
        digest = self._rewrite_phase_record(
            lambda value: value["observations"]["manifest"].__setitem__("bytes", "1")
        )
        with self.assertRaisesRegex(RUNNER.Reject, "manifest byte count"):
            self._anchor(expected_phase_a_sha256=digest)

    def test_anchor_rejects_coordinated_canonical_digest_rewrite(self) -> None:
        self._phase_a()

        def change(value):
            replacement = "f" * 64
            value["observations"]["phase_a_approval_digest"] = replacement

        digest = self._rewrite_phase_record(change)
        with self.assertRaisesRegex(RUNNER.Reject, "derived digests"):
            self._anchor(expected_phase_a_sha256=digest)
        self.assertFalse(os.path.lexists(self.external_root / "external-review" / RUNNER.ANCHOR_NAME))

    def test_anchor_rejects_root_mutation(self) -> None:
        self._phase_a()
        digest = self._phase_sha()
        os.chmod(self.external_root, 0o710)
        with self.assertRaisesRegex(RUNNER.Reject, "mode differs"):
            self._anchor(expected_phase_a_sha256=digest)

    def test_anchor_rejects_directory_binding_substitution(self) -> None:
        self._phase_a()
        evidence = self.external_root / "evidence" / RUNNER.PHASE_A_RECORD
        original = json.loads(evidence.read_text(encoding="utf-8"))
        for field in ("st_dev", "st_ino", "st_uid"):
            with self.subTest(field=field):
                digest = self._rewrite_phase_record(
                    lambda value, field=field: value["observations"]["external_root_binding"].__setitem__(field, value["observations"]["external_root_binding"][field] + 1)
                )
                with self.assertRaisesRegex(RUNNER.Reject, "external.root"):
                    self._anchor(expected_phase_a_sha256=digest)
                evidence.unlink()
                RUNNER._publish_record(evidence, original)

    def test_anchor_rejects_runtime_directory_replacement(self) -> None:
        self._phase_a()
        review = self.external_root / "external-review"
        moved = self.external_root / "external-review-old"
        review.rename(moved)
        review.mkdir(mode=0o700)
        with self.assertRaisesRegex(RUNNER.Reject, "runtime directory binding"):
            self._anchor()

    def test_anchor_rejects_owner_marker_mutation(self) -> None:
        self._phase_a()
        digest = self._phase_sha()
        marker = self.external_root / "phase-a" / ".owner"
        with marker.open("ab") as stream:
            stream.write(b" \n")
            stream.flush()
            os.fsync(stream.fileno())
        with self.assertRaisesRegex(RUNNER.Reject, "owner marker"):
            self._anchor(expected_phase_a_sha256=digest)

    def test_anchor_rejects_same_length_owner_marker_substitution(self) -> None:
        self._phase_a()
        digest = self._phase_sha()
        marker = self.external_root / "phase-a" / ".owner"
        raw = marker.read_bytes()
        offset = raw.index(b"not-implemented")
        replacement = b"x" * len(b"not-implemented")
        with marker.open("r+b") as stream:
            stream.seek(offset)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        self.assertEqual(marker.stat().st_size, len(raw))
        with self.assertRaisesRegex(RUNNER.Reject, "canonical bytes changed"):
            self._anchor(expected_phase_a_sha256=digest)

    def test_anchor_rejects_identical_owner_marker_inode_replacement(self) -> None:
        self._phase_a()
        digest = self._phase_sha()
        marker = self.external_root / "phase-a" / ".owner"
        original = RUNNER.stable_read(marker, "original owner marker")
        marker.unlink()
        replacement = RUNNER._publish_bytes(marker, original.raw, "replacement owner marker")
        self.assertEqual(replacement.sha256, original.sha256)
        self.assertNotEqual(replacement.identity["st_ino"], original.identity["st_ino"])
        with self.assertRaisesRegex(RUNNER.Reject, "owner marker observation changed"):
            self._anchor(expected_phase_a_sha256=digest)

    def test_exact_pins_and_verified_module_objects_are_installed(self) -> None:
        for relative, (expected_sha256, _blob) in RUNNER.SOURCE_PINS.items():
            raw = (self.checkout / relative).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected_sha256)
        self.assertEqual(
            self.modules.phase_a.validate_artifacts.__code__.co_filename,
            os.fspath((self.checkout / RUNNER.PHASE_A_REL).resolve()),
        )
        self.assertIs(self.modules.lifecycle.PHASE_B.REVIEW, self.modules.git_reviewer)
        self.assertEqual(
            RUNNER._trusted_git_state(),
            (
                self.modules.git_reviewer.CANDIDATE5_GIT_BINDING.identity,
                self.modules.git_reviewer.CANDIDATE5_GIT_BINDING.sha256,
            ),
        )
        self.assertEqual(
            self.modules.git_reviewer.CANDIDATE5_CANONICAL_CONFIG,
            b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n\thooksPath = /dev/null\n[protocol]\n\tallow = never\n",
        )

    def test_source_has_no_legacy_temporary_authority_or_live_operation(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("/private/" + "tmp", source)
        self.assertIn('EXTERNAL_ROOT = Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v2")', source)
        self.assertFalse(os.path.lexists(Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v2")))
        for forbidden in ("--execute", "socket.", "hermes_agent", "git push"):
            self.assertNotIn(forbidden, source.lower())

    def test_record_parser_rejects_duplicate_fields(self) -> None:
        self._phase_a()
        evidence = self.external_root / "evidence" / RUNNER.PHASE_A_RECORD
        duplicate = b'{"schema":"' + RUNNER.EVIDENCE_SCHEMA.encode() + b'","schema":"x","stage":"phase-a","prior_sha256":"' + b"0" * 64 + b'","inputs":{},"observations":{},"safety":{}}\n'
        with evidence.open("wb") as stream:
            stream.write(duplicate)
            stream.flush()
            os.fsync(stream.fileno())
        snapshot = RUNNER.stable_read(evidence, "duplicate evidence")
        with self.assertRaisesRegex(RUNNER.Reject, "duplicate key"):
            RUNNER._parse_closed_record(snapshot, "phase-a")

    def test_record_write_failure_removes_the_owned_partial_inode(self) -> None:
        parent = Path(self.temporary.name) / "record-parent"
        parent.mkdir(mode=0o700)
        target = parent / "record.json"
        genuine_fsync = os.fsync
        calls = 0

        def fail_first_fsync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected file fsync failure")
            return genuine_fsync(descriptor)

        with mock.patch.object(RUNNER.os, "fsync", side_effect=fail_first_fsync):
            with self.assertRaisesRegex(OSError, "injected file fsync failure"):
                RUNNER._publish_record(target, {"test": True})
        self.assertFalse(os.path.lexists(target))

    def _verify_guarded_with(self, *, head=None, tree=None, status=b"", worktrees=None, git_paths=None):
        observation = self._guarded_observation()
        full = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        identities = {
            RUNNER.REPOSITORY_ROOT: full,
            RUNNER.REPOSITORY_ROOT.parent: {**full, "st_ino": 5},
            RUNNER.SOURCE_REPOSITORY_ROOT: {**full, "st_ino": 6},
            RUNNER.GIT_COMMON_DIR: {**full, "st_ino": 7},
            RUNNER.GIT_OBJECT_DIR: {**full, "st_ino": 8},
            RUNNER.GIT_WORKTREE_DIR: {**full, "st_ino": 9},
        }
        valid_worktrees = (
            b"worktree " + os.fspath(RUNNER.REPOSITORY_ROOT).encode() + b"\0"
            b"HEAD " + RUNNER.FROZEN_COMMIT.encode() + b"\0"
            b"detached\0\0"
        )
        paths = {
            "git_dir": RUNNER.GIT_WORKTREE_DIR,
            "common": RUNNER.GIT_COMMON_DIR,
            "objects": RUNNER.GIT_OBJECT_DIR,
            **(git_paths or {}),
        }

        def git(_root, _binding, *args):
            if args == ("rev-parse", "--show-toplevel"):
                return os.fspath(RUNNER.REPOSITORY_ROOT).encode()
            if args == ("rev-parse", "HEAD"):
                return (head or RUNNER.FROZEN_COMMIT).encode()
            if args == ("rev-parse", "HEAD^{tree}"):
                return (tree or RUNNER.FROZEN_TREE).encode()
            if args == ("rev-parse", "--git-dir"):
                return os.fspath(paths["git_dir"]).encode()
            if args == ("rev-parse", "--git-common-dir"):
                return os.fspath(paths["common"]).encode()
            if args == ("rev-parse", "--git-path", "objects"):
                return os.fspath(paths["objects"]).encode()
            if args == ("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"):
                return status
            if args == ("worktree", "list", "--porcelain", "-z"):
                return valid_worktrees if worktrees is None else worktrees
            if len(args) == 2 and args[0] == "rev-parse" and ":" in args[1]:
                relative = Path(args[1].split(":", 1)[1])
                return RUNNER.SOURCE_PINS[relative][1].encode()
            raise AssertionError(args)

        def directory(path, _label, exact_mode=None):
            self.assertIn(Path(path), identities)
            return identities[Path(path)]

        with mock.patch.object(RUNNER, "_git", side_effect=git), mock.patch.object(
            RUNNER, "_directory_identity", side_effect=directory
        ):
            return RUNNER.verify_frozen_repository(object())

    def test_guarded_worktree_contract_accepts_exact_observation(self) -> None:
        self.assertEqual(self._verify_guarded_with()["head"], RUNNER.FROZEN_COMMIT)

    def test_guarded_worktree_rejects_primary_and_alternate_paths(self) -> None:
        with self.assertRaisesRegex(RUNNER.Reject, "path differs"):
            RUNNER.verify_frozen_repository(object(), RUNNER.AUTHORITY_REPOSITORY_ROOT)
        with self.assertRaisesRegex(RUNNER.Reject, "path differs"):
            RUNNER.verify_frozen_repository(object(), Path("/home/kayg/Developer/alternate"))

    def test_guarded_worktree_rejects_dirty_wrong_input_and_unregistered(self) -> None:
        with self.assertRaisesRegex(RUNNER.Reject, "not clean including ignored"):
            self._verify_guarded_with(status=b"!! ignored-cache\0")
        with self.assertRaisesRegex(RUNNER.Reject, "HEAD differs"):
            self._verify_guarded_with(head="f" * 40)
        with self.assertRaisesRegex(RUNNER.Reject, "tree differs"):
            self._verify_guarded_with(tree="e" * 40)
        with self.assertRaisesRegex(RUNNER.Reject, "not one registered"):
            self._verify_guarded_with(worktrees=b"worktree /home/kayg/Developer/other\0\0")

    def test_guarded_worktree_rejects_branch_attachment(self) -> None:
        attached = (
            b"worktree " + os.fspath(RUNNER.REPOSITORY_ROOT).encode() + b"\0"
            b"HEAD " + RUNNER.FROZEN_COMMIT.encode() + b"\0"
            b"branch refs/heads/codex/397-guarded-replay\0\0"
        )
        with self.assertRaisesRegex(RUNNER.Reject, "not exact detached"):
            self._verify_guarded_with(worktrees=attached)

    def test_guarded_worktree_rejects_different_git_storage(self) -> None:
        for field, message in (("git_dir", "Git directory"), ("common", "common directory"), ("objects", "object directory")):
            with self.subTest(field=field), self.assertRaisesRegex(RUNNER.Reject, message):
                self._verify_guarded_with(git_paths={field: Path("/home/kayg/Developer/different")})

    def test_guarded_worktree_rejects_symlink_and_external_overlap(self) -> None:
        target = Path(self.temporary.name) / "directory"
        target.mkdir(mode=0o700)
        link = Path(self.temporary.name) / "link"
        link.symlink_to(target)
        with self.assertRaisesRegex(RUNNER.Reject, "canonical"):
            RUNNER._directory_identity(link, "symlink guarded worktree")
        with mock.patch.object(RUNNER, "EXTERNAL_ROOT", RUNNER.REPOSITORY_ROOT / "external"):
            with self.assertRaisesRegex(RUNNER.Reject, "overlaps"):
                self._verify_guarded_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
