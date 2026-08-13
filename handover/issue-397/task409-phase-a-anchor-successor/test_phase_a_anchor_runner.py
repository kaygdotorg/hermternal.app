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

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def _phase_a(self, **kwargs):
        return RUNNER.phase_a(
            self.modules,
            repository_root=self.checkout,
            external_root=self.external_root,
            **kwargs,
        )

    def _anchor(self, **kwargs):
        return RUNNER.anchor(
            self.modules,
            repository_root=self.checkout,
            external_root=self.external_root,
            **kwargs,
        )

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
        self.assertEqual(anchor_snapshot.raw, RUNNER._canonical_json(anchor_record))
        self.assertTrue(anchor_snapshot.raw.endswith(b"\n"))
        self.assertFalse(anchor_snapshot.raw.endswith(b"\n\n"))

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
        self.assertEqual(RUNNER.EXTERNAL_ROOT, Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor"))
        self.assertFalse(os.path.lexists(RUNNER.EXTERNAL_ROOT))
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
