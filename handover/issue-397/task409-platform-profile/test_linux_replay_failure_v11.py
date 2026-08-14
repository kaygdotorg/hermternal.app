#!/usr/bin/env python3
"""Test the verified failure-v11 public-loader repair without replay."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_replay_failure_v11 as FAILURE  # noqa: E402

DURABLE_ANCHOR_SHA256 = "60692a0c9bb81ddb663fa20f74819e0db6e9a87f4d9d6e63faecd351ca811da2"
FAILURE_V10_ROOT = Path("/home/kayg/Developer/hermternal-issue397-replay-failure-v10")
FAILURE_V11_ROOT = Path("/home/kayg/Developer/hermternal-issue397-replay-failure-v11")
FAILURE_V11_EVIDENCE_SHA256 = "e80411452d17c6129fc2d67eb242af50ed569e330c5b87181433d4feb2d34480"
FAILURE_V11_OWNER_SHA256 = "36a9ee391f0ab20706d3c93e59c4b65186ac545f222c8b7b49108ae324e27ab4"


class FailureV11Tests(unittest.TestCase):
    def failure_root_state(self):
        """Return the exact retained failure identity without changing it."""
        if not FAILURE_V11_ROOT.exists():
            return None
        root = os.lstat(FAILURE_V11_ROOT)
        self.assertTrue(stat.S_ISDIR(root.st_mode))
        self.assertEqual(stat.S_IMODE(root.st_mode), 0o700)
        evidence = FAILURE._stable_bytes(
            FAILURE_V11_ROOT / "replay-failure.json",
            FAILURE_V11_EVIDENCE_SHA256,
            "retained failure-v11 evidence",
        )
        owner = FAILURE._stable_bytes(
            FAILURE_V11_ROOT / ".owner", FAILURE_V11_OWNER_SHA256,
            "retained failure-v11 owner",
        )
        return (
            root.st_dev, root.st_ino, root.st_uid, root.st_gid, root.st_mode,
            root.st_nlink, hashlib.sha256(evidence).hexdigest(),
            hashlib.sha256(owner).hexdigest(),
        )

    def test_exact_sources_and_distinct_absent_failure_root(self) -> None:
        failure_state = self.failure_root_state()
        self.assertEqual(hashlib.sha256(FAILURE.V10_PATH.read_bytes()).hexdigest(), FAILURE.V10_SHA256)
        self.assertEqual(
            hashlib.sha256(FAILURE.PHASE_A_V11_PATH.read_bytes()).hexdigest(),
            FAILURE.PHASE_A_V11_SHA256,
        )
        for name, digest in FAILURE.DEPENDENCY_PINS:
            self.assertEqual(hashlib.sha256((HERE / f"{name}.py").read_bytes()).hexdigest(), digest)
        self.assertEqual(FAILURE.DIRECTORY_NAME, FAILURE_V11_ROOT.name)
        self.assertNotEqual(FAILURE_V10_ROOT, FAILURE_V11_ROOT)
        self.assertFalse(FAILURE_V10_ROOT.exists())
        self.assertEqual(self.failure_root_state(), failure_state)

    def test_stable_reader_rejects_symlink_digest_and_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix=".failure-v11-reader-") as parent:
            root = Path(parent)
            source = root / "source.py"
            source.write_bytes(b"value = 1\n")
            link = root / "link.py"
            link.symlink_to(source.name)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with self.assertRaises(OSError):
                FAILURE._stable_bytes(link, digest, "linked source")
            with self.assertRaisesRegex(RuntimeError, "SHA-256 differs"):
                FAILURE._stable_bytes(source, "0" * 64, "changed source")
            replacement = root / "replacement.py"
            replacement.write_bytes(source.read_bytes())
            real_lstat = os.lstat

            def replace_before_identity(path):
                os.replace(replacement, source)
                return real_lstat(path)

            with mock.patch.object(FAILURE.os, "lstat", side_effect=replace_before_identity):
                with self.assertRaisesRegex(RuntimeError, "changed during read"):
                    FAILURE._stable_bytes(source, digest, "replaced source")

    def test_fresh_process_disposable_phase_anchor_public_load(self) -> None:
        failure_state = self.failure_root_state()
        script = r'''
import hashlib
import json
import os
import sys
import tempfile
import types
from pathlib import Path

import linux_replay_failure_v11 as failure
from test_linux_phase_a_v11 import PhaseAV11Tests

module_poisons = {}
for dependency_name in failure.TRACKED_MODULE_NAMES:
    dependency_poison = types.ModuleType(dependency_name)
    def reject_attribute(_name, dependency=dependency_name):
        raise RuntimeError("POISON_DEPENDENCY_EXECUTED:" + dependency)
    dependency_poison.__getattr__ = reject_attribute
    module_poisons[dependency_name] = dependency_poison
    sys.modules[dependency_name] = dependency_poison
_probe_outer, probe_phase = failure._load_authenticated()
probe_runner = probe_phase.load_runner()
assert all(sys.modules[name] is value for name, value in module_poisons.items())
with tempfile.TemporaryDirectory(
    prefix=".failure-v11-phase-", dir=probe_runner.REPOSITORY_ROOT.parent
) as parent:
    failure.PHASE_EXTERNAL_ROOT = Path(parent) / "external"
    outer, phase = failure._load_authenticated()
    assert phase is not module_poisons["issue397_linux_phase_a_v11_failure_v11_verified"]
    assert all(sys.modules[name] is value for name, value in module_poisons.items())
    runner = phase.load_runner()
    assert runner.EXTERNAL_ROOT == failure.PHASE_EXTERNAL_ROOT
    verifier = lambda: PhaseAV11Tests().guarded(runner)
    modules = runner.load_modules()
    phase_record = runner.phase_a(
        modules, repository_root=runner.REPOSITORY_ROOT,
        external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier,
    )
    phase_snapshot = runner.stable_read(
        runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, "phase evidence"
    )
    anchor_record = runner.anchor(
        modules, repository_root=runner.REPOSITORY_ROOT,
        external_root=runner.EXTERNAL_ROOT,
        expected_phase_a_sha256=phase_snapshot.sha256,
        worktree_verifier=verifier,
    )
    anchor_snapshot = runner.stable_read(
        runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD, "anchor evidence"
    )
    wrapper, _authority = outer.load_approved_wrapper(anchor_snapshot.sha256)
    base = phase._load_v10()
    nested = base._load_v8()._load_v7()._load_v3().load_runner()
    for name in ("_parse_closed_record", "_validate_evidence"):
        values = getattr(nested, name).__globals__
        assert values["SCHEMA"] == failure.PHASE_SCHEMA
        assert values["EVIDENCE_SCHEMA"] == failure.PHASE_EVIDENCE_SCHEMA
    assert all(sys.modules[name] is value for name, value in module_poisons.items())
    print(json.dumps({
        "phase_schema": phase_record["schema"],
        "anchor_prior": anchor_record["prior_sha256"],
        "phase_sha256": phase_snapshot.sha256,
        "runner_sha256": wrapper.PHASE_A_RUNNER_SHA256,
    }, sort_keys=True))
'''
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.fspath(HERE)
        result = subprocess.run(
            [sys.executable, "-B", "-c", script], cwd=HERE,
            env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(record["phase_schema"], FAILURE.PHASE_EVIDENCE_SCHEMA)
        self.assertEqual(record["anchor_prior"], record["phase_sha256"])
        self.assertEqual(record["runner_sha256"], FAILURE.PHASE_A_V11_SHA256)
        self.assertFalse(FAILURE_V10_ROOT.exists())
        self.assertEqual(self.failure_root_state(), failure_state)

    def test_fresh_process_reads_current_durable_anchor_without_publication(self) -> None:
        failure_state = self.failure_root_state()
        script = (
            "import json, pathlib, linux_replay_failure_v11 as f; "
            f"w,a=f.load_approved_wrapper('{DURABLE_ANCHOR_SHA256}'); "
            "print(json.dumps({'path':str(w.PHASE_A_RUNNER_PATH),"
            "'sha':w.PHASE_A_RUNNER_SHA256,'callable':callable(w.execute_and_publish)}))"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.fspath(HERE)
        result = subprocess.run(
            [sys.executable, "-B", "-c", script], cwd=HERE,
            env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout.splitlines()[-1])
        self.assertTrue(record["callable"])
        self.assertEqual(record["sha"], FAILURE.PHASE_A_V11_SHA256)
        self.assertEqual(Path(record["path"]), FAILURE.PHASE_A_V11_PATH)
        self.assertFalse(FAILURE_V10_ROOT.exists())
        self.assertEqual(self.failure_root_state(), failure_state)


if __name__ == "__main__":
    unittest.main(verbosity=2)
