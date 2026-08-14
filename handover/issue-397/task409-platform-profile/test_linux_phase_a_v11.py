#!/usr/bin/env python3
"""Run disposable v11 Phase A-to-anchor and the outer failure loader."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_phase_a_v11 as V11  # noqa: E402
import linux_replay_failure_v10 as FAILURE  # noqa: E402
import linux_replay_wrapper_v7 as WRAPPER  # noqa: E402
import linux_retained_driver_v7 as DRIVER  # noqa: E402
import object_preservation as POLICY  # noqa: E402


class PhaseAV11Tests(unittest.TestCase):
    def guarded(self, runner):
        identity = {
            "st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(),
            "st_mode": 0o700, "st_size": 4096, "st_nlink": 2,
            "st_mtime_ns": 3, "st_ctime_ns": 4,
        }
        binding = runner._binding_record(identity)
        return {
            "path": str(runner.REPOSITORY_ROOT), "binding": binding,
            "parent_binding": {**binding, "st_ino": 5}, "head": runner.FROZEN_COMMIT,
            "tree": runner.FROZEN_TREE, "detached": True,
            "source_repository": {"path": str(runner.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}},
            "git_common_dir": {"path": str(runner.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}},
            "git_object_dir": {"path": str(runner.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}},
            "git_worktree_dir": {"path": str(runner.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}},
        }

    def test_production_paths_are_closed_over_v11_root(self) -> None:
        root = Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11")
        runner = V11.load_runner()
        self.assertEqual(runner.EXTERNAL_ROOT, root)
        self.assertEqual(runner.phase_a.__globals__["SCHEMA"], V11.V11_SCHEMA)
        self.assertEqual(runner.phase_a.__globals__["EVIDENCE_SCHEMA"], V11.V11_EVIDENCE_SCHEMA)
        paths = {
            "phase": root / "evidence" / runner.PHASE_A_RECORD,
            "anchor": root / "evidence" / runner.ANCHOR_RECORD,
            "owner": root / "phase-a/.owner",
            "manifest": root / "phase-a/input-manifest.json",
            "approval": root / "external-review" / runner.ANCHOR_NAME,
        }
        self.assertEqual({name: os.fspath(path) for name, path in paths.items()}, {
            "phase": "/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11/evidence/phase-a.json",
            "anchor": "/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11/evidence/anchor.json",
            "owner": "/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11/phase-a/.owner",
            "manifest": "/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11/phase-a/input-manifest.json",
            "approval": "/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11/external-review/phase-a-approval-anchor.json",
        })
        v10_runner = V11.predecessor.load_runner()
        self.assertEqual(
            v10_runner.EXTERNAL_ROOT,
            Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v10"),
        )
        failure_root = Path("/home/kayg/Developer") / FAILURE.DIRECTORY_NAME
        self.assertEqual(failure_root.name, "hermternal-issue397-replay-failure-v10")
        self.assertNotEqual(failure_root, root)

        base = V11._load_v10()
        v8 = base._load_v8()
        v7 = v8._load_v7()
        v3 = v7._load_v3()
        for module in (base, v8, v7, v3):
            self.assertEqual(module.load_runner().EXTERNAL_ROOT, root)
        observed = []

        def approved(_anchor_sha256, _adapter_sha256):
            observed.append(v3.load_runner().EXTERNAL_ROOT)
            return types.SimpleNamespace(), object()

        v3.load_approved_wrapper = approved
        v7._load_v3 = lambda: v3
        v8._load_v7 = lambda: v7
        base._load_v8 = lambda: v8
        with mock.patch.object(V11, "_load_v10", return_value=base):
            wrapper, _authority = V11.load_approved_wrapper("0" * 64, V11._adapter_sha256())
        self.assertEqual(observed, [root])
        self.assertEqual(wrapper.PHASE_A_RUNNER_PATH, Path(V11.__file__))
    def test_disposable_phase_anchor_and_outer_failure_load(self) -> None:
        self.assertEqual(hashlib.sha256(V11.V10_PATH.read_bytes()).hexdigest(), V11.V10_SHA256)
        self.assertFalse(WRAPPER.preflight()["execution_enabled"])
        base = V11._load_v10()
        runner = base.load_runner()
        with tempfile.TemporaryDirectory(
            prefix=".phase-a-v11-test-", dir=Path(runner.REPOSITORY_ROOT).parent
        ) as parent:
            runner.EXTERNAL_ROOT = Path(parent) / "external"
            modules = runner.load_modules()
            verifier = lambda: self.guarded(runner)
            phase = runner.phase_a(
                modules, repository_root=runner.REPOSITORY_ROOT,
                external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier
            )
            phase_snapshot = runner.stable_read(
                runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, "phase"
            )
            owner_path = runner.EXTERNAL_ROOT / "phase-a" / ".owner"
            owner_snapshot = runner.stable_read(owner_path, "Phase A owner")
            owner_state = os.lstat(owner_path)
            self.assertTrue(stat.S_ISREG(owner_state.st_mode))
            self.assertEqual(stat.S_IMODE(owner_state.st_mode), 0o600)
            self.assertEqual(owner_state.st_nlink, 1)
            self.assertEqual(dict(owner_snapshot.identity), runner._identity(owner_state))
            self.assertEqual(owner_snapshot, runner.stable_read(owner_path, "Phase A owner repeat"))
            self.assertEqual(owner_snapshot.sha256, hashlib.sha256(owner_snapshot.raw).hexdigest())
            owner = json.loads(owner_snapshot.raw)
            self.assertEqual(
                owner_snapshot.raw,
                (json.dumps(owner, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            )
            self.assertEqual(
                set(owner), {"executor", "kind", "read_only", "schema", "uid", "platform_profile"}
            )
            profile = owner["platform_profile"]
            self.assertEqual(set(profile), {
                "profile_id", "profile_path", "profile_sha256", "phase_a_adapter_sha256",
                "linux_wrapper_adapter_sha256", "linux_driver_adapter_sha256",
                "forbidden_proof", "forbidden_proof_sha256", "section_anchor",
                "object_preservation", "object_preservation_sha256",
                "object_preservation_policy_sha256",
            })
            preservation = profile["object_preservation"]
            self.assertEqual(set(preservation), {
                "schema", "typed_count", "typed_counts", "typed_inventory_sha256",
                "independent_roots", "independent_roots_sha256", "present_forbidden",
                "missing_proved", "final_head",
            })
            self.assertEqual(set(preservation["typed_counts"]), {"blob", "commit", "tree"})
            self.assertEqual(preservation["typed_count"], 563)
            self.assertEqual(
                POLICY.record_sha256(preservation), profile["object_preservation_sha256"]
            )
            policy_snapshot = runner.stable_read(DRIVER.POLICY_PATH, "preservation policy")
            self.assertEqual(policy_snapshot.sha256, DRIVER.POLICY_SHA256)
            self.assertEqual(
                profile["object_preservation_policy_sha256"], policy_snapshot.sha256
            )
            marker = phase["observations"]["owner_marker"]
            self.assertEqual(set(marker), {
                "path", "identity", "bytes", "sha256", "lf_count",
                "terminal_byte_hex", "content",
            })
            self.assertEqual(marker["path"], os.fspath(owner_path))
            self.assertEqual(marker["identity"], dict(owner_snapshot.identity))
            self.assertEqual(marker["bytes"], len(owner_snapshot.raw))
            self.assertEqual(marker["sha256"], owner_snapshot.sha256)
            self.assertEqual(marker["content"], owner)
            anchor = runner.anchor(
                modules, repository_root=runner.REPOSITORY_ROOT,
                external_root=runner.EXTERNAL_ROOT,
                expected_phase_a_sha256=phase_snapshot.sha256,
                worktree_verifier=verifier
            )
            anchor_snapshot = runner.stable_read(
                runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD, "anchor"
            )
            v8 = base._load_v8()
            v7 = v8._load_v7()
            v3 = v7._load_v3()
            v3.load_runner = lambda: runner
            v7._load_v3 = lambda: v3
            v8._load_v7 = lambda: v7
            base._load_v8 = lambda: v8
            with mock.patch.object(V11, "_load_v10", return_value=base):
                wrapper, _authority = V11.load_approved_wrapper(
                    anchor_snapshot.sha256, V11._adapter_sha256()
                )
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                FAILURE.load_approved_wrapper("0" * 64)
        self.assertEqual(phase["schema"], V11.V11_EVIDENCE_SCHEMA)
        self.assertEqual(anchor["prior_sha256"], phase_snapshot.sha256)
        self.assertEqual(
            profile["object_preservation_sha256"],
            "8aea6f4fcc34388362fff8840518d61f39ca8565548dc1b63e78de31101631c3",
        )
        self.assertTrue(callable(wrapper.execute_and_publish))
        self.assertEqual(wrapper.PHASE_A_RUNNER_PATH, Path(V11.__file__))


if __name__ == "__main__":
    unittest.main(verbosity=2)
