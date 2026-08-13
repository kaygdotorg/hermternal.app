#!/usr/bin/env python3
"""Regressions for genuine durable Phase A and Phase B lifecycle calls."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


LIFECYCLE = load("issue397_lifecycle_tests", HERE / "phase_b_lifecycle_successor.py")
FIXTURE = load("issue397_lifecycle_fixture", HERE / "candidate5_phase_a_fixture.py")


class Guard:
    def __init__(self, identity):
        self.identity = identity
    def assert_stable(self):
        return None


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="issue397-lifecycle-")
        self.base = Path(self.temp.name).resolve()
        self.authority_root = self.base / "approved-candidate-five"
        self.replay_root = self.base / "replay-root"
        self.repository = self.base / "repository"
        self.anchor_root = self.base / "anchor-root"
        for path in (self.authority_root, self.replay_root, self.repository, self.anchor_root):
            path.mkdir(mode=0o700)
        self.manifest, self.paths = FIXTURE.build(self.authority_root, LIFECYCLE.PHASE_A)
        self.manifest_path = self.base / "phase-a-manifest.json"
        self.anchor_path = self.anchor_root / "phase-a-anchor.json"
        self.result_path = self.replay_root / "replay-result.json"
        self._write_json(self.manifest_path, self.manifest)
        self.manifest_sha = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        self.approval_digest = LIFECYCLE.PHASE_A.phase_a_approval_digest(self.manifest)
        self.policy_sha = LIFECYCLE.PHASE_A.policy_digest(self.manifest["policy"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _write_json(path: Path, value) -> None:
        path.write_bytes((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
        path.chmod(0o600)

    @staticmethod
    def _dir_identity(path: Path) -> dict[str, int]:
        st = os.lstat(path)
        return {"st_dev": st.st_dev, "st_ino": st.st_ino, "st_uid": st.st_uid, "st_mode": stat.S_IMODE(st.st_mode), "st_nlink": st.st_nlink}

    def _write_result(self) -> tuple[str, str, str]:
        head, parent, tree = "a" * 40, "b" * 40, "c" * 40
        policy = self.manifest["policy"]
        result = {
            "schema": LIFECYCLE.PHASE_B.RESULT_SCHEMA, "phase": LIFECYCLE.PHASE_B.RESULT_PHASE,
            "lane": LIFECYCLE.PHASE_B.LANE, "phase_a_manifest_sha256": self.manifest_sha,
            "phase_a_approval_digest": self.approval_digest, "replay_root": str(self.replay_root),
            "replay_root_identity": self._dir_identity(self.replay_root), "repository": str(self.repository),
            "repository_identity": self._dir_identity(self.repository), "head_state": "detached",
            "final_head": head, "parent": parent, "tree": tree, "base_commit": policy["base_commit"],
            "base_tree": policy["base_tree"], "protected_main_commit": policy["main_commit"],
            "required_ancestors": list(policy["required_ancestors"]), "forbidden_ancestors": list(policy["forbidden_ancestors"]),
        }
        self._write_json(self.result_path, result)
        result["replay_root_identity"] = self._dir_identity(self.replay_root)
        self._write_json(self.result_path, result)
        return head, parent, tree

    @contextmanager
    def _git_boundary(self, on_inspect=None):
        identity = SimpleNamespace(root=self.repository)
        guard = Guard(identity)
        repo_identity = self._dir_identity(self.repository)
        def inspect(*_args, **_kwargs):
            if on_inspect is not None:
                on_inspect()
            return identity
        with patch.object(LIFECYCLE.PHASE_B.REVIEW, "inspect_metadata", side_effect=inspect), patch.object(
            LIFECYCLE.PHASE_B.REVIEW, "RepoGuard", return_value=guard
        ), patch.object(LIFECYCLE.PHASE_B.REVIEW, "directory_identity", return_value=repo_identity), patch.object(
            LIFECYCLE.PHASE_B.REVIEW, "_check_repo_shape"
        ), patch.object(LIFECYCLE.PHASE_B.REVIEW, "_check_origin_and_base"), patch.object(
            LIFECYCLE.PHASE_B.REVIEW, "check_worktree_registry"
        ), patch.object(LIFECYCLE.PHASE_B.REVIEW, "check_clean"), patch.object(
            LIFECYCLE.PHASE_B.REVIEW, "check_index_flags"
        ), patch.object(LIFECYCLE.PHASE_B.REVIEW, "_check_fsck"), patch.object(
            LIFECYCLE.PHASE_B.REVIEW, "_check_explicit_closure"
        ), patch.object(LIFECYCLE.PHASE_B.REVIEW, "_check_ancestry"), patch.object(
            LIFECYCLE.PHASE_B, "_derive_identity", side_effect=lambda _r, claims, _g: {"final_head": claims[0], "parent": claims[1], "tree": claims[2]}
        ), patch.object(LIFECYCLE.PHASE_B, "_raw_head_from_snapshot", return_value="a" * 40):
            yield

    def _anchor(self):
        return LIFECYCLE.provision_external_anchor(
            self.manifest_path, self.anchor_path, self.authority_root,
            manifest_sha256=self.manifest_sha, approval_digest=self.approval_digest, policy_sha256=self.policy_sha,
        )

    def _phase_b(self):
        return LIFECYCLE.validate_genuine_phase_b(
            self.result_path, self.replay_root, self.repository, self.manifest_path, self.anchor_path, self.authority_root,
            manifest_sha256=self.manifest_sha, approval_digest=self.approval_digest,
        )

    def test_genuine_durable_validator_calls_exactly_one_plus_one(self) -> None:
        self.assertEqual(Path(LIFECYCLE.ANCHOR.PHASE_A.validate_artifacts.__code__.co_filename).resolve(), LIFECYCLE.PHASE_A_PATH)
        self.assertEqual(Path(LIFECYCLE.PHASE_B.PHASE_A.validate_artifacts.__code__.co_filename).resolve(), LIFECYCLE.PHASE_A_PATH)
        anchor_original = LIFECYCLE.ANCHOR.PHASE_A.validate_artifacts
        phase_b_original = LIFECYCLE.PHASE_B.PHASE_A.validate_artifacts
        calls = {"anchor": 0, "phase_b": 0}
        def anchor_counted(manifest):
            calls["anchor"] += 1
            return anchor_original(manifest)
        def phase_b_counted(manifest):
            calls["phase_b"] += 1
            return phase_b_original(manifest)
        with patch.object(LIFECYCLE.ANCHOR.PHASE_A, "validate_artifacts", side_effect=anchor_counted), patch.object(
            LIFECYCLE.PHASE_B.PHASE_A, "validate_artifacts", side_effect=phase_b_counted
        ):
            self._anchor()
            self._write_result()
            with self._git_boundary():
                observed = self._phase_b()
        self.assertEqual(calls, {"anchor": 1, "phase_b": 1})
        self.assertEqual(observed["final_head"], "a" * 40)

    def test_valid_alternate_path_with_matching_bytes_digest_and_identity_rejects(self) -> None:
        alternate = self.base / "attacker-chosen.md"
        shutil.copyfile(self.paths["markdown"], alternate)
        alternate.chmod(0o600)
        changed = json.loads(json.dumps(self.manifest))
        changed["artifacts"]["markdown"] = {
            "path": str(alternate), "sha256": hashlib.sha256(alternate.read_bytes()).hexdigest(),
            "identity": LIFECYCLE.PHASE_A._identity(os.lstat(alternate)),
        }
        self._write_json(self.manifest_path, changed)
        supplied = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(LIFECYCLE.Reject, "independent authority"):
            LIFECYCLE.provision_external_anchor(self.manifest_path, self.anchor_path, self.authority_root, manifest_sha256=supplied, approval_digest=self.approval_digest, policy_sha256=self.policy_sha)
        self.assertFalse(self.anchor_path.exists())

    def test_duplicate_alias_and_alternate_root_reject(self) -> None:
        for mutation in ("duplicate", "alias", "root"):
            changed = json.loads(json.dumps(self.manifest))
            if mutation == "duplicate":
                changed["artifacts"]["json"] = dict(changed["artifacts"]["markdown"])
            elif mutation == "alias":
                changed["artifacts"]["shell"]["path"] = str(self.authority_root) + "/./candidate-five.sh"
            else:
                other = self.base / "other-root"
                other.mkdir(mode=0o700, exist_ok=True)
                changed["artifacts"]["shell"]["path"] = str(other / "candidate-five.sh")
            self._write_json(self.manifest_path, changed)
            with self.assertRaises(LIFECYCLE.Reject):
                LIFECYCLE.load_authorized_manifest(self.manifest_path, self.authority_root)

    def test_anchor_genuine_validator_bypass_sentinel_fails(self) -> None:
        def sentinel(_manifest):
            raise LIFECYCLE.ANCHOR.PHASE_A.Reject("anchor genuine validator sentinel")
        with patch.object(LIFECYCLE.ANCHOR.PHASE_A, "validate_artifacts", side_effect=sentinel):
            with self.assertRaisesRegex(LIFECYCLE.Reject, "anchor genuine validator sentinel"):
                self._anchor()
        self.assertFalse(self.anchor_path.exists())

    def test_phase_b_genuine_validator_bypass_sentinel_fails_before_git(self) -> None:
        self._anchor()
        self._write_result()
        git_called = False
        def sentinel(_manifest):
            raise LIFECYCLE.PHASE_B.PHASE_A.Reject("phase B genuine validator sentinel")
        def forbidden_git(*_args, **_kwargs):
            nonlocal git_called
            git_called = True
        with patch.object(LIFECYCLE.PHASE_B.PHASE_A, "validate_artifacts", side_effect=sentinel), patch.object(
            LIFECYCLE.PHASE_B.REVIEW, "inspect_metadata", side_effect=forbidden_git
        ):
            with self.assertRaisesRegex(LIFECYCLE.Reject, "phase B genuine validator sentinel"):
                self._phase_b()
        self.assertFalse(git_called)

    def test_post_auth_markdown_json_and_same_size_shell_swaps_reject_without_third_call(self) -> None:
        self._anchor()
        self._write_result()
        original_validator = LIFECYCLE.PHASE_B.PHASE_A.validate_artifacts
        for role in ("markdown", "json", "shell"):
            with self.subTest(role=role):
                calls = 0
                path = self.paths[role]
                moved = self.base / f"verified-{role}"
                replacement = self.base / f"replacement-{role}"
                original_raw = path.read_bytes()
                replacement_raw = bytes([original_raw[0] ^ 1]) + original_raw[1:]
                self.assertEqual(len(replacement_raw), len(original_raw))

                def counted(manifest):
                    nonlocal calls
                    calls += 1
                    return original_validator(manifest)

                def swap():
                    replacement.write_bytes(replacement_raw)
                    replacement.chmod(0o600)
                    os.rename(path, moved)
                    os.rename(replacement, path)

                with patch.object(LIFECYCLE.PHASE_B.PHASE_A, "validate_artifacts", side_effect=counted):
                    with self._git_boundary(on_inspect=swap):
                        with self.assertRaisesRegex(LIFECYCLE.Reject, f"{role} (hash|identity) changed"):
                            self._phase_b()
                self.assertEqual(calls, 1)
                os.unlink(path)
                os.rename(moved, path)

    def test_post_auth_authority_root_substitution_rejects_without_third_call(self) -> None:
        self._anchor()
        self._write_result()
        original_validator = LIFECYCLE.PHASE_B.PHASE_A.validate_artifacts
        calls = 0
        moved_root = self.base / "verified-authority-root"

        def counted(manifest):
            nonlocal calls
            calls += 1
            return original_validator(manifest)

        def swap_root():
            os.rename(self.authority_root, moved_root)
            self.authority_root.mkdir(mode=0o700)
            for role, name in LIFECYCLE.ROLE_NAMES.items():
                shutil.copyfile(moved_root / name, self.authority_root / name)
                (self.authority_root / name).chmod(0o600)

        with patch.object(LIFECYCLE.PHASE_B.PHASE_A, "validate_artifacts", side_effect=counted):
            with self._git_boundary(on_inspect=swap_root):
                with self.assertRaisesRegex(LIFECYCLE.Reject, "authority root changed"):
                    self._phase_b()
        self.assertEqual(calls, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
