#!/usr/bin/env python3
"""Phase A -> external approval anchor -> Phase B lifecycle regressions.

The current candidate-five Markdown/JSON/shell triad is not present in this
bundle, so the default lane creates three private, reviewed-byte fixtures and
uses a strict validator adapter for those bytes.  A future run can point
``TASK409_CANDIDATE_FIVE_TRIAD_JSON`` at a JSON object containing the final
triad paths and optional digests without changing the lifecycle assertions.

The Phase B reviewer is mocked only at the Git observation boundary.  The
manifest, anchor, replay-result, stable-file reads, digest checks, anchor
schema, and final Phase-A stability reread remain real.  No candidate shell,
network, replay, or Git subprocess runs in this harness.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, Mapping
from unittest.mock import Mock, patch


BUNDLE = Path(__file__).resolve().parent
TRIAD_CONFIG_ENV = "TASK409_CANDIDATE_FIVE_TRIAD_JSON"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Register dynamic modules before execution so Python 3.9 dataclasses can
    # resolve postponed annotations while loading the prepared helpers.
    import sys

    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ANCHOR = load_module(
    "task409_e2e_anchor_v3",
    BUNDLE / "provision_task409_phase_a_anchor_v3.py",
)
PHASE_B = load_module(
    "task409_e2e_phase_b_v3",
    BUNDLE / "task409_post_replay_identity_v3.py",
)


@dataclass(frozen=True)
class ReviewedArtifact:
    name: str
    path: Path
    sha256: str
    identity: dict[str, int]
    raw: bytes


@dataclass(frozen=True)
class ReviewedTriad:
    artifacts: Mapping[str, ReviewedArtifact]
    normalized_json_sha256: str

    def manifest_artifacts(self) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "path": str(item.path),
                "sha256": item.sha256,
                "identity": dict(item.identity),
            }
            for name, item in self.artifacts.items()
        }

    def shell_metadata(self) -> dict[str, Any]:
        shell = self.artifacts["shell"].raw
        return {
            "body_bytes": len(shell),
            "body_lines": shell.count(b"\n"),
            "terminal_byte_hex": shell[-1:].hex(),
        }


def _identity(path: Path) -> dict[str, int]:
    st = os.lstat(path)
    return {
        "st_dev": int(st.st_dev),
        "st_ino": int(st.st_ino),
        "st_uid": int(st.st_uid),
        "st_gid": int(st.st_gid),
        "st_mode": int(stat.S_IMODE(st.st_mode)),
        "st_size": int(st.st_size),
        "st_nlink": int(st.st_nlink),
    }


def _write_private(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256")
    if any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256")
    return value


def _artifact_from_path(name: str, path: Path, supplied_sha256: str | None = None) -> ReviewedArtifact:
    path = path.resolve()
    if not path.is_absolute() or str(path) != os.path.realpath(str(path)):
        raise ValueError(f"{name} fixture path must be canonical absolute")
    raw = path.read_bytes()
    actual_sha = _sha256(raw)
    if supplied_sha256 is not None and _require_sha(supplied_sha256, f"{name} digest") != actual_sha:
        raise ValueError(f"{name} supplied digest does not match reviewed bytes")
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{name} fixture must be a regular file")
    return ReviewedArtifact(name, path, actual_sha, _identity(path), raw)


def _config_artifact(config: Mapping[str, Any], name: str) -> tuple[Path, str | None]:
    value = config.get(name)
    if isinstance(value, str):
        return Path(value), None
    if isinstance(value, Mapping):
        path = value.get("path")
        digest = value.get("sha256")
        if not isinstance(path, str):
            raise ValueError(f"configured {name} artifact path is missing")
        if digest is not None and not isinstance(digest, str):
            raise ValueError(f"configured {name} artifact digest is invalid")
        return Path(path), digest
    raise ValueError(f"configured {name} artifact is missing")


def _load_reviewed_triad(base: Path) -> ReviewedTriad:
    """Load final triad facts when supplied, otherwise make private fixtures.

    The adapter is deliberately outside Phase A.  It supplies only the
    reviewed bytes, paths, and digests that the lifecycle test binds; it does
    not synthesize candidate identities, reviewer identities, or Git state.
    """
    configured = os.environ.get(TRIAD_CONFIG_ENV)
    if configured:
        config_path = Path(configured).resolve()
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, Mapping):
            raise ValueError("candidate-five triad configuration must be an object")
        artifacts: dict[str, ReviewedArtifact] = {}
        for name in ("markdown", "json", "shell"):
            path, digest = _config_artifact(config, name)
            artifacts[name] = _artifact_from_path(name, path, digest)
        normalized = config.get("normalized_json_sha256")
        if normalized is None:
            normalized = artifacts["json"].sha256
        normalized = _require_sha(normalized, "normalized JSON digest")
        return ReviewedTriad(artifacts, normalized)

    fixture_root = base / "synthetic-candidate-five-triad"
    fixture_root.mkdir(mode=0o700)
    raw_by_name = {
        "markdown": (
            b"# synthetic candidate-five reviewed matrix\n\n"
            b"This fixture stands in for the unavailable final Markdown triad.\n"
        ),
        "json": b'{"schema":"hermternal.task409.final-execution-matrix.v1","synthetic":true}\n',
        "shell": b"#!/bin/bash\nprintf '%s\\n' 'synthetic reviewed driver'\n",
    }
    artifacts = {}
    for name, raw in raw_by_name.items():
        path = fixture_root / f"candidate-five.{name}"
        _write_private(path, raw)
        artifacts[name] = _artifact_from_path(name, path)
    return ReviewedTriad(artifacts, artifacts["json"].sha256)


def _manifest_for(triad: ReviewedTriad) -> dict[str, Any]:
    phase_a = ANCHOR.PHASE_A
    policy = phase_a._expected_policy()
    return {
        "schema": phase_a.SCHEMA,
        "phase": phase_a.PHASE,
        "artifacts": triad.manifest_artifacts(),
        "shell_metadata": triad.shell_metadata(),
        "normalized_json_sha256": triad.normalized_json_sha256,
        "inputs": {
            "lane": phase_a.LANE,
            "object_format": "sha1",
            "base_ref": phase_a.BASE_REF,
            "base_commit": phase_a.BASE_COMMIT,
            "base_tree": phase_a.BASE_TREE,
            "main_ref": phase_a.MAIN_REF,
            "main_commit": phase_a.MAIN_COMMIT,
        },
        "stale": {
            "paths": list(phase_a.MANDATORY_STALE_PATHS),
            "hashes": list(phase_a.MANDATORY_STALE_HASHES),
        },
        "policy": policy,
        "approval": {
            "status": "consistency-only",
            "manifest_sha256": "not-bound-in-phase-a",
            "policy_sha256": phase_a.APPROVED_POLICY_SHA256,
        },
    }


def _write_json(path: Path, value: Mapping[str, Any], *, indent: int = 2) -> bytes:
    raw = (json.dumps(value, sort_keys=True, indent=indent) + "\n").encode("utf-8")
    _write_private(path, raw)
    return raw


def _replace_json(path: Path, value: Mapping[str, Any], *, indent: int) -> bytes:
    replacement = path.with_name(path.name + ".replacement")
    raw = _write_json(replacement, value, indent=indent)
    os.replace(replacement, path)
    path.chmod(0o600)
    return raw


class _FixtureValidation:
    """Strict Phase-A substitute for the unavailable candidate-five triad."""

    def __init__(self, triad: ReviewedTriad) -> None:
        self.triad = triad
        self.phase_a = ANCHOR.PHASE_A
        self.calls = 0

    def __call__(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        self.calls += 1
        if set(manifest) != self.phase_a.ROOT_KEYS:
            raise self.phase_a.Reject("synthetic Phase-A manifest fields differ")
        if manifest.get("schema") != self.phase_a.SCHEMA or manifest.get("phase") != self.phase_a.PHASE:
            raise self.phase_a.Reject("synthetic Phase-A schema differs")
        if manifest.get("artifacts") != self.triad.manifest_artifacts():
            raise self.phase_a.Reject("synthetic manifest is not bound to reviewed triad bytes")
        if manifest.get("shell_metadata") != self.triad.shell_metadata():
            raise self.phase_a.Reject("synthetic shell metadata differs")
        if manifest.get("normalized_json_sha256") != self.triad.normalized_json_sha256:
            raise self.phase_a.Reject("synthetic normalized JSON digest differs")
        policy = manifest.get("policy")
        if policy != self.phase_a._expected_policy():
            raise self.phase_a.Reject("synthetic Phase-A policy differs")
        return {"policy": policy}


class _FakeGuard:
    def __init__(self, identity: Any, calls: list[str]) -> None:
        self.identity = identity
        self.calls = calls

    def assert_stable(self) -> None:
        self.calls.append("guard.assert_stable")


class Task409PhaseABPostReplayE2ETests(unittest.TestCase):
    """Exercise the complete authenticated lifecycle without Git or replay."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="task409-e2e-", dir="/private/tmp")
        self.base = Path(self.temp.name).resolve()
        self.replay_root = self.base / "replay-root"
        self.repository = self.base / "repository-fixture"
        self.anchor_directory = self.base / "anchor-output"
        for directory in (self.replay_root, self.repository, self.anchor_directory):
            directory.mkdir(mode=0o700)

        self.manifest_path = self.base / "phase-a-manifest.json"
        self.anchor_path = self.anchor_directory / "phase-a-approval-anchor.json"
        self.result_path = self.replay_root / "replay-result.json"
        self.triad = _load_reviewed_triad(self.base)
        self.manifest = _manifest_for(self.triad)
        self.manifest_raw = _write_json(self.manifest_path, self.manifest)
        self.manifest_sha256 = _sha256(self.manifest_raw)
        self.approval_digest = ANCHOR.PHASE_A.phase_a_approval_digest(self.manifest)
        self.policy_sha256 = ANCHOR.PHASE_A.policy_digest(self.manifest["policy"])
        self.validator = _FixtureValidation(self.triad)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @contextmanager
    def _phase_a_validation(self) -> Iterator[_FixtureValidation]:
        # Anchor and Phase B load separate module instances.  Bind both to the
        # same reviewed-byte adapter so neither lane can silently use another
        # manifest interpretation.
        with patch.object(ANCHOR.PHASE_A, "validate_artifacts", side_effect=self.validator), patch.object(
            PHASE_B.PHASE_A, "validate_artifacts", side_effect=self.validator
        ):
            yield self.validator

    def _provision_anchor(self) -> dict[str, Any]:
        with self._phase_a_validation():
            return ANCHOR.provision_anchor(
                self.manifest_path,
                self.anchor_path,
                manifest_sha256=self.manifest_sha256,
                phase_a_approval_digest=self.approval_digest,
                policy_sha256=self.policy_sha256,
                decision=ANCHOR.DECISION,
            )

    @staticmethod
    def _directory_identity(path: Path) -> dict[str, int]:
        st = os.lstat(path)
        return {
            "st_dev": int(st.st_dev),
            "st_ino": int(st.st_ino),
            "st_uid": int(st.st_uid),
            "st_mode": int(stat.S_IMODE(st.st_mode)),
            "st_nlink": int(st.st_nlink),
        }

    def _write_replay_result(self) -> tuple[str, str, str]:
        final_head = "a" * 40
        parent = "b" * 40
        tree = "c" * 40
        policy = self.manifest["policy"]
        result = {
            "schema": PHASE_B.RESULT_SCHEMA,
            "phase": PHASE_B.RESULT_PHASE,
            "lane": PHASE_B.LANE,
            "phase_a_manifest_sha256": self.manifest_sha256,
            "phase_a_approval_digest": self.approval_digest,
            "replay_root": str(self.replay_root),
            "replay_root_identity": self._directory_identity(self.replay_root),
            "repository": str(self.repository),
            "repository_identity": self._directory_identity(self.repository),
            "head_state": "detached",
            "final_head": final_head,
            "parent": parent,
            "tree": tree,
            "base_commit": policy["base_commit"],
            "base_tree": policy["base_tree"],
            "protected_main_commit": policy["main_commit"],
            "required_ancestors": list(policy["required_ancestors"]),
            "forbidden_ancestors": list(policy["forbidden_ancestors"]),
        }
        # Creating the direct-child result can change the replay-root identity;
        # publish the result once, capture the post-publication identity, then
        # rewrite only the result bytes in the same private fixture directory.
        _write_json(self.result_path, result)
        result["replay_root_identity"] = self._directory_identity(self.replay_root)
        result["repository_identity"] = self._directory_identity(self.repository)
        _write_json(self.result_path, result)
        return final_head, parent, tree

    @contextmanager
    def _mock_git_review(
        self,
        *,
        reviewer_label: str = "synthetic-reviewer-one",
        on_inspect: Any | None = None,
    ) -> Iterator[dict[str, Any]]:
        calls: list[str] = []
        repository_identity = self._directory_identity(self.repository)
        identity = SimpleNamespace(label=reviewer_label, root=self.repository)
        guard = _FakeGuard(identity, calls)

        def inspect_metadata(root: Path, label: str) -> Any:
            calls.append("inspect_metadata")
            if on_inspect is not None:
                on_inspect()
            return identity

        def derive_identity(_repo: Path, claims: tuple[str, str, str], _guard: Any) -> dict[str, str]:
            calls.append("derive_identity")
            return {
                "final_head": claims[0],
                "parent": claims[1],
                "tree": claims[2],
            }

        def raw_head(_repo: Path, _guard: Any) -> str:
            calls.append("raw_detached_head")
            return "a" * 40

        patches = [
            patch.object(PHASE_B.REVIEW, "inspect_metadata", side_effect=inspect_metadata),
            patch.object(PHASE_B.REVIEW, "RepoGuard", side_effect=lambda value: guard),
            patch.object(PHASE_B.REVIEW, "directory_identity", return_value=repository_identity),
            patch.object(PHASE_B.REVIEW, "_check_repo_shape", side_effect=lambda *args, **kwargs: calls.append("repo_shape")),
            patch.object(PHASE_B.REVIEW, "_check_origin_and_base", side_effect=lambda *args, **kwargs: calls.append("origin_and_base")),
            patch.object(PHASE_B.REVIEW, "check_worktree_registry", side_effect=lambda *args, **kwargs: calls.append("worktree_registry")),
            patch.object(PHASE_B.REVIEW, "check_clean", side_effect=lambda *args, **kwargs: calls.append("clean")),
            patch.object(PHASE_B.REVIEW, "check_index_flags", side_effect=lambda *args, **kwargs: calls.append("index_flags")),
            patch.object(PHASE_B.REVIEW, "_check_fsck", side_effect=lambda *args, **kwargs: calls.append("fsck")),
            patch.object(PHASE_B.REVIEW, "_check_explicit_closure", side_effect=lambda *args, **kwargs: calls.append("object_closure")),
            patch.object(PHASE_B.REVIEW, "_check_ancestry", side_effect=lambda *args, **kwargs: calls.append("ancestry")),
            patch.object(PHASE_B, "_derive_identity", side_effect=derive_identity),
            patch.object(PHASE_B, "_raw_head_from_snapshot", side_effect=raw_head),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10], patches[11], patches[12]:
            yield {"calls": calls, "identity": identity, "repository_identity": repository_identity}

    def _run_phase_b(self, *, manifest_sha256: str, approval_digest: str) -> dict[str, Any]:
        with self._phase_a_validation():
            with self._mock_git_review() as review:
                result = PHASE_B.validate_post_replay(
                    self.result_path,
                    self.replay_root,
                    self.repository,
                    phase_a_manifest_path=self.manifest_path,
                    phase_a_manifest_sha256=manifest_sha256,
                    phase_a_approval_anchor_path=self.anchor_path,
                    phase_a_approval_digest=approval_digest,
                )
                result["_review_calls"] = review["calls"]
                return result

    def test_valid_phase_a_manifest_external_anchor_then_phase_b_passes(self) -> None:
        anchor_result = self._provision_anchor()
        final_head, parent, tree = self._write_replay_result()

        with self._phase_a_validation():
            with self._mock_git_review() as review:
                observed = PHASE_B.validate_post_replay(
                    self.result_path,
                    self.replay_root,
                    self.repository,
                    phase_a_manifest_path=self.manifest_path,
                    phase_a_manifest_sha256=self.manifest_sha256,
                    phase_a_approval_anchor_path=self.anchor_path,
                    phase_a_approval_digest=self.approval_digest,
                )

        self.assertEqual(anchor_result["manifest_sha256"], self.manifest_sha256)
        self.assertEqual(anchor_result["phase_a_approval_digest"], self.approval_digest)
        self.assertEqual(observed["final_head"], final_head)
        self.assertEqual(observed["parent"], parent)
        self.assertEqual(observed["tree"], tree)
        self.assertEqual(observed["phase_a_manifest_sha256"], self.manifest_sha256)
        self.assertEqual(observed["phase_a_approval_digest"], self.approval_digest)
        self.assertIn("inspect_metadata", review["calls"])
        self.assertIn("guard.assert_stable", review["calls"])

    def test_missing_anchor_rejects_before_git_inspection(self) -> None:
        self._write_replay_result()
        with self._phase_a_validation():
            with self._mock_git_review() as review:
                with self.assertRaisesRegex(PHASE_B.Reject, "approval anchor"):
                    PHASE_B.validate_post_replay(
                        self.result_path,
                        self.replay_root,
                        self.repository,
                        phase_a_manifest_path=self.manifest_path,
                        phase_a_manifest_sha256=self.manifest_sha256,
                        phase_a_approval_anchor_path=self.anchor_path,
                        phase_a_approval_digest=self.approval_digest,
                    )
        self.assertNotIn("inspect_metadata", review["calls"])

    def test_manifest_rewrite_after_anchor_rejects_with_old_supplied_digest(self) -> None:
        self._provision_anchor()
        self._write_replay_result()
        rewritten = dict(self.manifest)
        rewritten["artifacts"] = dict(self.manifest["artifacts"])
        rewritten["artifacts"]["markdown"] = dict(self.manifest["artifacts"]["markdown"])
        rewritten["artifacts"]["markdown"]["sha256"] = "f" * 64
        _replace_json(self.manifest_path, rewritten, indent=2)

        with self._phase_a_validation():
            with self._mock_git_review() as review:
                with self.assertRaisesRegex(PHASE_B.Reject, "manifest SHA-256 is stale or forged"):
                    PHASE_B.validate_post_replay(
                        self.result_path,
                        self.replay_root,
                        self.repository,
                        phase_a_manifest_path=self.manifest_path,
                        phase_a_manifest_sha256=self.manifest_sha256,
                        phase_a_approval_anchor_path=self.anchor_path,
                        phase_a_approval_digest=self.approval_digest,
                    )
        self.assertNotIn("inspect_metadata", review["calls"])

    def test_manifest_rewrite_after_anchor_rejects_with_new_digest_but_stale_anchor(self) -> None:
        self._provision_anchor()
        self._write_replay_result()
        # Formatting is intentionally the only change.  The reviewed artifact
        # bytes and semantic Phase-A approval digest remain constant, while the
        # manifest bytes and therefore its externally anchored digest change.
        _replace_json(self.manifest_path, self.manifest, indent=4)
        new_manifest_sha256 = _sha256(self.manifest_path.read_bytes())
        self.assertNotEqual(new_manifest_sha256, self.manifest_sha256)
        self.assertEqual(ANCHOR.PHASE_A.phase_a_approval_digest(self.manifest), self.approval_digest)

        with self._phase_a_validation():
            with self._mock_git_review() as review:
                with self.assertRaisesRegex(PHASE_B.Reject, "anchor manifest digest differs"):
                    PHASE_B.validate_post_replay(
                        self.result_path,
                        self.replay_root,
                        self.repository,
                        phase_a_manifest_path=self.manifest_path,
                        phase_a_manifest_sha256=new_manifest_sha256,
                        phase_a_approval_anchor_path=self.anchor_path,
                        phase_a_approval_digest=self.approval_digest,
                    )
        self.assertNotIn("inspect_metadata", review["calls"])

    def test_in_flight_manifest_rewrite_after_authentication_fails_final_stability_check(self) -> None:
        self._provision_anchor()
        self._write_replay_result()
        rewrite_count = 0

        def rewrite_after_authentication() -> None:
            nonlocal rewrite_count
            rewrite_count += 1
            _replace_json(self.manifest_path, self.manifest, indent=4)

        with self._phase_a_validation():
            with self._mock_git_review(on_inspect=rewrite_after_authentication) as review:
                with self.assertRaisesRegex(PHASE_B.Reject, "manifest changed before final PASS"):
                    PHASE_B.validate_post_replay(
                        self.result_path,
                        self.replay_root,
                        self.repository,
                        phase_a_manifest_path=self.manifest_path,
                        phase_a_manifest_sha256=self.manifest_sha256,
                        phase_a_approval_anchor_path=self.anchor_path,
                        phase_a_approval_digest=self.approval_digest,
                    )
        self.assertEqual(rewrite_count, 1)
        self.assertEqual(review["calls"].count("inspect_metadata"), 1)

    def test_anchor_and_phase_b_bind_reviewed_bytes_not_reviewer_identity(self) -> None:
        self._provision_anchor()
        anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"))
        self.assertEqual(set(anchor), set(ANCHOR.ANCHOR_KEYS))
        self.assertNotIn("reviewer", anchor)
        self.assertNotIn("reviewer_identity", anchor)
        self.assertEqual(anchor["manifest_sha256"], self.manifest_sha256)
        self.assertEqual(anchor["phase_a_approval_digest"], self.approval_digest)

        self._write_replay_result()
        outputs = []
        for label in ("reviewer-one", "reviewer-two"):
            with self._phase_a_validation():
                with self._mock_git_review(reviewer_label=label) as review:
                    outputs.append(
                        PHASE_B.validate_post_replay(
                            self.result_path,
                            self.replay_root,
                            self.repository,
                            phase_a_manifest_path=self.manifest_path,
                            phase_a_manifest_sha256=self.manifest_sha256,
                            phase_a_approval_anchor_path=self.anchor_path,
                            phase_a_approval_digest=self.approval_digest,
                        )
                    )
            self.assertIn("inspect_metadata", review["calls"])
        self.assertEqual(outputs[0]["final_head"], outputs[1]["final_head"])
        self.assertEqual(outputs[0]["phase_a_manifest_sha256"], self.manifest_sha256)
        self.assertEqual(outputs[1]["phase_a_manifest_sha256"], self.manifest_sha256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
