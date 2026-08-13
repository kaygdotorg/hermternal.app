#!/usr/bin/env python3
"""Bind genuine durable Phase A and Phase B to independent path authority."""
from __future__ import annotations

import importlib.util
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
PREFLIGHT = HERE.parent / "task409-execution-preflight"
PHASE_A_PATH = PREFLIGHT / "task409_execution_preflight_v3.py"
ANCHOR_PATH = PREFLIGHT / "provision_task409_phase_a_anchor_v3.py"
PHASE_B_PATH = PREFLIGHT / "task409_post_replay_identity_v3.py"
ROLE_NAMES = {
    "markdown": "candidate-five.md",
    "json": "candidate-five.json",
    "shell": "candidate-five.sh",
}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load durable module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PHASE_A = _load("issue397_lifecycle_genuine_phase_a", PHASE_A_PATH)
ANCHOR = _load("issue397_lifecycle_genuine_anchor", ANCHOR_PATH)
PHASE_B = _load("issue397_lifecycle_genuine_phase_b", PHASE_B_PATH)


class Reject(Exception):
    """A deliberate fail-closed authority rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def expected_paths(authority_root: Path) -> dict[str, Path]:
    """Derive the closed role paths from independent root authority."""
    root = Path(authority_root)
    require(root.is_absolute() and str(root) == os.path.realpath(root), "authority root must be canonical absolute")
    st = os.lstat(root)
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "authority root must be a directory")
    require(st.st_uid == os.getuid() and not stat.S_IMODE(st.st_mode) & 0o022, "authority root must be private")
    return {role: root / name for role, name in ROLE_NAMES.items()}


def _directory_binding(path: Path) -> tuple[int, int, int, int, int]:
    """Bind a canonical directory name to its current private inode."""
    require(str(path) == os.path.realpath(path), "authority directory became noncanonical")
    st = os.lstat(path)
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "authority directory is not a directory")
    require(st.st_uid == os.getuid() and not stat.S_IMODE(st.st_mode) & 0o022, "authority directory is not private")
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid), stat.S_IMODE(st.st_mode), int(st.st_nlink))


def _final_artifact_stability(
    authority_root: Path,
    root_binding: tuple[int, int, int, int, int],
    parent_binding: tuple[int, int, int, int, int],
    authenticated: Mapping[str, Any],
) -> None:
    """Reread authenticated artifact facts without a third validator call."""
    require(_directory_binding(authority_root) == root_binding, "authority root changed during Phase B")
    require(_directory_binding(authority_root.parent) == parent_binding, "authority parent changed during Phase B")
    expected = expected_paths(authority_root)
    require(authenticated.get("paths") == {role: str(path) for role, path in expected.items()}, "authenticated Phase A paths differ")
    hashes = authenticated.get("hashes")
    identities = authenticated.get("identities")
    require(isinstance(hashes, dict) and isinstance(identities, dict), "authenticated Phase A artifact facts are missing")
    for role, path in expected.items():
        try:
            raw, st = PHASE_A.read_twice(path, f"final {role}", PHASE_A.MAX_ARTIFACT_SIZE[role])
        except PHASE_A.Reject as exc:
            raise Reject(str(exc)) from exc
        require(hashlib.sha256(raw).hexdigest() == hashes[f"{role}_sha256"], f"{role} hash changed during Phase B")
        require(PHASE_A._identity(st) == identities[role], f"{role} identity changed during Phase B")
    require(_directory_binding(authority_root) == root_binding, "authority root changed after final artifact reads")
    require(_directory_binding(authority_root.parent) == parent_binding, "authority parent changed after final artifact reads")


def assert_manifest_authority(manifest: Mapping[str, Any], authority_root: Path) -> dict[str, Path]:
    """Reject descriptor-selected paths before a genuine validator call."""
    paths = expected_paths(authority_root)
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict) and set(artifacts) == set(ROLE_NAMES), "manifest roles differ from fixed authority")
    for role, expected in paths.items():
        record = artifacts.get(role)
        require(isinstance(record, dict), f"manifest {role} record is invalid")
        require(record.get("path") == str(expected), f"manifest {role} path differs from independent authority")
    require(len(set(paths.values())) == 3, "fixed authority paths must be distinct")
    return paths


def load_authorized_manifest(manifest_path: Path, authority_root: Path) -> tuple[dict[str, Any], str]:
    """Use the durable stable manifest reader, then enforce external paths."""
    try:
        manifest, manifest_sha256 = PHASE_A.load_manifest(Path(manifest_path))
    except PHASE_A.Reject as exc:
        raise Reject(str(exc)) from exc
    assert_manifest_authority(manifest, authority_root)
    return manifest, manifest_sha256


def provision_external_anchor(
    manifest_path: Path,
    anchor_path: Path,
    authority_root: Path,
    *,
    manifest_sha256: str,
    approval_digest: str,
    policy_sha256: str,
) -> dict[str, Any]:
    """Run the genuine external anchor after independent path binding."""
    _, observed_sha = load_authorized_manifest(manifest_path, authority_root)
    require(observed_sha == manifest_sha256, "manifest SHA-256 differs before anchor")
    try:
        return ANCHOR.provision_anchor(
            Path(manifest_path),
            Path(anchor_path),
            manifest_sha256=manifest_sha256,
            phase_a_approval_digest=approval_digest,
            policy_sha256=policy_sha256,
            decision=ANCHOR.DECISION,
        )
    except (ANCHOR.Reject, ANCHOR.PHASE_A.Reject) as exc:
        raise Reject(str(exc)) from exc


def validate_genuine_phase_b(
    result_path: Path,
    replay_root: Path,
    repository: Path,
    manifest_path: Path,
    anchor_path: Path,
    authority_root: Path,
    *,
    manifest_sha256: str,
    approval_digest: str,
) -> dict[str, Any]:
    """Run genuine Phase B; tests may replace only its Git observations."""
    _, observed_sha = load_authorized_manifest(manifest_path, authority_root)
    require(observed_sha == manifest_sha256, "manifest SHA-256 differs before Phase B")
    root_binding = _directory_binding(Path(authority_root))
    parent_binding = _directory_binding(Path(authority_root).parent)
    captured: list[Mapping[str, Any]] = []
    genuine_validator = PHASE_B.PHASE_A.validate_artifacts

    def capture_genuine_result(manifest: dict[str, Any]) -> dict[str, Any]:
        result = genuine_validator(manifest)
        captured.append(result)
        return result

    PHASE_B.PHASE_A.validate_artifacts = capture_genuine_result
    try:
        result = PHASE_B.validate_post_replay(
            Path(result_path),
            Path(replay_root),
            Path(repository),
            phase_a_manifest_path=Path(manifest_path),
            phase_a_manifest_sha256=manifest_sha256,
            phase_a_approval_anchor_path=Path(anchor_path),
            phase_a_approval_digest=approval_digest,
        )
    except (PHASE_B.Reject, PHASE_B.PHASE_A.Reject, PHASE_B.REVIEW.Reject) as exc:
        raise Reject(str(exc)) from exc
    finally:
        PHASE_B.PHASE_A.validate_artifacts = genuine_validator
    require(len(captured) == 1, "Phase B genuine validator call count differs")
    _final_artifact_stability(Path(authority_root), root_binding, parent_binding, captured[0])
    return result
