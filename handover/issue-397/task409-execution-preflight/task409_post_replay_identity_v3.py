#!/usr/bin/env python3
"""Task #409 Phase B authenticated post-replay identity gate.

Phase A is the only source of artifact and ancestry policy. Phase B first
stable-opens the actual Phase-A manifest, validates its frozen artifact
bindings, recomputes its canonical approval digest, and checks an independent
approval-anchor file supplied by a trusted caller. Replay-result policy fields
are evidence only: they must equal the authenticated Phase-A policy and cannot
weaken or replace it.

The replay repository is then inspected read-only. Git derives detached
FINAL_HEAD, its exactly-one commit parent, and its tree from raw ``.git/HEAD``
and typed objects. The Phase-A manifest and approval anchor are reread before
PASS so a same-path rewrite cannot be hidden after repository checks.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve().parent
REVIEW_PATH = HERE / "review_task464_git_v3.py"
REVIEW_SPEC = importlib.util.spec_from_file_location("task409_git_reviewer_v3_for_phase_b", REVIEW_PATH)
if REVIEW_SPEC is None or REVIEW_SPEC.loader is None:
    raise RuntimeError(f"cannot load reviewer: {REVIEW_PATH}")
REVIEW = importlib.util.module_from_spec(REVIEW_SPEC)
sys.modules[REVIEW_SPEC.name] = REVIEW
REVIEW_SPEC.loader.exec_module(REVIEW)

PHASE_A_PATH = HERE / "task409_execution_preflight_v3.py"
PHASE_A_SPEC = importlib.util.spec_from_file_location("task409_phase_a_v3_for_phase_b", PHASE_A_PATH)
if PHASE_A_SPEC is None or PHASE_A_SPEC.loader is None:
    raise RuntimeError(f"cannot load Phase A: {PHASE_A_PATH}")
PHASE_A = importlib.util.module_from_spec(PHASE_A_SPEC)
sys.modules[PHASE_A_SPEC.name] = PHASE_A
PHASE_A_SPEC.loader.exec_module(PHASE_A)

RESULT_SCHEMA = "task409-execution-preflight/replay-result/v2"
RESULT_PHASE = "B-post-replay-detached-final-head"
PHASE_A_SCHEMA = "task409-execution-preflight/v3"
ANCHOR_SCHEMA = "task409-execution-preflight/phase-a-approval-anchor/v1"
ANCHOR_PHASE = "external-review-of-phase-a-consistency"
ANCHOR_KEYS = frozenset(
    {
        "schema",
        "phase",
        "manifest_sha256",
        "phase_a_approval_digest",
        "policy_sha256",
        "decision",
        "provisioning_boundary",
    }
)
LANE = "candidate-4"
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
DIR_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink")
RESULT_KEYS = frozenset(
    {
        "schema",
        "phase",
        "lane",
        "phase_a_manifest_sha256",
        "phase_a_approval_digest",
        "replay_root",
        "replay_root_identity",
        "repository",
        "repository_identity",
        "head_state",
        "final_head",
        "parent",
        "tree",
        "base_commit",
        "base_tree",
        "protected_main_commit",
        "required_ancestors",
        "forbidden_ancestors",
    }
)


class Reject(Exception):
    """A deliberate fail-closed post-replay rejection."""


def reject(message: str) -> None:
    raise Reject(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def _canonical_dir(value: Any, label: str) -> Path:
    require(isinstance(value, str) and value, f"{label} must be a nonempty absolute path")
    path = Path(value)
    require(path.is_absolute(), f"{label} must be absolute")
    require(str(path) == os.path.realpath(str(path)), f"{label} must already be canonical")
    st = os.lstat(path)
    require(not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode), f"{label} must be a real directory")
    require(st.st_uid == os.getuid(), f"{label} owner differs from current uid")
    require(stat.S_IMODE(st.st_mode) == 0o700, f"{label} mode must be 0700")
    return path


def _canonical_file(value: Any, label: str) -> Path:
    require(isinstance(value, (str, Path)), f"{label} path is invalid")
    path = Path(value)
    require(path.is_absolute() and str(path) == os.path.realpath(str(path)), f"{label} must be canonical absolute")
    return path


def _directory_identity(path: Path, label: str) -> dict[str, int]:
    st = os.lstat(path)
    require(not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode), f"{label} is not a private directory")
    require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, f"{label} identity is not private")
    return {
        "st_dev": int(st.st_dev),
        "st_ino": int(st.st_ino),
        "st_uid": int(st.st_uid),
        "st_mode": int(stat.S_IMODE(st.st_mode)),
        "st_nlink": int(st.st_nlink),
    }


def _validate_dir_identity(value: Any, expected: Mapping[str, int], label: str) -> None:
    require(isinstance(value, dict) and set(value) == set(DIR_FIELDS), f"{label} fields differ")
    for key in DIR_FIELDS:
        require(isinstance(value[key], int) and not isinstance(value[key], bool) and value[key] >= 0, f"{label}.{key} is invalid")
    require(dict(value) == dict(expected), f"{label} differs from observed identity")


def _result_file_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    st = os.lstat(path)
    require(stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode), "replay result must be a regular file")
    require(st.st_nlink == 1 and not stat.S_IMODE(st.st_mode) & 0o022, "replay result must be private and single-link")
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid), int(stat.S_IMODE(st.st_mode)), int(st.st_size), int(st.st_nlink))


def _load_json_no_duplicates(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as exc:
        reject(f"{label} JSON parse failed: {exc}")
    require(isinstance(value, dict), f"{label} root must be an object")
    return value


def _read_result(path: Path) -> tuple[dict[str, Any], tuple[int, int, int, int, int, int], bytes]:
    before = _result_file_identity(path)
    first = REVIEW.read_stable_file(path, "replay result")
    middle = _result_file_identity(path)
    second = REVIEW.read_stable_file(path, "replay result")
    after = _result_file_identity(path)
    require(before == middle == after and first == second, "replay result changed during validation")
    return _load_json_no_duplicates(first, "replay result"), before, first


def _read_bound_json(path: Path, label: str) -> tuple[dict[str, Any], Any]:
    """Read a private JSON file repeatedly through stable descriptor reads."""
    try:
        before = REVIEW.read_bound_file(path, label)
        middle = REVIEW.read_bound_file(path, label)
        after = REVIEW.read_bound_file(path, label)
    except REVIEW.Reject as exc:
        reject(str(exc))
    require(before.identity == middle.identity == after.identity, f"{label} identity changed during validation")
    require(before.sha256 == middle.sha256 == after.sha256, f"{label} digest changed during validation")
    require(before.raw == middle.raw == after.raw, f"{label} bytes changed during validation")
    return _load_json_no_duplicates(before.raw, label), before


def _read_bound_anchor(path: Path, manifest_sha256: str, approval_digest: str, policy_sha256: str) -> Any:
    """Read the external review decision with a closed, exact schema."""
    for value, label in ((manifest_sha256, "manifest SHA-256"), (approval_digest, "approval digest"), (policy_sha256, "policy SHA-256")):
        require(SHA256_RE.fullmatch(value) is not None, f"Phase A {label} must be 64 lowercase hexadecimal characters")
    try:
        before = REVIEW.read_bound_file(path, "Phase A approval anchor", limit=4096)
        middle = REVIEW.read_bound_file(path, "Phase A approval anchor", limit=4096)
        after = REVIEW.read_bound_file(path, "Phase A approval anchor", limit=4096)
    except REVIEW.Reject as exc:
        reject(str(exc))
    require(before.identity == middle.identity == after.identity, "Phase A approval anchor identity changed")
    require(before.sha256 == middle.sha256 == after.sha256 and before.raw == middle.raw == after.raw, "Phase A approval anchor changed")
    anchor = _load_json_no_duplicates(before.raw, "Phase A approval anchor")
    require(set(anchor) == ANCHOR_KEYS, "Phase A approval anchor fields differ")
    require(anchor["schema"] == ANCHOR_SCHEMA and anchor["phase"] == ANCHOR_PHASE, "Phase A approval anchor schema differs")
    require(anchor["manifest_sha256"] == manifest_sha256, "Phase A approval anchor manifest digest differs")
    require(anchor["phase_a_approval_digest"] == approval_digest, "Phase A approval anchor approval digest differs")
    require(anchor["policy_sha256"] == policy_sha256, "Phase A approval anchor policy digest differs")
    require(anchor["decision"] == "approve-consistency-only", "Phase A approval anchor decision differs")
    require(anchor["provisioning_boundary"] == "external-review-input", "Phase A approval anchor provisioning boundary differs")
    return before


def _oid(value: Any, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value) is not None, f"{label} must be exactly 40 lowercase hexadecimal characters")
    return value


def _sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _oid_list(value: Any, label: str) -> list[str]:
    require(isinstance(value, list) and len(value) == len(set(value)), f"{label} must be a duplicate-free array")
    return [_oid(item, f"{label} item") for item in value]


def _commonpath(a: Path, b: Path) -> str:
    try:
        return os.path.commonpath([str(a), str(b)])
    except ValueError:
        return ""


def _validate_result(
    result: Mapping[str, Any],
    result_path: Path,
    replay_root: Path,
    repository: Path,
    phase_a_manifest_sha256: str,
    phase_a_approval_digest: str,
) -> tuple[str, str, str, list[str], list[str]]:
    require(set(result) == RESULT_KEYS, "replay result fields differ")
    require(result["schema"] == RESULT_SCHEMA and result["phase"] == RESULT_PHASE, "replay result schema or phase differs")
    require(result["lane"] == LANE and result["head_state"] == "detached", "replay result lane/head state differs")
    _sha(result["phase_a_manifest_sha256"], "replay result phase_a_manifest_sha256")
    _sha(result["phase_a_approval_digest"], "replay result phase_a_approval_digest")
    require(result["phase_a_manifest_sha256"] == phase_a_manifest_sha256, "replay result Phase-A manifest digest differs")
    require(result["phase_a_approval_digest"] == phase_a_approval_digest, "replay result Phase-A approval digest differs")
    require(result["replay_root"] == str(replay_root) and result["repository"] == str(repository), "replay result path differs")
    require(result_path.parent == replay_root and replay_root != repository, "replay result placement is invalid")
    require(_commonpath(replay_root, repository) not in {str(replay_root), str(repository)}, "replay root and repository overlap")
    _validate_dir_identity(result["replay_root_identity"], _directory_identity(replay_root, "replay root"), "replay_root_identity")
    _validate_dir_identity(result["repository_identity"], _directory_identity(repository, "repository"), "repository_identity")
    return (
        _oid(result["final_head"], "replay result final_head"),
        _oid(result["parent"], "replay result parent"),
        _oid(result["tree"], "replay result tree"),
        _oid_list(result["required_ancestors"], "required_ancestors"),
        _oid_list(result["forbidden_ancestors"], "forbidden_ancestors"),
    )


def _raw_head_from_snapshot(repo: Path, guard: Any) -> str:
    snapshot = REVIEW.read_bound_file(repo / ".git" / "HEAD", "detached HEAD")
    require(snapshot.identity == guard.identity.head_snapshot.identity, "detached HEAD identity differs from inspected snapshot")
    require(snapshot.sha256 == guard.identity.head_snapshot.sha256 and snapshot.raw == guard.identity.head_snapshot.raw, "detached HEAD changed before Git checks")
    require(re.fullmatch(rb"[0-9a-f]{40}\n", snapshot.raw) is not None, "detached .git/HEAD must be exactly lowercase 40-hex plus LF")
    return snapshot.raw[:-1].decode("ascii")


def _require_detached(repo: Path, guard: Any, raw_oid: str) -> None:
    symbolic = REVIEW.run_git(repo, ["symbolic-ref", "-q", "HEAD"], guard=guard)
    require(symbolic.returncode == 1 and not symbolic.stdout and not symbolic.stderr, "repository HEAD is not detached")
    resolved = REVIEW._rev_parse(repo, "HEAD^{commit}", "detached HEAD resolution", guard)
    require(resolved == raw_oid, "Git HEAD resolution differs from raw detached HEAD OID")


def _derive_identity(repo: Path, claims: tuple[str, str, str], guard: Any) -> dict[str, str]:
    expected_head, expected_parent, expected_tree = claims
    raw_head = _raw_head_from_snapshot(repo, guard)
    _require_detached(repo, guard, raw_head)
    REVIEW._assert_oid_type(repo, raw_head, "commit", "raw detached FINAL_HEAD", guard)
    parents = REVIEW._decode(REVIEW.git_output(repo, ["rev-list", "--parents", "-n", "1", raw_head], guard=guard), "FINAL_HEAD parent record").split()
    require(len(parents) == 2 and parents[0] == raw_head, "raw detached FINAL_HEAD must have exactly one parent")
    parent = _oid(parents[1], "raw detached FINAL_HEAD parent")
    REVIEW._assert_oid_type(repo, parent, "commit", "raw detached FINAL_HEAD parent", guard)
    tree = REVIEW._rev_parse(repo, f"{raw_head}^{{tree}}", "raw detached FINAL_HEAD tree", guard)
    REVIEW._assert_oid_type(repo, tree, "tree", "raw detached FINAL_HEAD tree", guard)
    require(raw_head == expected_head and parent == expected_parent and tree == expected_tree, "replay result identity is stale or forged")
    return {"final_head": raw_head, "parent": parent, "tree": tree}


def _authenticate_phase_a(
    manifest_path: Path,
    manifest_sha256: str,
    approval_anchor_path: Path,
    approval_digest: str,
) -> tuple[dict[str, Any], Any, Any]:
    manifest_path = _canonical_file(manifest_path, "Phase A manifest")
    approval_anchor_path = _canonical_file(approval_anchor_path, "Phase A approval anchor")
    require(manifest_path != approval_anchor_path, "Phase A manifest and approval anchor must differ")
    manifest, snapshot = _read_bound_json(manifest_path, "Phase A manifest")
    actual_manifest_sha = snapshot.sha256
    supplied_manifest_sha = _sha(manifest_sha256, "supplied Phase A manifest SHA-256")
    require(actual_manifest_sha == supplied_manifest_sha, "Phase A manifest SHA-256 is stale or forged")
    require(manifest.get("schema") == PHASE_A_SCHEMA, "Phase A manifest schema differs")
    try:
        # This validates the closed schema and all three frozen artifact bytes;
        # policy is consequently derived from authenticated Phase-A content.
        PHASE_A.validate_artifacts(manifest)
    except PHASE_A.Reject as exc:
        reject(f"authenticated Phase A manifest rejected: {exc}")
    actual_approval = PHASE_A.phase_a_approval_digest(manifest)
    supplied_approval = _sha(approval_digest, "trusted Phase A approval digest")
    require(actual_approval == supplied_approval, "Phase A approval digest differs")
    policy = manifest.get("policy")
    require(isinstance(policy, dict), "authenticated Phase A policy is missing")
    policy_sha256 = PHASE_A.policy_digest(policy)
    require(policy_sha256 == PHASE_A.APPROVED_POLICY_SHA256, "authenticated Phase A policy is not approved")
    anchor = _read_bound_anchor(approval_anchor_path, supplied_manifest_sha, supplied_approval, policy_sha256)
    return manifest, snapshot, anchor


def _assert_phase_a_stable(
    manifest_path: Path,
    manifest_snapshot: Any,
    anchor_path: Path,
    anchor_snapshot: Any,
    manifest_sha256: str,
    approval_digest: str,
    policy_sha256: str,
) -> None:
    manifest_now, snapshot_now = _read_bound_json(manifest_path, "Phase A manifest final reread")
    require(snapshot_now.identity == manifest_snapshot.identity and snapshot_now.sha256 == manifest_snapshot.sha256, "Phase A manifest changed before final PASS")
    require(snapshot_now.sha256 == manifest_sha256, "Phase A manifest digest changed before final PASS")
    require(PHASE_A.phase_a_approval_digest(manifest_now) == approval_digest, "Phase A approval digest changed before final PASS")
    anchor_now = _read_bound_anchor(anchor_path, manifest_sha256, approval_digest, policy_sha256)
    require(anchor_now.identity == anchor_snapshot.identity and anchor_now.sha256 == anchor_snapshot.sha256, "Phase A approval anchor changed before final PASS")


def validate_post_replay(
    result_path: Path,
    replay_root: Path,
    repository: Path,
    *,
    phase_a_manifest_path: Path,
    phase_a_manifest_sha256: str,
    phase_a_approval_anchor_path: Path,
    phase_a_approval_digest: str,
) -> dict[str, Any]:
    """Authenticate Phase A, then validate detached Git identity read-only."""
    replay_root = _canonical_dir(str(replay_root), "replay root")
    repository = _canonical_dir(str(repository), "repository")
    result_path = _canonical_file(result_path, "replay result")
    require(result_path.parent == replay_root, "replay result must be directly inside replay root")

    manifest, manifest_snapshot, anchor_snapshot = _authenticate_phase_a(
        phase_a_manifest_path,
        phase_a_manifest_sha256,
        phase_a_approval_anchor_path,
        phase_a_approval_digest,
    )
    policy = manifest["policy"]
    result, result_identity, result_raw = _read_result(result_path)
    claims = _validate_result(result, result_path, replay_root, repository, phase_a_manifest_sha256, phase_a_approval_digest)
    require(result["base_commit"] == policy["base_commit"], "replay result base_commit is not Phase-A evidence")
    require(result["base_tree"] == policy["base_tree"], "replay result base_tree is not Phase-A evidence")
    require(result["protected_main_commit"] == policy["main_commit"], "replay result protected main is not Phase-A evidence")
    require(claims[3] == policy["required_ancestors"], "replay result required ancestry differs from authenticated Phase A")
    require(claims[4] == policy["forbidden_ancestors"], "replay result forbidden ancestry differs from authenticated Phase A")

    try:
        identity = REVIEW.inspect_metadata(repository, "post-replay")
        require(REVIEW.directory_identity(identity) == result["repository_identity"], "RepoGuard identity differs from declared repository identity")
        guard = REVIEW.RepoGuard(identity)
        require(REVIEW.directory_identity(guard.identity) == result["repository_identity"], "RepoGuard identity changed at capture")
        REVIEW._check_repo_shape(repository, identity, guard)
        try:
            REVIEW._check_origin_and_base(repository, "post-replay", guard, policy=policy)
        except TypeError:
            reject("v3 reviewer does not accept authenticated Phase-A policy")
        REVIEW.check_worktree_registry(repository, identity, guard)
        REVIEW.check_clean(repository, guard)
        REVIEW.check_index_flags(repository, guard)
        REVIEW._check_fsck(repository, identity, guard)
        observed = _derive_identity(repository, claims[:3], guard)
        REVIEW._check_explicit_closure(repository, observed["final_head"], guard)
        for ancestor in policy["required_ancestors"]:
            REVIEW._check_ancestry(repository, observed["final_head"], ancestor, forbidden=False, guard=guard)
        for ancestor in policy["forbidden_ancestors"]:
            REVIEW._check_ancestry(repository, observed["final_head"], ancestor, forbidden=True, guard=guard)
        require(REVIEW.directory_identity(guard.identity) == result["repository_identity"], "RepoGuard identity differs at final PASS")
        guard.assert_stable()
        final_head = _raw_head_from_snapshot(repository, guard)
        require(final_head == observed["final_head"], "raw detached HEAD changed before final PASS")
    except REVIEW.Reject as exc:
        reject(str(exc))

    result_now, result_identity_now, result_raw_now = _read_result(result_path)
    require(result_now == result, "replay result fields changed before final PASS")
    require(result_identity_now == result_identity and result_raw_now == result_raw, "replay result changed before final PASS")
    _assert_phase_a_stable(
        Path(phase_a_manifest_path),
        manifest_snapshot,
        Path(phase_a_approval_anchor_path),
        anchor_snapshot,
        phase_a_manifest_sha256,
        phase_a_approval_digest,
        PHASE_A.policy_digest(policy),
    )
    return {
        "phase": RESULT_PHASE,
        "lane": LANE,
        "repository": str(repository),
        "replay_root": str(replay_root),
        **observed,
        "phase_a_manifest_sha256": phase_a_manifest_sha256,
        "phase_a_approval_digest": phase_a_approval_digest,
        "execution": "not-run",
        "mutation": "not-run",
        "network": "not-used",
        "approval": "not-claimed",
    }


def _raw_argv_scan(argv: Sequence[str]) -> None:
    require(all(isinstance(item, str) for item in argv), "arguments must be text")
    require("--ref" not in argv and not any(item.startswith("--ref=") for item in argv), "--ref is not supported; Phase B is detached-only")
    require("--execute" not in argv, "--execute is forbidden")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Task #409 Phase B authenticated detached FINAL_HEAD identity gate")
    parser.add_argument("--replay-result", required=True)
    parser.add_argument("--replay-root", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--phase-a-manifest", required=True)
    parser.add_argument("--phase-a-manifest-sha256", required=True)
    parser.add_argument("--phase-a-approval-anchor", required=True)
    parser.add_argument("--phase-a-approval-digest", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        actual = list(sys.argv[1:] if argv is None else argv)
        _raw_argv_scan(actual)
        args = build_parser().parse_args(actual)
        result = validate_post_replay(
            Path(args.replay_result),
            Path(args.replay_root),
            Path(args.repository),
            phase_a_manifest_path=Path(args.phase_a_manifest),
            phase_a_manifest_sha256=args.phase_a_manifest_sha256,
            phase_a_approval_anchor_path=Path(args.phase_a_approval_anchor),
            phase_a_approval_digest=args.phase_a_approval_digest,
        )
        print("PASS: Phase B authenticated detached FINAL_HEAD identity checks passed")
        for key in ("phase", "lane", "replay_root", "repository", "final_head", "parent", "tree", "phase_a_manifest_sha256", "phase_a_approval_digest", "execution", "mutation", "network", "approval"):
            print(f"{key}={json.dumps(result[key], sort_keys=True, separators=(',', ':'))}")
        return 0
    except Reject as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 2
    except REVIEW.Reject as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, AssertionError) as exc:
        print(f"REJECT: unexpected structural Phase B failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
