#!/usr/bin/env python3
"""Provision an external Phase-A consistency approval anchor.

This helper is an operator/trusted-controller boundary, not part of Phase A or
replay.  It accepts only the authenticated Phase-A manifest path and supplied
Phase-A digests.  It has no replay-result input, never executes the candidate,
and never derives approval from Git or candidate identity data.

The publication is create-if-absent.  Source and output files are opened and
reread through stable descriptor-relative reads; the output is canonical JSON
with one terminal LF, fsynced before the parent directory is fsynced, and
rejected if any existing path would be overwritten.  The supplied reviewed
manifest and digests are enforced as inputs; this helper has no cryptographic
operator identity and does not itself prove reviewer independence.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve().parent
REVIEW_PATH = HERE / "review_task464_git_v3.py"
REVIEW_SPEC = importlib.util.spec_from_file_location("task409_anchor_reviewer_v3", REVIEW_PATH)
if REVIEW_SPEC is None or REVIEW_SPEC.loader is None:
    raise RuntimeError(f"cannot load reviewer: {REVIEW_PATH}")
REVIEW = importlib.util.module_from_spec(REVIEW_SPEC)
sys.modules[REVIEW_SPEC.name] = REVIEW
REVIEW_SPEC.loader.exec_module(REVIEW)

PHASE_A_PATH = HERE / "task409_execution_preflight_v3.py"
PHASE_A_SPEC = importlib.util.spec_from_file_location("task409_anchor_phase_a_v3", PHASE_A_PATH)
if PHASE_A_SPEC is None or PHASE_A_SPEC.loader is None:
    raise RuntimeError(f"cannot load Phase A: {PHASE_A_PATH}")
PHASE_A = importlib.util.module_from_spec(PHASE_A_SPEC)
sys.modules[PHASE_A_SPEC.name] = PHASE_A
PHASE_A_SPEC.loader.exec_module(PHASE_A)

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
DECISION = "approve-consistency-only"
PROVISIONING_BOUNDARY = "external-review-input"
SHA256_HEX_LENGTH = 64


class Reject(Exception):
    """A deliberate fail-closed provisioning rejection."""


def reject(message: str) -> None:
    raise Reject(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def _sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and len(value) == SHA256_HEX_LENGTH, f"{label} must be 64 lowercase hexadecimal characters")
    require(all(char in "0123456789abcdef" for char in value), f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _canonical_existing_file(value: Path, label: str) -> Path:
    path = Path(value)
    require(path.is_absolute() and str(path) == os.path.realpath(str(path)), f"{label} must be canonical absolute")
    try:
        REVIEW.read_bound_file(path, label, limit=8 * 1024 * 1024)
    except REVIEW.Reject as exc:
        reject(str(exc))
    require(stat.S_ISREG(os.lstat(path).st_mode), f"{label} must be a regular file")
    return path


@dataclass
class _ParentBinding:
    """A held descriptor chain for the canonical output parent."""

    path: Path
    name: str
    fds: tuple[int, ...]
    fd: int
    chain_identity: tuple[tuple[int, ...], ...]
    static_chain_identity: tuple[tuple[int, ...], ...]
    pre_identity: tuple[int, ...]
    open_identity: tuple[int, ...]
    final_identity: tuple[int, ...] | None
    final_static_identity: tuple[int, ...] | None


@dataclass
class _Publication:
    """The descriptor and inode identity owned by one successful create."""

    fd: int
    identity: tuple[int, int]


@dataclass(frozen=True)
class _AnchorSnapshot:
    path: Path
    identity: tuple[int, ...]
    sha256: str
    raw: bytes


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(st.st_dev),
        int(st.st_ino),
        int(st.st_uid),
        int(stat.S_IMODE(st.st_mode)),
        int(st.st_size),
        int(st.st_nlink),
        int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
        int(getattr(st, "st_ctime_ns", int(st.st_ctime * 1_000_000_000))),
    )


def _static_identity(identity: tuple[int, ...]) -> tuple[int, int, int, int]:
    """Return parent provenance fields unaffected by child publication."""
    require(len(identity) == 8, "file identity width differs")
    # Directory size, link count, and timestamps legitimately change when the
    # anchor entry is created.  Device, inode, owner, and mode bind provenance.
    return (identity[0], identity[1], identity[2], identity[3])


def _inode_identity(st: os.stat_result) -> tuple[int, int]:
    return int(st.st_dev), int(st.st_ino)


def _validate_parent_stat(st: os.stat_result, label: str) -> tuple[int, ...]:
    identity = _identity(st)
    require(stat.S_ISDIR(st.st_mode), f"{label} is not a directory")
    require(st.st_uid == os.getuid(), f"{label} owner differs from current uid")
    require(not stat.S_IMODE(st.st_mode) & 0o022, f"{label} is group/world writable")
    return identity


def _static_chain(identity: tuple[tuple[int, ...], ...]) -> tuple[tuple[int, ...], ...]:
    return tuple(_static_identity(item) for item in identity)


def _close_fds(fds: Sequence[int]) -> list[str]:
    errors: list[str] = []
    for fd in reversed(tuple(fds)):
        try:
            os.close(fd)
        except OSError as exc:
            errors.append(f"fd {fd} close failed: {exc}")
    return errors


def _open_parent_binding(value: Path) -> _ParentBinding:
    """Canonicalize, hold, and bind every directory component of the parent.

    The descriptor chain is retained until publication and rollback finish.  A
    second path walk is required before returning so a checked parent cannot be
    replaced between ``lstat`` and the held descriptor.
    """
    path = Path(value)
    require(path.is_absolute() and str(path) == os.path.realpath(str(path)), "approval anchor must be canonical absolute")
    require(path.name not in {"", ".", ".."}, "approval anchor must have a basename")
    parent = path.parent
    require(parent.is_absolute() and str(parent) == os.path.realpath(str(parent)), "approval anchor parent must be canonical")
    held: list[int] = []
    try:
        pre = os.lstat(parent)
        pre_identity = _validate_parent_stat(pre, "approval anchor parent")
        held, chain_identity = REVIEW._open_directory_chain(parent, "approval anchor parent")
        parent_fd = held[-1]
        opened = os.fstat(parent_fd)
        opened_identity = _validate_parent_stat(opened, "held approval anchor parent")
        require(pre_identity == opened_identity, "approval anchor parent changed while opening")
        require(chain_identity[-1] == _identity(opened), "held approval anchor parent identity differs")

        check_fds, check_chain = REVIEW._open_directory_chain(parent, "approval anchor parent")
        close_errors = _close_fds(check_fds)
        require(not close_errors, "approval anchor parent verification close failed: " + "; ".join(close_errors))
        require(check_chain == chain_identity, "approval anchor parent changed before publication")
        final = os.stat(parent, follow_symlinks=False)
        final_identity = _identity(final)
        require(final_identity == opened_identity, "approval anchor parent path identity changed before publication")
        require(str(parent) == os.path.realpath(str(parent)), "approval anchor parent became non-canonical")
        return _ParentBinding(
            path=parent,
            name=path.name,
            fds=tuple(held),
            fd=parent_fd,
            chain_identity=chain_identity,
            static_chain_identity=_static_chain(chain_identity),
            pre_identity=pre_identity,
            open_identity=opened_identity,
            final_identity=final_identity,
            final_static_identity=_static_identity(final_identity),
        )
    except Reject:
        _close_fds(held)
        raise
    except OSError as exc:
        _close_fds(held)
        reject(f"approval anchor parent cannot be opened safely: {exc}")
    raise AssertionError("unreachable")


def _assert_parent_current(binding: _ParentBinding, label: str) -> None:
    """Verify the held parent and canonical path still name the same objects."""
    require(str(binding.path) == os.path.realpath(str(binding.path)), f"{label} became non-canonical")
    held = os.fstat(binding.fd)
    _validate_parent_stat(held, f"{label} held parent")
    held_identity = _identity(held)
    require(_static_identity(held_identity) == _static_identity(binding.open_identity), f"{label} held parent identity changed")
    path_stat = os.stat(binding.path, follow_symlinks=False)
    path_identity = _validate_parent_stat(path_stat, f"{label} path parent")
    require(_static_identity(path_identity) == _static_identity(binding.open_identity), f"{label} path parent was replaced")
    require(_inode_identity(path_stat) == _inode_identity(held), f"{label} pathname does not name the held parent")
    if binding.final_static_identity is not None:
        require(_static_identity(path_identity) == binding.final_static_identity, f"{label} parent provenance changed after final binding")
    check_fds, check_chain = REVIEW._open_directory_chain(binding.path, label)
    close_errors = _close_fds(check_fds)
    require(not close_errors, f"{label} verification close failed: " + "; ".join(close_errors))
    require(_static_chain(check_chain) == binding.static_chain_identity, f"{label} directory chain was replaced")


def _target_stat(binding: _ParentBinding) -> os.stat_result | None:
    try:
        return os.stat(binding.name, dir_fd=binding.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        reject(f"approval anchor target cannot be inspected descriptor-relatively: {exc}")
    raise AssertionError("unreachable")


def _target_stat_for_cleanup(binding: _ParentBinding) -> tuple[os.stat_result | None, str | None]:
    try:
        return os.stat(binding.name, dir_fd=binding.fd, follow_symlinks=False), None
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"target reconciliation stat failed: {exc}"


def _validate_anchor_stat(st: os.stat_result, expected_size: int, label: str) -> tuple[int, int]:
    require(stat.S_ISREG(st.st_mode), f"{label} is not a regular file")
    require(st.st_uid == os.getuid(), f"{label} owner differs from current uid")
    require(stat.S_IMODE(st.st_mode) == 0o600, f"{label} mode is not 0600")
    require(st.st_nlink == 1, f"{label} must have exactly one hard link")
    require(st.st_size == expected_size, f"{label} size differs from canonical bytes")
    return _inode_identity(st)


def _read_fd_bytes(fd: int, limit: int, label: str) -> bytes:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(131072, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            require(total <= limit, f"{label} exceeds bounded read limit")
            chunks.append(chunk)
        return b"".join(chunks)
    except Reject:
        raise
    except OSError as exc:
        reject(f"{label} cannot be reread safely: {exc}")
    raise AssertionError("unreachable")


def _read_anchor_descriptor(
    binding: _ParentBinding,
    path: Path,
    expected_raw: bytes,
    expected_sha256: str,
    label: str,
) -> _AnchorSnapshot:
    """Read the output through the held parent, never through a path lookup."""
    fd = -1
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(binding.name, os.O_RDONLY | nofollow, dir_fd=binding.fd)
        before = os.fstat(fd)
        inode = _validate_anchor_stat(before, len(expected_raw), label)
        raw = _read_fd_bytes(fd, len(expected_raw) + 1, label)
        after = os.fstat(fd)
        final = os.stat(binding.name, dir_fd=binding.fd, follow_symlinks=False)
        final_inode = _validate_anchor_stat(final, len(expected_raw), label)
        require(inode == final_inode, f"{label} target inode was substituted")
        require(_identity(before) == _identity(after), f"{label} changed while being read")
        require(len(raw) == before.st_size and raw == expected_raw, f"{label} bytes differ from canonical bytes")
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == expected_sha256, f"{label} digest differs from canonical bytes")
        _assert_parent_current(binding, f"{label} parent")
        return _AnchorSnapshot(path, _identity(before), digest, raw)
    except Reject:
        raise
    except OSError as exc:
        reject(f"{label} cannot be read descriptor-relatively: {exc}")
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError as exc:
                reject(f"{label} descriptor close failed: {exc}")
    raise AssertionError("unreachable")


def _close_publication(publication: _Publication) -> list[str]:
    if publication.fd < 0:
        return []
    fd = publication.fd
    try:
        os.close(fd)
    except OSError as exc:
        # Keep the identity and descriptor state available for reconciliation.
        # close(2) can report an ambiguous outcome after the inode was closed.
        return [f"created anchor descriptor close failed: {exc}"]
    publication.fd = -1
    return []


def _reconcile_created(
    binding: _ParentBinding,
    publication: _Publication | None,
    *,
    create_attempted: bool,
) -> tuple[list[str], bool]:
    """Rollback only an inode proven to belong to this invocation."""
    errors: list[str] = []
    residual = False
    target, stat_error = _target_stat_for_cleanup(binding)
    if stat_error:
        errors.append(stat_error)
        residual = create_attempted
    elif publication is None:
        if target is not None and create_attempted:
            errors.append("ambiguous create outcome left an unknown target; refusing to unlink it")
            residual = True
    elif target is None:
        # A concurrent unlink may already have removed the owned directory entry.
        # Keep the descriptor evidence, but never guess at another pathname.
        pass
    elif _inode_identity(target) != publication.identity:
        errors.append("target inode is foreign or was substituted; refusing to unlink it")
        residual = True
    else:
        try:
            os.unlink(binding.name, dir_fd=binding.fd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            errors.append(f"owned anchor unlink failed: {exc}")
            residual = True
        else:
            after, after_error = _target_stat_for_cleanup(binding)
            if after_error:
                errors.append(after_error)
                residual = True
            elif after is not None:
                errors.append("owned anchor unlink left a target entry; refusing further deletion")
                residual = True
    try:
        os.fsync(binding.fd)
    except OSError as exc:
        errors.append(f"rollback parent fsync failed: {exc}")
        residual = True
    return errors, residual


def _fail_publication(
    binding: _ParentBinding,
    publication: _Publication | None,
    primary: BaseException,
    *,
    create_attempted: bool,
) -> None:
    cleanup_errors, residual = _reconcile_created(binding, publication, create_attempted=create_attempted)
    if publication is not None:
        cleanup_errors.extend(_close_publication(publication))
    message = str(primary) or primary.__class__.__name__
    if cleanup_errors:
        message += "; cleanup: " + "; ".join(cleanup_errors)
    if residual:
        message += "; residual owned or unknown target was not removed"
    reject(f"approval anchor publication failed: {message}")


def _read_json_stable(path: Path, label: str) -> tuple[dict[str, Any], Any]:
    """Read and compare three stable snapshots before trusting source bytes."""
    try:
        snapshots = [REVIEW.read_bound_file(path, label, limit=8 * 1024 * 1024) for _ in range(3)]
    except REVIEW.Reject as exc:
        reject(str(exc))
    first = snapshots[0]
    require(all(snapshot.identity == first.identity for snapshot in snapshots), f"{label} identity changed during read")
    require(all(snapshot.sha256 == first.sha256 and snapshot.raw == first.raw for snapshot in snapshots), f"{label} bytes changed during read")
    try:
        value = json.loads(first.raw.decode("utf-8"), object_pairs_hook=_pairs_without_duplicates(label))
    except Reject:
        raise
    except Exception as exc:
        reject(f"{label} JSON parse failed: {exc}")
    require(isinstance(value, dict), f"{label} root must be an object")
    return value, first


def _pairs_without_duplicates(label: str):
    def hook(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            require(key not in output, f"{label} contains duplicate key {key!r}")
            output[key] = value
        return output

    return hook


def _authenticate_manifest(
    manifest_path: Path,
    manifest_sha256: str,
    phase_a_approval_digest: str,
    policy_sha256: str,
) -> tuple[dict[str, Any], Any]:
    manifest_path = _canonical_existing_file(manifest_path, "Phase A manifest")
    supplied_manifest_sha = _sha(manifest_sha256, "Phase A manifest SHA-256")
    supplied_approval = _sha(phase_a_approval_digest, "Phase A approval digest")
    supplied_policy = _sha(policy_sha256, "Phase A policy SHA-256")
    manifest, snapshot = _read_json_stable(manifest_path, "Phase A manifest")
    require(snapshot.sha256 == supplied_manifest_sha, "Phase A manifest SHA-256 is stale or forged")
    require(set(manifest) == PHASE_A.ROOT_KEYS, "Phase A manifest fields differ")
    require(manifest["schema"] == PHASE_A.SCHEMA and manifest["phase"] == PHASE_A.PHASE, "Phase A manifest schema or phase differs")
    try:
        PHASE_A.validate_artifacts(manifest)
    except PHASE_A.Reject as exc:
        reject(f"authenticated Phase A manifest rejected: {exc}")
    approval = manifest.get("approval")
    require(isinstance(approval, dict) and set(approval) == {"status", "manifest_sha256", "policy_sha256"}, "Phase A approval fields differ")
    require(approval["status"] == "consistency-only" and approval["manifest_sha256"] == "not-bound-in-phase-a", "Phase A must remain unclaimed")
    policy = manifest.get("policy")
    require(isinstance(policy, dict) and PHASE_A.policy_digest(policy) == supplied_policy, "Phase A policy digest differs")
    require(supplied_policy == PHASE_A.APPROVED_POLICY_SHA256, "Phase A policy is not the canonical approved policy")
    require(PHASE_A.phase_a_approval_digest(manifest) == supplied_approval, "Phase A approval digest differs")
    return manifest, snapshot


def _anchor_bytes(manifest_sha256: str, phase_a_approval_digest: str, policy_sha256: str) -> bytes:
    anchor = {
        "schema": ANCHOR_SCHEMA,
        "phase": ANCHOR_PHASE,
        "manifest_sha256": manifest_sha256,
        "phase_a_approval_digest": phase_a_approval_digest,
        "policy_sha256": policy_sha256,
        "decision": DECISION,
        "provisioning_boundary": PROVISIONING_BOUNDARY,
    }
    require(set(anchor) == ANCHOR_KEYS, "generated anchor fields differ")
    return (json.dumps(anchor, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _publish_create_only(binding: _ParentBinding, raw: bytes) -> _Publication:
    """Create and durably write the anchor through the held parent descriptor."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    publication: _Publication | None = None
    create_attempted = False
    try:
        create_attempted = True
        fd = os.open(binding.name, flags, 0o600, dir_fd=binding.fd)
        publication = _Publication(fd, _inode_identity(os.fstat(fd)))
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode), "new Phase A approval anchor is not a regular file")
        require(opened.st_uid == os.getuid(), "new Phase A approval anchor owner differs from current uid")
        require(not stat.S_IMODE(opened.st_mode) & 0o022, "new Phase A approval anchor is group/world writable")
        require(opened.st_nlink == 1 and opened.st_size == 0, "new Phase A approval anchor metadata differs after create")
        os.fchmod(fd, 0o600)
        opened = os.fstat(fd)
        require(_validate_anchor_stat(opened, 0, "new Phase A approval anchor") == publication.identity,
                "new Phase A approval anchor identity differs after create")
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            require(written > 0, "anchor write made no progress")
            offset += written
        written_stat = os.fstat(fd)
        require(_validate_anchor_stat(written_stat, len(raw), "new Phase A approval anchor") == publication.identity,
                "new Phase A approval anchor inode or metadata changed after write")
        read_fd = -1
        try:
            read_fd = os.open(binding.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=binding.fd)
            read_stat = os.fstat(read_fd)
            require(_validate_anchor_stat(read_stat, len(raw), "new Phase A approval anchor") == publication.identity,
                    "new Phase A approval anchor read descriptor inode differs after write")
            reread = _read_fd_bytes(read_fd, len(raw) + 1, "new Phase A approval anchor")
            require(reread == raw, "new Phase A approval anchor bytes differ after write")
            require(hashlib.sha256(reread).hexdigest() == hashlib.sha256(raw).hexdigest(),
                    "new Phase A approval anchor digest differs after write")
        finally:
            if read_fd >= 0:
                os.close(read_fd)
        target = os.stat(binding.name, dir_fd=binding.fd, follow_symlinks=False)
        require(_validate_anchor_stat(target, len(raw), "new Phase A approval anchor") == publication.identity,
                "new Phase A approval anchor target inode differs after write")
        _assert_parent_current(binding, "approval anchor parent before file fsync")
        os.fsync(fd)
        after_file_fsync = os.fstat(fd)
        require(_validate_anchor_stat(after_file_fsync, len(raw), "new Phase A approval anchor") == publication.identity,
                "new Phase A approval anchor changed during file fsync")
        os.fsync(binding.fd)
        _assert_parent_current(binding, "approval anchor parent after parent fsync")
        return publication
    except FileExistsError:
        reject("approval anchor already exists; refusing overwrite")
    except Exception as exc:
        if not create_attempted:
            raise
        _fail_publication(binding, publication, exc, create_attempted=create_attempted)
    raise AssertionError("unreachable")


def _close_binding(binding: _ParentBinding) -> list[str]:
    return _close_fds(binding.fds)


def provision_anchor(
    manifest_path: Path,
    anchor_path: Path,
    *,
    manifest_sha256: str,
    phase_a_approval_digest: str,
    policy_sha256: str,
    decision: str,
) -> dict[str, Any]:
    """Create one externally approved anchor after an independent Phase-A PASS."""
    require(decision == DECISION, "only the explicit external consistency decision is accepted")
    manifest, manifest_snapshot = _authenticate_manifest(
        manifest_path, manifest_sha256, phase_a_approval_digest, policy_sha256
    )
    del manifest  # Authentication above is the source read; no replay-result data is accepted.
    supplied_anchor_manifest_sha = _sha(manifest_sha256, "Phase A manifest SHA-256")
    require(manifest_snapshot.sha256 == supplied_anchor_manifest_sha, "Phase A manifest path or digest is not bound")
    binding = _open_parent_binding(anchor_path)
    path = binding.path / binding.name
    publication: _Publication | None = None
    try:
        target = _target_stat(binding)
        require(target is None, "approval anchor already exists; refusing overwrite")
        raw = _anchor_bytes(manifest_snapshot.sha256, phase_a_approval_digest, policy_sha256)
        publication = _publish_create_only(binding, raw)
        expected_sha = hashlib.sha256(raw).hexdigest()
        # Preserve the reviewer-bound stable-read cross-check for callers that
        # already observe this helper.  It is only an early warning; the
        # descriptor-relative snapshots below own the race decision.
        try:
            compatibility_snapshots = [
                REVIEW.read_bound_file(path, "new Phase A approval anchor", limit=4096) for _ in range(3)
            ]
        except REVIEW.Reject as exc:
            reject(str(exc))
        compatibility_first = compatibility_snapshots[0]
        require(
            all(snapshot.identity == compatibility_first.identity for snapshot in compatibility_snapshots),
            "approval anchor changed during compatibility reread",
        )
        require(
            all(snapshot.sha256 == compatibility_first.sha256 and snapshot.raw == compatibility_first.raw
                for snapshot in compatibility_snapshots),
            "approval anchor bytes changed during compatibility reread",
        )
        final_snapshots = [
            _read_anchor_descriptor(binding, path, raw, expected_sha, "new Phase A approval anchor") for _ in range(3)
        ]
        first = final_snapshots[0]
        require(all(snapshot.identity == first.identity for snapshot in final_snapshots), "approval anchor changed after publication")
        require(all(snapshot.sha256 == first.sha256 and snapshot.raw == first.raw for snapshot in final_snapshots), "approval anchor bytes changed after publication")
        require(first.raw == raw and first.sha256 == expected_sha, "approval anchor publication bytes differ")
        require(raw.endswith(b"\n") and not raw.endswith(b"\\n"), "approval anchor must terminate with one LF, not literal backslash-n")
        close_errors = _close_publication(publication)
        require(not close_errors, "; ".join(close_errors))
        publication = None
        close_errors = _close_binding(binding)
        require(not close_errors, "approval anchor parent close failed: " + "; ".join(close_errors))
        binding = None  # type: ignore[assignment]
        return {
            "path": str(path),
            "sha256": first.sha256,
            "manifest_sha256": manifest_snapshot.sha256,
            "phase_a_approval_digest": phase_a_approval_digest,
            "policy_sha256": policy_sha256,
            "decision": DECISION,
            "provisioning_boundary": PROVISIONING_BOUNDARY,
        }
    except Reject:
        # _publish_create_only already reconciles and closes its descriptor when
        # it rejects.  Only final-read failures still own an open publication.
        if publication is not None and publication.fd >= 0:
            _fail_publication(binding, publication, sys.exc_info()[1] or Reject("final anchor validation rejected"), create_attempted=True)
        raise
    except Exception as exc:
        if publication is not None and publication.fd >= 0:
            _fail_publication(binding, publication, exc, create_attempted=True)
        raise
    finally:
        if binding is not None:
            _close_binding(binding)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Provision an external Task #409 Phase-A consistency anchor")
    parser.add_argument("--phase-a-manifest", required=True)
    parser.add_argument("--phase-a-manifest-sha256", required=True)
    parser.add_argument("--phase-a-approval-digest", required=True)
    parser.add_argument("--phase-a-policy-sha256", required=True)
    parser.add_argument("--anchor-output", required=True)
    parser.add_argument("--decision", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
        result = provision_anchor(
            Path(args.phase_a_manifest),
            Path(args.anchor_output),
            manifest_sha256=args.phase_a_manifest_sha256,
            phase_a_approval_digest=args.phase_a_approval_digest,
            policy_sha256=args.phase_a_policy_sha256,
            decision=args.decision,
        )
        print("PASS: external Phase-A consistency approval anchor provisioned")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Reject as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, AssertionError) as exc:
        print(f"REJECT: unexpected anchor provisioning failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
