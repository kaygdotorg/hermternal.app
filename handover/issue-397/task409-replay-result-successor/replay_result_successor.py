#!/usr/bin/env python3
"""Run the retained driver through one boundary and publish final evidence.

The wrapper loads only pinned #404, #405, authority, and #400 source bytes. It
does not trust process output as repository evidence. After process success, it
stable-reads the pending record and uses the #400 reviewer to inspect the
retained repository. It creates final records only after all checks pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


BASE = Path(__file__).resolve().parents[1]
DRIVER_PATH = (
    BASE / "task409-retained-driver-successor" / "retained_driver_successor.py"
)
PHASE_A_RUNNER_PATH = (
    BASE / "task409-phase-a-anchor-successor" / "phase_a_anchor_runner.py"
)
GIT_AUTHORITY_PATH = (
    BASE
    / "task464-candidate5-git-config-successor"
    / "candidate5_git_config_successor.py"
)
DRIVER_SHA256 = "3e3dc1444879b416fa7e8e884a3523566ba9f4a9a96f2857380d8c4869917e20"
DERIVED_STDIN_SHA256 = (
    "ea10248929964a5570623de3ecd653cd3ba7348d3df565491a94816872647e2d"
)
PHASE_A_RUNNER_SHA256 = (
    "fb11d84062c05a2054a2f4162908de54ed15a530538fbf671ee54ff999baaf84"
)
GIT_AUTHORITY_SHA256 = (
    "b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a"
)

PENDING_SCHEMA = "hermternal.issue-397.replay-result.pending/v1"
RESULT_SCHEMA = "task409-execution-preflight/replay-result/v2"
RESULT_PHASE = "B-post-replay-detached-final-head"
RESULT_LANE = "candidate-4"
COMPLETION_SCHEMA = "hermternal.issue-397.replay-completion/v2"
SUCCESS_OUTPUT = b"TASK409_RETAINED_REPLAY_OK=1\n"
STDERR_POLICY = "empty"
RESULT_NAME = "replay-result.json"
COMPLETION_NAME = "replay-completion.json"
PENDING_NAME = "replay-result.pending.json"
RUN_PARENT = Path("/private/tmp")
RUN_PREFIX = "hermternal-task409-final-replay."
MAX_BYTES = 8 * 1024 * 1024
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
DIR_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink")

PENDING_KEYS = frozenset(
    {
        "schema",
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
COMPLETION_KEYS = frozenset(
    {
        "schema",
        "completion_marker",
        "stderr_policy",
        "returncode",
        "result_path",
        "result_sha256",
        "result_identity",
        "pending_path",
        "pending_sha256",
        "pending_identity",
        "driver_module_sha256",
        "driver_source_sha256",
        "markdown_sha256",
        "json_sha256",
        "shell_sha256",
        "provenance_sha256",
        "source_commit",
        "argv_sha256",
        "argv_bytes",
        "argv_count",
        "stdin_sha256",
        "stdin_bytes",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
        "phase_a_evidence_path",
        "phase_a_evidence_sha256",
    }
)


class Reject(Exception):
    """A fail-closed wrapper rejection with optional pending residue."""

    def __init__(self, message: str, pending_residue: Path | None = None) -> None:
        super().__init__(message)
        self.pending_residue = pending_residue


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _sha(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and SHA_RE.fullmatch(value) is not None,
        f"{label} must be 64 lowercase hexadecimal characters",
    )
    return value


def _oid(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and OID_RE.fullmatch(value) is not None,
        f"{label} must be 40 lowercase hexadecimal characters",
    )
    return value


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_uid),
        int(stat.S_IMODE(value.st_mode)),
        int(value.st_size),
        int(value.st_nlink),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _directory_identity(path: Path, label: str) -> dict[str, int]:
    path = _canonical(path, label)
    current = os.lstat(path)
    require(
        stat.S_ISDIR(current.st_mode) and not stat.S_ISLNK(current.st_mode),
        f"{label} is not a directory",
    )
    require(
        current.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == 0o700,
        f"{label} is not owned mode 0700",
    )
    return {
        "st_dev": int(current.st_dev),
        "st_ino": int(current.st_ino),
        "st_uid": int(current.st_uid),
        "st_mode": int(stat.S_IMODE(current.st_mode)),
        "st_nlink": int(current.st_nlink),
    }


def _canonical(path: Path, label: str) -> Path:
    path = Path(path)
    require(
        path.is_absolute() and os.path.realpath(path) == os.fspath(path),
        f"{label} is not canonical absolute",
    )
    return path


@dataclass(frozen=True)
class Snapshot:
    """Exact bytes and one complete stable file identity."""

    path: Path
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int, int, int]


def stable_read(
    path: Path,
    label: str,
    *,
    limit: int = MAX_BYTES,
    mode: int = 0o600,
) -> Snapshot:
    """Read one private single-link file three times without path following."""
    path = _canonical(path, label)
    snapshots: list[Snapshot] = []
    for _ in range(3):
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), f"{label} is not regular")
            require(
                before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == mode
                and before.st_nlink == 1,
                f"{label} owner, mode, or link count differs",
            )
            require(0 < before.st_size <= limit, f"{label} size differs")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(descriptor, min(131072, limit + 1 - total))
                if not block:
                    break
                total += len(block)
                require(total <= limit, f"{label} exceeds its byte limit")
                chunks.append(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = os.lstat(path)
        raw = b"".join(chunks)
        identity = _identity(before)
        require(
            identity == _identity(after) == _identity(final),
            f"{label} changed during read",
        )
        require(len(raw) == before.st_size, f"{label} byte count differs")
        snapshots.append(
            Snapshot(path, raw, hashlib.sha256(raw).hexdigest(), identity)
        )
    require(
        snapshots[0] == snapshots[1] == snapshots[2],
        f"{label} changed across reads",
    )
    return snapshots[0]


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, f"{label} has duplicate key {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"{label} is not strict UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), f"{label} root differs")
    return value


def _verified_module(path: Path, expected_sha256: str, name: str) -> types.ModuleType:
    snapshot = stable_read(path, name, mode=0o644)
    require(snapshot.sha256 == expected_sha256, f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = None
    sys.modules[name] = module
    exec(
        compile(snapshot.raw, os.fspath(path), "exec", dont_inherit=True),
        module.__dict__,
    )
    return module


@dataclass(frozen=True)
class Authority:
    """The verified derived driver, final authority, and #400 reviewer."""

    driver: types.ModuleType
    reviewer: types.ModuleType
    argv: tuple[str, ...]
    stdin: bytes
    driver_source_sha256: str
    derived_stdin_sha256: str
    markdown_sha256: str
    json_sha256: str
    shell_sha256: str
    provenance_sha256: str
    base_commit: str
    base_tree: str
    protected_main_commit: str
    source_commit: str
    required_ancestors: tuple[str, ...]
    forbidden_ancestors: tuple[str, ...]


def load_authority() -> Authority:
    """Verified-load exact pending-driver derivation and #400 authority."""
    driver = _verified_module(DRIVER_PATH, DRIVER_SHA256, "issue397_retained_driver")
    reviewer_module = _verified_module(
        GIT_AUTHORITY_PATH,
        GIT_AUTHORITY_SHA256,
        "issue397_retained_git_authority",
    )
    reviewer = reviewer_module.install_successor()
    frozen = driver.load_frozen_authority()
    contract = driver.derive_contract()
    require(contract.stdin == driver.transform_shell(frozen), "derived stdin differs")
    require(
        contract.argv == tuple(frozen.document["execution_driver"]["argv"]),
        "derived argv differs from authority",
    )
    require(
        contract.derived_sha256 == hashlib.sha256(contract.stdin).hexdigest(),
        "derived stdin digest differs",
    )
    require(
        contract.derived_sha256 == DERIVED_STDIN_SHA256,
        "derived stdin differs from the approved self-contained driver",
    )
    require(
        contract.source_sha256 == frozen.shell.sha256
        and contract.derived_sha256 != contract.source_sha256,
        "derived and source shell boundary differs",
    )
    base = frozen.document["base"]
    forbidden = frozen.document["forbidden_ancestry"]
    forbidden_values = tuple(
        dict.fromkeys(
            [*forbidden["commits"], *forbidden["raw_semantic_source_commits"]]
        )
    )
    source = next(
        (
            lane["source_commit"]["commit"]
            for lane in frozen.document["ordered_lanes"]
            if isinstance(lane.get("source_commit"), dict)
        ),
        None,
    )
    for value, label in (
        (base["commit"], "base commit"),
        (base["tree"], "base tree"),
        (base["protected_main_commit"], "protected main"),
        (source, "source commit"),
    ):
        _oid(value, label)
    require(
        all(OID_RE.fullmatch(value) for value in forbidden_values),
        "forbidden authority differs",
    )
    return Authority(
        driver=driver,
        reviewer=reviewer,
        argv=contract.argv,
        stdin=contract.stdin,
        driver_source_sha256=contract.source_sha256,
        derived_stdin_sha256=contract.derived_sha256,
        markdown_sha256=frozen.markdown.sha256,
        json_sha256=frozen.json.sha256,
        shell_sha256=frozen.shell.sha256,
        provenance_sha256=frozen.provenance.sha256,
        base_commit=base["commit"],
        base_tree=base["tree"],
        protected_main_commit=base["protected_main_commit"],
        source_commit=source,
        required_ancestors=(base["commit"],),
        forbidden_ancestors=forbidden_values,
    )


@dataclass(frozen=True)
class PhaseAEvidence:
    """Closed primitive bindings for the complete live #404 v2 file set."""

    snapshot: Snapshot
    manifest_sha256: str
    approval_digest: str
    live_record: Mapping[str, Any]


def _snapshot_record(snapshot: Snapshot) -> dict[str, Any]:
    """Convert one stable snapshot to a cross-module primitive record."""
    return {
        "path": os.fspath(snapshot.path),
        "sha256": snapshot.sha256,
        "bytes": len(snapshot.raw),
        "identity": list(snapshot.identity),
    }


def _authority_record(authority: Authority) -> dict[str, Any]:
    """Return the exact primitive authority values used across rereads."""
    return {
        "argv": list(authority.argv),
        "stdin_sha256": authority.derived_stdin_sha256,
        "stdin_bytes": len(authority.stdin),
        "driver_source_sha256": authority.driver_source_sha256,
        "markdown_sha256": authority.markdown_sha256,
        "json_sha256": authority.json_sha256,
        "shell_sha256": authority.shell_sha256,
        "provenance_sha256": authority.provenance_sha256,
        "base_commit": authority.base_commit,
        "base_tree": authority.base_tree,
        "protected_main_commit": authority.protected_main_commit,
        "source_commit": authority.source_commit,
        "required_ancestors": list(authority.required_ancestors),
        "forbidden_ancestors": list(authority.forbidden_ancestors),
    }


def _load_phase_a_evidence(path: Path, expected_sha256: str) -> PhaseAEvidence:
    """Load only the exact durable #404 v2 anchor evidence interface."""
    _sha(expected_sha256, "expected Phase A evidence SHA-256")
    runner = _verified_module(
        PHASE_A_RUNNER_PATH,
        PHASE_A_RUNNER_SHA256,
        "issue397_retained_phase_a_runner",
    )
    required_path = (
        runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD
    ).resolve()
    supplied_path = _canonical(path, "Phase A evidence")
    require(supplied_path == required_path, "Phase A evidence path differs from v2 authority")
    require(
        runner.EVIDENCE_SCHEMA == "hermternal.issue-397.phase-a-anchor-evidence.v2",
        "Phase A evidence schema differs from approved v2",
    )
    anchor_evidence = stable_read(supplied_path, "Phase A anchor evidence")
    require(anchor_evidence.sha256 == expected_sha256, "Phase A evidence SHA-256 differs")
    runner_anchor_evidence = runner.stable_read(
        supplied_path, "Phase A anchor evidence"
    )
    require(
        runner_anchor_evidence.raw == anchor_evidence.raw
        and runner_anchor_evidence.sha256 == anchor_evidence.sha256,
        "Phase A anchor evidence changed across validator loads",
    )
    record = runner._parse_closed_record(
        runner_anchor_evidence,
        "anchor",
        external_root=runner.EXTERNAL_ROOT,
    )
    inputs = record["inputs"]
    modules = runner.load_modules()
    root = runner.EXTERNAL_ROOT
    paths = {
        "phase_a_evidence": root / "evidence" / runner.PHASE_A_RECORD,
        "anchor_evidence": supplied_path,
        "manifest": root / "phase-a" / "input-manifest.json",
        "approval_anchor": root / "external-review" / runner.ANCHOR_NAME,
        "owner_marker": root / "phase-a" / ".owner",
    }
    snapshots = {
        name: stable_read(path.resolve(), f"Phase A {name.replace('_', ' ')}")
        for name, path in paths.items()
    }
    phase_record = runner._parse_closed_record(
        runner.stable_read(paths["phase_a_evidence"], "Phase A evidence"),
        "phase-a",
        external_root=root,
    )
    manifest, manifest_sha256 = modules.phase_a.load_manifest(paths["manifest"])
    require(
        manifest_sha256 == inputs["phase_a_manifest_sha256"]
        and snapshots["manifest"].sha256 == manifest_sha256
        and phase_record["observations"]["manifest"]["sha256"] == manifest_sha256,
        "live Phase A manifest digest differs",
    )
    require(
        snapshots["phase_a_evidence"].sha256 == record["prior_sha256"]
        == inputs["expected_phase_a_sha256"],
        "live Phase A evidence chain differs",
    )
    require(
        modules.phase_a.phase_a_approval_digest(manifest)
        == inputs["phase_a_approval_digest"],
        "live Phase A approval digest differs",
    )
    owner_value = runner._owner_value()
    require(
        snapshots["owner_marker"].raw == runner._canonical_json(owner_value)
        and snapshots["owner_marker"].sha256
        == phase_record["observations"]["owner_marker"]["sha256"],
        "live Phase A owner marker differs",
    )
    anchor_value = json.loads(
        snapshots["approval_anchor"].raw.decode("utf-8"),
        object_pairs_hook=lambda pairs: runner._unique_object(pairs, runner.ANCHOR_NAME),
    )
    require(
        set(anchor_value) == set(modules.anchor.ANCHOR_KEYS)
        and snapshots["approval_anchor"].raw
        == runner._canonical_json(record["observations"]["anchor"]["fields"])
        and snapshots["approval_anchor"].sha256
        == record["observations"]["anchor"]["sha256"],
        "live Phase A approval anchor fields differ",
    )
    directories = {
        os.fspath(path): runner._binding_record(
            runner._directory_identity(path, f"live Phase A directory {path.name}", exact_mode=0o700)
        )
        for path in (root, root / "phase-a", root / "external-review", root / "evidence")
    }
    require(
        phase_record["observations"]["external_root_binding"]
        == directories[os.fspath(root)]
        == record["observations"]["external_root_binding"]
        and phase_record["observations"]["runtime_directory_bindings"]
        == {key: value for key, value in directories.items() if key != os.fspath(root)},
        "live Phase A directory bindings differ",
    )
    live_record = {
        "schema": runner.EVIDENCE_SCHEMA,
        "files": {name: _snapshot_record(item) for name, item in snapshots.items()},
        "directories": directories,
        "manifest_sha256": manifest_sha256,
        "approval_digest": inputs["phase_a_approval_digest"],
        "anchor_sha256": snapshots["approval_anchor"].sha256,
        "owner_sha256": snapshots["owner_marker"].sha256,
    }
    return PhaseAEvidence(
        anchor_evidence,
        _sha(inputs["phase_a_manifest_sha256"], "Phase A manifest SHA-256"),
        _sha(inputs["phase_a_approval_digest"], "Phase A approval digest"),
        live_record,
    )


def load_phase_a_evidence(path: Path, expected_sha256: str) -> PhaseAEvidence:
    """Normalize every v2 evidence or filesystem failure to wrapper rejection."""
    try:
        return _load_phase_a_evidence(path, expected_sha256)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"Phase A live evidence rejected: {error}") from error


@dataclass(frozen=True)
class ProcessResult:
    """Actual child PID, return code, stdout bytes, and stderr bytes."""

    pid: int
    returncode: int
    stdout: bytes
    stderr: bytes


ProcessBoundary = Callable[[tuple[str, ...], bytes, Mapping[str, str]], ProcessResult]


def _run_process(
    argv: tuple[str, ...], stdin: bytes, environment: Mapping[str, str]
) -> ProcessResult:
    """Run one child while enforcing output limits during pipe reads."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env=dict(environment),
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise Reject("process pipes are unavailable")
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    input_view = memoryview(stdin)
    for stream in (process.stdin, process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    try:
        while selector.get_map():
            for key, _ in selector.select():
                stream = key.fileobj
                label = key.data
                if label == "stdin":
                    count = 1
                    if input_view:
                        try:
                            count = os.write(stream.fileno(), input_view[:131072])
                        except BrokenPipeError:
                            count = 0
                        input_view = input_view[count:]
                    if not input_view or count == 0:
                        selector.unregister(stream)
                        stream.close()
                    continue
                chunk = os.read(stream.fileno(), 131072)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                output[label].extend(chunk)
                if len(output[label]) > MAX_BYTES:
                    process.kill()
                    process.wait()
                    raise Reject(f"process {label} exceeds its byte limit")
        returncode = process.wait()
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    return ProcessResult(
        process.pid, returncode, bytes(output["stdout"]), bytes(output["stderr"])
    )


def _run_root(pid: int) -> Path:
    require(isinstance(pid, int) and not isinstance(pid, bool) and pid > 0, "process PID differs")
    return (RUN_PARENT / f"{RUN_PREFIX}{pid}").resolve()


def _pending_residue(pid: int) -> Path | None:
    path = _run_root(pid) / "replay-root" / PENDING_NAME
    return path if os.path.lexists(path) else None


def _reject_process(message: str, result: ProcessResult) -> None:
    raise Reject(message, _pending_residue(result.pid))


@dataclass(frozen=True)
class PendingFacts:
    """Closed pending values read from the retained driver output."""

    snapshot: Snapshot
    replay_root: Path
    repository: Path
    value: Mapping[str, Any]


def _validate_directory_claim(
    claim: Any, observed: Mapping[str, int], label: str
) -> None:
    require(isinstance(claim, dict) and set(claim) == set(DIR_FIELDS), f"{label} fields differ")
    require(
        all(
            isinstance(claim[key], int)
            and not isinstance(claim[key], bool)
            and claim[key] >= 0
            for key in DIR_FIELDS
        ),
        f"{label} scalar type differs",
    )
    require(dict(claim) == dict(observed), f"{label} differs")


def load_pending(result: ProcessResult, authority: Authority) -> PendingFacts:
    """Stable-read and validate the pending driver record against authority."""
    run_root = _run_root(result.pid)
    replay_root = run_root / "replay-root"
    repository = run_root / "repository"
    require(run_root.parent == RUN_PARENT.resolve(), "run root parent differs")
    require(replay_root.parent == repository.parent == run_root, "retained roots differ")
    replay_identity = _directory_identity(replay_root, "replay root")
    repository_identity = _directory_identity(repository, "retained repository")
    snapshot = stable_read(replay_root / PENDING_NAME, "pending replay result")
    value = _strict_json(snapshot.raw, "pending replay result")
    require(set(value) == PENDING_KEYS, "pending replay result fields differ")
    require(value["schema"] == PENDING_SCHEMA, "pending replay result schema differs")
    require(value["replay_root"] == os.fspath(replay_root), "pending replay root differs")
    require(value["repository"] == os.fspath(repository), "pending repository differs")
    _validate_directory_claim(
        value["replay_root_identity"], replay_identity, "pending replay root identity"
    )
    _validate_directory_claim(
        value["repository_identity"],
        repository_identity,
        "pending repository identity",
    )
    require(value["head_state"] == "detached", "pending HEAD state differs")
    for key in ("final_head", "parent", "tree"):
        _oid(value[key], f"pending {key}")
    require(value["base_commit"] == authority.base_commit, "pending base commit differs")
    require(value["base_tree"] == authority.base_tree, "pending base tree differs")
    require(
        value["protected_main_commit"] == authority.protected_main_commit,
        "pending protected main differs",
    )
    require(
        value["required_ancestors"] == list(authority.required_ancestors),
        "pending required ancestry differs",
    )
    require(
        value["forbidden_ancestors"] == list(authority.forbidden_ancestors),
        "pending forbidden ancestry differs",
    )
    return PendingFacts(snapshot, replay_root, repository, value)


def reobserve_repository(pending: PendingFacts, authority: Authority) -> dict[str, str]:
    """Use the pinned #400 reviewer for fresh read-only repository checks."""
    reviewer = authority.reviewer
    try:
        identity = reviewer.inspect_metadata(pending.repository, "retained replay")
        guard = reviewer.RepoGuard(identity)
        reviewer.check_worktree_registry(pending.repository, identity, guard)
        reviewer.check_clean(pending.repository, guard)
        reviewer.check_index_flags(pending.repository, guard)
        reviewer._check_repo_shape(pending.repository, identity, guard)
        policy = {
            "base_ref": "refs/remotes/origin/dev",
            "main_ref": "refs/remotes/origin/main",
            "base_commit": authority.base_commit,
            "base_tree": authority.base_tree,
            "main_commit": authority.protected_main_commit,
        }
        reviewer._check_origin_and_base(
            pending.repository, "retained replay", guard, policy=policy
        )
        head_snapshot = reviewer.read_bound_file(
            pending.repository / ".git" / "HEAD", "retained detached HEAD"
        )
        reviewer.require(
            head_snapshot.identity == identity.head_snapshot.identity
            and head_snapshot.sha256 == identity.head_snapshot.sha256
            and head_snapshot.raw == identity.head_snapshot.raw,
            "retained HEAD differs from inspected bytes",
        )
        reviewer.require(
            re.fullmatch(rb"[0-9a-f]{40}\n", head_snapshot.raw) is not None,
            "retained HEAD is not an exact detached object ID",
        )
        final_head = head_snapshot.raw[:-1].decode("ascii")
        symbolic = reviewer.run_git(
            pending.repository, ["symbolic-ref", "-q", "HEAD"], guard=guard
        )
        reviewer.require(
            symbolic.returncode == 1 and not symbolic.stdout and not symbolic.stderr,
            "retained HEAD is attached",
        )
        reviewer._assert_oid_type(
            pending.repository, final_head, "commit", "retained final HEAD", guard
        )
        parent_fields = reviewer._decode(
            reviewer.git_output(
                pending.repository,
                ["rev-list", "--parents", "-n", "1", final_head],
                guard=guard,
            ),
            "retained parent record",
        ).split()
        reviewer.require(
            len(parent_fields) == 2 and parent_fields[0] == final_head,
            "retained final HEAD parent count differs",
        )
        parent = _oid(parent_fields[1], "observed parent")
        tree = reviewer._rev_parse(
            pending.repository,
            f"{final_head}^{{tree}}",
            "retained final tree",
            guard,
        )
        reviewer._assert_oid_type(
            pending.repository, parent, "commit", "retained parent", guard
        )
        reviewer._assert_oid_type(
            pending.repository, tree, "tree", "retained final tree", guard
        )
        for ancestor in authority.required_ancestors:
            reviewer._check_ancestry(
                pending.repository,
                final_head,
                ancestor,
                forbidden=False,
                guard=guard,
            )
        for ancestor in authority.forbidden_ancestors:
            reviewer._check_ancestry(
                pending.repository,
                final_head,
                ancestor,
                forbidden=True,
                guard=guard,
            )
        reviewer._check_fsck(pending.repository, identity, guard)
        reviewer._check_explicit_closure(pending.repository, final_head, guard)
        guard.assert_stable()
        observed_directory = reviewer.directory_identity(identity)
    except reviewer.Reject as error:
        raise Reject(f"#400 retained repository review rejected: {error}") from error
    _validate_directory_claim(
        pending.value["repository_identity"],
        observed_directory,
        "reviewed repository identity",
    )
    observed = {"final_head": final_head, "parent": parent, "tree": tree}
    require(
        observed
        == {
            "final_head": pending.value["final_head"],
            "parent": pending.value["parent"],
            "tree": pending.value["tree"],
        },
        "pending Git facts differ from #400 observations",
    )
    return observed


@dataclass(frozen=True)
class ProcessEvidence:
    """Hashes and byte counts for the one actual process observation."""

    argv_sha256: str
    argv_bytes: int
    argv_count: int
    stdin_sha256: str
    stdin_bytes: int
    stdout_sha256: str
    stdout_bytes: int
    stderr_sha256: str
    stderr_bytes: int


def validate_process(
    result: ProcessResult, authority: Authority
) -> ProcessEvidence:
    """Require exact success, sole stdout marker, and empty stderr."""
    require(isinstance(result, ProcessResult), "process boundary result differs")
    _run_root(result.pid)
    require(
        isinstance(result.returncode, int) and not isinstance(result.returncode, bool),
        "process return code differs",
    )
    require(isinstance(result.stdout, bytes), "process stdout is not bytes")
    require(isinstance(result.stderr, bytes), "process stderr is not bytes")
    if result.returncode != 0:
        _reject_process(f"retained driver returned rc={result.returncode}", result)
    if result.stdout != SUCCESS_OUTPUT:
        _reject_process("retained driver stdout is not the sole success marker", result)
    if result.stderr:
        _reject_process("retained driver stderr is not empty", result)
    require(
        len(result.stdout) <= MAX_BYTES and len(result.stderr) <= MAX_BYTES,
        "process output exceeds its byte limit",
    )
    argv_raw = b"".join(item.encode("utf-8") + b"\0" for item in authority.argv)
    return ProcessEvidence(
        hashlib.sha256(argv_raw).hexdigest(),
        len(argv_raw),
        len(authority.argv),
        hashlib.sha256(authority.stdin).hexdigest(),
        len(authority.stdin),
        hashlib.sha256(result.stdout).hexdigest(),
        len(result.stdout),
        hashlib.sha256(result.stderr).hexdigest(),
        len(result.stderr),
    )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _result_bytes(pending: PendingFacts, phase_a: PhaseAEvidence) -> bytes:
    value = {
        "schema": RESULT_SCHEMA,
        "phase": RESULT_PHASE,
        "lane": RESULT_LANE,
        "phase_a_manifest_sha256": phase_a.manifest_sha256,
        "phase_a_approval_digest": phase_a.approval_digest,
        **{key: pending.value[key] for key in PENDING_KEYS if key != "schema"},
    }
    require(set(value) == RESULT_KEYS, "final replay result fields differ")
    return _canonical_json(value)


def _file_identity(snapshot: Snapshot) -> dict[str, int]:
    return {
        "st_dev": snapshot.identity[0],
        "st_ino": snapshot.identity[1],
        "st_uid": snapshot.identity[2],
        "st_mode": snapshot.identity[3],
        "st_size": snapshot.identity[4],
        "st_nlink": snapshot.identity[5],
    }


def _completion_bytes(
    result_snapshot: Snapshot,
    pending: PendingFacts,
    authority: Authority,
    phase_a: PhaseAEvidence,
    process: ProcessEvidence,
) -> bytes:
    value = {
        "schema": COMPLETION_SCHEMA,
        "completion_marker": SUCCESS_OUTPUT.decode("ascii").rstrip("\n"),
        "stderr_policy": STDERR_POLICY,
        "returncode": 0,
        "result_path": os.fspath(result_snapshot.path),
        "result_sha256": result_snapshot.sha256,
        "result_identity": _file_identity(result_snapshot),
        "pending_path": os.fspath(pending.snapshot.path),
        "pending_sha256": pending.snapshot.sha256,
        "pending_identity": _file_identity(pending.snapshot),
        "driver_module_sha256": DRIVER_SHA256,
        "driver_source_sha256": authority.driver_source_sha256,
        "markdown_sha256": authority.markdown_sha256,
        "json_sha256": authority.json_sha256,
        "shell_sha256": authority.shell_sha256,
        "provenance_sha256": authority.provenance_sha256,
        "source_commit": authority.source_commit,
        "argv_sha256": process.argv_sha256,
        "argv_bytes": process.argv_bytes,
        "argv_count": process.argv_count,
        "stdin_sha256": process.stdin_sha256,
        "stdin_bytes": process.stdin_bytes,
        "stdout_sha256": process.stdout_sha256,
        "stdout_bytes": process.stdout_bytes,
        "stderr_sha256": process.stderr_sha256,
        "stderr_bytes": process.stderr_bytes,
        "phase_a_evidence_path": os.fspath(phase_a.snapshot.path),
        "phase_a_evidence_sha256": phase_a.snapshot.sha256,
    }
    require(set(value) == COMPLETION_KEYS, "replay completion fields differ")
    return _canonical_json(value)


def _write_new(
    path: Path,
    raw: bytes,
    label: str,
    own: Callable[[Path, tuple[int, int]], None],
) -> Snapshot:
    """Create one file and report ownership immediately after descriptor open."""
    require(not os.path.lexists(path), f"{label} already exists")
    parent_fd = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    descriptor = -1
    owned: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            path.name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        owned = (int(opened.st_dev), int(opened.st_ino))
        own(path, owned)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, f"{label} write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
    snapshot = stable_read(path, label)
    require(snapshot.raw == raw, f"{label} bytes differ after create")
    if owned is None:
        raise AssertionError("new file ownership was not recorded")
    return snapshot


def _remove_owned(path: Path, owned: tuple[int, int]) -> bool:
    """Remove only an exact file inode that this publication created."""
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return True
    if (
        not stat.S_ISREG(current.st_mode)
        or (int(current.st_dev), int(current.st_ino)) != owned
    ):
        return False
    os.unlink(path)
    return not os.path.lexists(path)


@dataclass(frozen=True)
class Publication:
    """Stable snapshots of both final retained records."""

    result: Snapshot
    completion: Snapshot


def publish_final(
    pending: PendingFacts,
    authority: Authority,
    phase_a: PhaseAEvidence,
    process: ProcessEvidence,
    final_validator: Callable[[Publication], None] | None = None,
) -> Publication:
    """Create both final files or remove only this call's owned partial files."""
    result_path = pending.replay_root / RESULT_NAME
    completion_path = pending.replay_root / COMPLETION_NAME
    require(
        not os.path.lexists(result_path) and not os.path.lexists(completion_path),
        "a final replay record already exists",
    )
    owned: list[tuple[Path, tuple[int, int]]] = []
    def own(path: Path, inode: tuple[int, int]) -> None:
        owned.append((path, inode))

    try:
        result = _write_new(
            result_path, _result_bytes(pending, phase_a), "replay result", own
        )
        completion = _write_new(
            completion_path,
            _completion_bytes(result, pending, authority, phase_a, process),
            "replay completion",
            own,
        )
        parent_fd = os.open(
            pending.replay_root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        publication = Publication(
            stable_read(result_path, "final replay result"),
            stable_read(completion_path, "final replay completion"),
        )
        require(publication.result == result, "final replay result changed")
        require(publication.completion == completion, "final replay completion changed")
        verify_publication(publication, pending)
        if final_validator is not None:
            final_validator(publication)
        return publication
    except BaseException as primary:
        residue: list[str] = []
        for path, inode in reversed(owned):
            try:
                if not _remove_owned(path, inode):
                    residue.append(os.fspath(path))
            except OSError:
                residue.append(os.fspath(path))
        try:
            parent_fd = os.open(
                pending.replay_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            residue.extend(
                os.fspath(path) for path, _ in owned if os.path.lexists(path)
            )
        suffix = f"; final residue={sorted(set(residue))!r}" if residue else ""
        raise Reject(
            f"final publication failed: {primary}{suffix}", pending.snapshot.path
        ) from primary


def verify_publication(publication: Publication, pending: PendingFacts) -> None:
    """Stable-reread and bind both final records to the retained pending file."""
    result = stable_read(publication.result.path, "replay result verification")
    completion = stable_read(
        publication.completion.path, "replay completion verification"
    )
    require(result == publication.result, "published replay result changed")
    require(completion == publication.completion, "published completion changed")
    result_value = _strict_json(result.raw, "published replay result")
    completion_value = _strict_json(completion.raw, "published replay completion")
    require(
        set(result_value) == RESULT_KEYS and result_value["schema"] == RESULT_SCHEMA,
        "published replay result schema differs",
    )
    require(
        set(completion_value) == COMPLETION_KEYS
        and completion_value["schema"] == COMPLETION_SCHEMA,
        "published replay completion schema differs",
    )
    require(
        completion_value["result_path"] == os.fspath(result.path)
        and completion_value["result_sha256"] == result.sha256
        and completion_value["result_identity"] == _file_identity(result),
        "completion result binding differs",
    )
    require(
        completion_value["pending_path"] == os.fspath(pending.snapshot.path)
        and completion_value["pending_sha256"] == pending.snapshot.sha256
        and completion_value["pending_identity"] == _file_identity(pending.snapshot),
        "completion pending binding differs",
    )


def _verify_live_inputs(
    pending: PendingFacts,
    authority_record: Mapping[str, Any],
    phase_a: PhaseAEvidence,
    expected_phase_a_evidence_sha256: str,
    repository_observation: Mapping[str, str],
) -> None:
    """Reauthenticate every live input through closed primitive records."""
    require(
        _snapshot_record(stable_read(pending.snapshot.path, "pending live reread"))
        == _snapshot_record(pending.snapshot),
        "pending replay result changed during live verification",
    )
    require(
        reobserve_repository(pending, load_authority()) == repository_observation,
        "retained repository observations changed during live verification",
    )
    current_authority = load_authority()
    require(
        _authority_record(current_authority) == dict(authority_record),
        "authority changed during live verification",
    )
    current_phase_a = load_phase_a_evidence(
        phase_a.snapshot.path, expected_phase_a_evidence_sha256
    )
    require(
        dict(current_phase_a.live_record) == dict(phase_a.live_record)
        and _snapshot_record(current_phase_a.snapshot)
        == _snapshot_record(phase_a.snapshot),
        "Phase A live file set changed during verification",
    )


def execute_and_publish(
    phase_a_evidence: Path,
    expected_phase_a_evidence_sha256: str,
    *,
    process_boundary: ProcessBoundary = _run_process,
) -> Publication:
    """Execute one exact retained driver call and publish validated evidence."""
    result: ProcessResult | None = None
    try:
        phase_a = load_phase_a_evidence(
            phase_a_evidence, expected_phase_a_evidence_sha256
        )
        authority = load_authority()
        authority_record = _authority_record(authority)
        environment: Mapping[str, str] = {}
        result = process_boundary(authority.argv, authority.stdin, environment)
        process = validate_process(result, authority)
        pending = load_pending(result, authority)
        observed = reobserve_repository(pending, authority)
        _verify_live_inputs(
            pending,
            authority_record,
            phase_a,
            expected_phase_a_evidence_sha256,
            observed,
        )
        publication = publish_final(
            pending,
            authority,
            phase_a,
            process,
            final_validator=lambda _publication: _verify_live_inputs(
                pending,
                authority_record,
                phase_a,
                expected_phase_a_evidence_sha256,
                observed,
            ),
        )
        return publication
    except Reject as error:
        if error.pending_residue is not None:
            raise
        residue = _pending_residue(result.pid) if result is not None else None
        raise Reject(str(error), residue) from error
    except Exception as error:
        residue = _pending_residue(result.pid) if result is not None else None
        raise Reject(f"wrapper input or filesystem failure: {error}", residue) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one retained replay and publish checked final evidence."
    )
    parser.add_argument("--phase-a-evidence", type=Path, required=True)
    parser.add_argument("--expected-phase-a-evidence-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        publication = execute_and_publish(
            args.phase_a_evidence,
            args.expected_phase_a_evidence_sha256,
        )
    except Reject as error:
        print(f"REJECT: {error}", file=sys.stderr)
        if error.pending_residue is not None:
            print(f"PENDING_RESIDUE={error.pending_residue}", file=sys.stderr)
        return 2
    print(f"PASS: {publication.result.path}")
    print(f"COMPLETION: {publication.completion.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
