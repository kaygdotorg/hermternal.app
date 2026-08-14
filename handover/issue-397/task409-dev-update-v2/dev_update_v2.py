#!/usr/bin/env python3
"""Plan, then verify, one normal update of ``origin/dev`` after #406 v3.

This module never invokes ``git push``.  It returns one fixed refspec only
after it validates a final, hash-pinned #406 report, its #405 chain, local
identity, and an initial remote readback.  A separate operator action can use
that argv.  The post-readback mode records what that external action changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


BASE_DEV = "729f2613af2b78d58b07918478e9102d5716f367"
BASE_DEV_TREE = "43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f"
PROTECTED_MAIN = "3ebf8b3fe4767442490ab3053c0c1ccf84e8019f"
OFFLINE_REPORT_SCHEMA = "hermternal.issue-397.offline-gates/v3"
PIN_SCHEMA = "hermternal.issue-397.dev-update/v2-offline-report-pin"
PLAN_SCHEMA = "hermternal.issue-397.dev-update-plan/v2"
REPORT_SCHEMA = "hermternal.issue-397.dev-update-report/v2"
PRE_READBACK_SCHEMA = "hermternal.issue-397.dev-update-pre-readback/v2"
POST_READBACK_SCHEMA = "hermternal.issue-397.dev-update-post-readback/v2"
PIN_PATH = Path(__file__).with_name("final-offline-report-pin.json")
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 8 * 1024 * 1024
SAFE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/dev/null",
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
}
RESULT_KEYS = frozenset({
    "schema", "phase", "lane", "phase_a_manifest_sha256",
    "phase_a_approval_digest", "replay_root", "replay_root_identity",
    "repository", "repository_identity", "head_state", "final_head",
    "parent", "tree", "base_commit", "base_tree", "protected_main_commit",
    "required_ancestors", "forbidden_ancestors",
})
COMPLETION_KEYS = frozenset({
    "schema", "completion_marker", "stderr_policy", "returncode",
    "result_path", "result_sha256", "result_identity", "pending_path",
    "pending_sha256", "pending_identity", "driver_module_sha256",
    "driver_source_sha256", "markdown_sha256", "json_sha256", "shell_sha256",
    "provenance_sha256", "source_commit", "argv_sha256", "argv_bytes",
    "argv_count", "stdin_sha256", "stdin_bytes", "stdout_sha256",
    "stdout_bytes", "stderr_sha256", "stderr_bytes", "phase_a_evidence_path",
    "phase_a_evidence_sha256",
})
GATE_IDS = (
    "git-head", "git-tree", "git-main", "git-dev-base", "git-clean",
    "git-fsck", "web-typecheck", "web-unit", "web-build", "privacy-redaction",
    "accessibility", "no-network-browser", "auth-click-enter",
)


class Reject(Exception):
    """A deliberate, fail-closed dev-update rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _oid(value: Any, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value) is not None, f"{label} differs")
    return value


def _sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None, f"{label} differs")
    return value


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    """Decode a JSON object while rejecting duplicate keys and non-UTF-8 bytes."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, f"{label} has duplicate key {key}")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"{label} is not strict UTF-8 JSON") from error
    require(isinstance(value, dict), f"{label} is not an object")
    return value


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int, int, int]


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode),
        value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns,
    )


def stable_read(path: Path, label: str, *, mode: int, limit: int = MAX_BYTES) -> Snapshot:
    """Read a private record repeatedly, with no link or replacement race."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path differs")
    reads: list[Snapshot] = []
    for _ in range(3):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"{label} file type differs")
            require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == mode, f"{label} owner or mode differs")
            require(0 < before.st_size <= limit, f"{label} size differs")
            raw = bytearray()
            while True:
                block = os.read(descriptor, min(131072, limit + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                require(len(raw) <= limit, f"{label} exceeds byte limit")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = os.lstat(path)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} changed during read")
        reads.append(Snapshot(path, bytes(raw), hashlib.sha256(raw).hexdigest(), _identity(before)))
    require(reads[0] == reads[1] == reads[2], f"{label} changed across reads")
    return reads[0]


@dataclass(frozen=True)
class Pin:
    report_path: Path
    report_sha256: str
    report_schema: str
    commit: str
    tree: str
    source_commit: str
    result_path: Path
    result_sha256: str
    completion_path: Path
    completion_sha256: str


def _canonical_private_path(value: Any, label: str) -> Path:
    require(isinstance(value, str) and value, f"{label} path differs")
    path = Path(value)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path differs")
    return path


def _pin_record(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping) and set(value) == keys, f"{label} fields differ")
    return value


def load_pin(path: Path = PIN_PATH) -> Pin:
    """Load the sole finalization record. Deferred data is not an authority."""
    snapshot = stable_read(Path(path).resolve(), "#406 v3 pin", mode=0o644, limit=64 * 1024)
    value = strict_json(snapshot.raw, "#406 v3 pin")
    require(set(value) == {"schema", "status", "report", "candidate", "chain"}, "#406 v3 pin schema differs")
    require(value["schema"] == PIN_SCHEMA and value["status"] == "final", "#406 v3 pin is not final")
    report = _pin_record(value["report"], {"path", "sha256", "schema"}, "#406 v3 report pin")
    candidate = _pin_record(value["candidate"], {"commit", "tree", "source_commit"}, "candidate pin")
    chain = _pin_record(value["chain"], {"result", "completion"}, "#405 chain pin")
    result = _pin_record(chain["result"], {"path", "sha256"}, "#405 result pin")
    completion = _pin_record(chain["completion"], {"path", "sha256"}, "#405 completion pin")
    require(report["schema"] == OFFLINE_REPORT_SCHEMA, "#406 v3 report schema pin differs")
    return Pin(
        _canonical_private_path(report["path"], "#406 v3 report"), _sha(report["sha256"], "#406 v3 report SHA-256"), report["schema"],
        _oid(candidate["commit"], "candidate commit"), _oid(candidate["tree"], "candidate tree"), _oid(candidate["source_commit"], "candidate source commit"),
        _canonical_private_path(result["path"], "#405 result"), _sha(result["sha256"], "#405 result SHA-256"),
        _canonical_private_path(completion["path"], "#405 completion"), _sha(completion["sha256"], "#405 completion SHA-256"),
    )


@dataclass(frozen=True)
class Candidate:
    commit: str
    tree: str
    source_commit: str
    report: Snapshot
    result: Snapshot
    completion: Snapshot


def _validate_input_record(value: Any, snapshot: Snapshot, label: str) -> None:
    record = _pin_record(value, {"path", "sha256"}, label)
    require(record["path"] == os.fspath(snapshot.path) and record["sha256"] == snapshot.sha256, f"{label} binding differs")


def _validate_gates(value: Any) -> None:
    require(isinstance(value, list) and len(value) == len(GATE_IDS), "#406 gate count differs")
    ids: list[str] = []
    for gate in value:
        require(isinstance(gate, Mapping) and set(gate) == {"id", "argv", "exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes"}, "#406 gate schema differs")
        require(isinstance(gate["id"], str) and isinstance(gate["argv"], list), "#406 gate identity differs")
        require(gate["exit_code"] == 0 and isinstance(gate["stdout_bytes"], int) and gate["stdout_bytes"] >= 0 and isinstance(gate["stderr_bytes"], int) and gate["stderr_bytes"] >= 0, "#406 gate outcome differs")
        _sha(gate["stdout_sha256"], "#406 gate stdout SHA-256")
        _sha(gate["stderr_sha256"], "#406 gate stderr SHA-256")
        ids.append(gate["id"])
    require(tuple(ids) == GATE_IDS, "#406 gate IDs or order differs")


def _validate_semantic_evidence(value: Any) -> None:
    semantic = _pin_record(value, {"checks", "sources"}, "#406 semantic evidence")
    checks = _pin_record(semantic["checks"], {"click", "enter", "clearing", "redaction", "accessibility", "privacy_policy", "screenshot_contract"}, "#406 semantic checks")
    require(all(item is True for item in checks.values()), "#406 semantic checks differ")
    sources = _pin_record(semantic["sources"], {"auth", "privacy", "screenshots"}, "#406 semantic sources")
    for label, source in sources.items():
        record = _pin_record(source, {"path", "sha256", "identity", "git_mode", "git_blob"}, f"#406 semantic {label}")
        require(isinstance(record["path"], str) and record["path"], f"#406 semantic {label} path differs")
        _sha(record["sha256"], f"#406 semantic {label} SHA-256")
        require(isinstance(record["identity"], list) and len(record["identity"]) == 8 and all(isinstance(item, int) for item in record["identity"]), f"#406 semantic {label} identity differs")
        require(record["git_mode"] == "100644", f"#406 semantic {label} Git mode differs")
        _oid(record["git_blob"], f"#406 semantic {label} Git blob")


def validate_offline_report(pin: Pin) -> Candidate:
    """Authenticate one exact v3 PASS report and its #405 result/completion chain."""
    report = stable_read(pin.report_path, "#406 v3 report", mode=0o600)
    require(report.sha256 == pin.report_sha256, "#406 v3 report SHA-256 differs")
    result = stable_read(pin.result_path, "#405 result", mode=0o600)
    completion = stable_read(pin.completion_path, "#405 completion", mode=0o600)
    require(result.sha256 == pin.result_sha256 and completion.sha256 == pin.completion_sha256, "#405 chain SHA-256 differs")
    value = strict_json(report.raw, "#406 v3 report")
    expected = {"schema", "status", "network", "credentials", "gate_list_sha256", "repository", "repository_identity", "final_head", "final_tree", "protected_main", "expected_dev_base", "dev_target", "inputs", "semantic_evidence", "gates"}
    require(set(value) == expected and value["schema"] == pin.report_schema and value["status"] == "passed", "#406 v3 report schema or status differs")
    require(value["network"] == "not-used" and value["credentials"] == "not-used", "#406 v3 safety fields differ")
    require(value["final_head"] == pin.commit and value["final_tree"] == pin.tree and value["dev_target"] == pin.commit, "#406 v3 candidate identity differs")
    require(value["protected_main"] == PROTECTED_MAIN and value["expected_dev_base"] == BASE_DEV, "#406 v3 protected refs differ")
    _sha(value["gate_list_sha256"], "#406 gate list SHA-256")
    require(isinstance(value["repository"], str) and value["repository"], "#406 repository differs")
    require(isinstance(value["repository_identity"], list) and len(value["repository_identity"]) == 8 and all(isinstance(item, int) for item in value["repository_identity"]), "#406 repository identity differs")
    inputs = _pin_record(value["inputs"], {"result", "completion", "phase_a_anchor", "provenance"}, "#406 inputs")
    _validate_input_record(inputs["result"], result, "#406 result input")
    _validate_input_record(inputs["completion"], completion, "#406 completion input")
    for label in ("phase_a_anchor", "provenance"):
        record = _pin_record(inputs[label], {"path", "sha256"}, f"#406 {label} input")
        require(isinstance(record["path"], str) and record["path"], f"#406 {label} path differs")
        _sha(record["sha256"], f"#406 {label} SHA-256")
    _validate_semantic_evidence(value["semantic_evidence"])
    _validate_gates(value["gates"])
    result_value, completion_value = strict_json(result.raw, "#405 result"), strict_json(completion.raw, "#405 completion")
    require(set(result_value) == RESULT_KEYS and result_value["final_head"] == pin.commit and result_value["tree"] == pin.tree, "#405 result identity differs")
    require(result_value["base_commit"] == BASE_DEV and result_value["base_tree"] == BASE_DEV_TREE and result_value["protected_main_commit"] == PROTECTED_MAIN, "#405 result base differs")
    require(set(completion_value) == COMPLETION_KEYS and completion_value["returncode"] == 0, "#405 completion schema differs")
    require(completion_value["result_path"] == os.fspath(result.path) and completion_value["result_sha256"] == result.sha256, "#405 completion result binding differs")
    require(completion_value["source_commit"] == pin.source_commit, "#405 completion source differs")
    return Candidate(pin.commit, pin.tree, pin.source_commit, report, result, completion)


Run = Callable[..., subprocess.CompletedProcess[bytes]]


def _git(run: Run, repository: Path, args: Sequence[str]) -> str:
    result = run(("/usr/bin/git", "-C", os.fspath(repository), *args), cwd=repository, env=dict(SAFE_ENV), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    require(result.returncode == 0, f"Git observation failed: {' '.join(args)}")
    return bytes(result.stdout or b"").decode("ascii", "strict").strip()


def _remote_oid(run: Run, repository: Path, ref: str, label: str) -> str:
    observed = _git(run, repository, ("ls-remote", "--refs", "origin", ref))
    fields = observed.split("\t")
    require(len(fields) == 2 and fields[1] == ref, f"{label} remote readback differs")
    return _oid(fields[0], f"{label} remote OID")


def validate_refspec(candidate: Candidate) -> tuple[str, ...]:
    """Return the sole permitted normal push argv; this module never executes it."""
    refspec = f"{candidate.commit}:refs/heads/dev"
    require(OID_RE.fullmatch(candidate.commit) is not None, "candidate commit differs")
    return ("/usr/bin/git", "push", "--porcelain", "origin", refspec)


def preflight(pin: Pin, repository: Path, run: Run = subprocess.run) -> dict[str, Any]:
    """Validate all #406, local, and initial remote gates before yielding argv."""
    candidate = validate_offline_report(pin)
    repository = Path(repository).resolve(strict=True)
    observed = {
        "top": _git(run, repository, ("rev-parse", "--show-toplevel")),
        "head": _git(run, repository, ("rev-parse", "HEAD^{commit}")),
        "candidate": _git(run, repository, ("rev-parse", f"{candidate.commit}^{{commit}}")),
        "candidate_tree": _git(run, repository, ("rev-parse", f"{candidate.commit}^{{tree}}")),
        "source": _git(run, repository, ("rev-parse", f"{candidate.source_commit}^{{commit}}")),
        "dev": _git(run, repository, ("rev-parse", "refs/remotes/origin/dev^{commit}")),
        "dev_tree": _git(run, repository, ("rev-parse", "refs/remotes/origin/dev^{tree}")),
        "main": _git(run, repository, ("rev-parse", "refs/remotes/origin/main^{commit}")),
        "status": _git(run, repository, ("status", "--porcelain=v1", "--untracked-files=all")),
        "ancestor": _git(run, repository, ("merge-base", "--is-ancestor", BASE_DEV, candidate.commit)),
    }
    require(observed == {"top": os.fspath(repository), "head": candidate.commit, "candidate": candidate.commit, "candidate_tree": candidate.tree, "source": candidate.source_commit, "dev": BASE_DEV, "dev_tree": BASE_DEV_TREE, "main": PROTECTED_MAIN, "status": "", "ancestor": ""}, "local candidate or tracked refs differ")
    remote_dev, remote_main = _remote_oid(run, repository, "refs/heads/dev", "origin/dev"), _remote_oid(run, repository, "refs/heads/main", "origin/main")
    require(remote_dev == BASE_DEV and remote_main == PROTECTED_MAIN, "initial remote refs differ")
    return {
        "schema": PLAN_SCHEMA,
        "status": "ready",
        "candidate": {"commit": candidate.commit, "tree": candidate.tree, "source_commit": candidate.source_commit},
        "offline_report": {"path": os.fspath(candidate.report.path), "sha256": candidate.report.sha256, "schema": pin.report_schema},
        "chain": {"result": {"path": os.fspath(candidate.result.path), "sha256": candidate.result.sha256}, "completion": {"path": os.fspath(candidate.completion.path), "sha256": candidate.completion.sha256}},
        "pre_remote_readback": {"schema": PRE_READBACK_SCHEMA, "origin_dev": {"commit": remote_dev, "tree": BASE_DEV_TREE}, "origin_main": {"commit": remote_main}},
        "push": {"mode": "normal-non-force", "argv": list(validate_refspec(candidate)), "executed": False},
    }


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_new(path: Path, value: Mapping[str, Any], label: str) -> Snapshot:
    """Create one private evidence file. Existing paths are always rejected."""
    path = Path(path).resolve()
    parent = os.lstat(path.parent)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, f"{label} parent differs")
    raw = _canonical_bytes(value)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as error:
        raise Reject(f"{label} already exists") from error
    except OSError as error:
        raise Reject(f"{label} creation failed") from error
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    snapshot = stable_read(path, label, mode=0o600)
    require(snapshot.raw == raw, f"{label} changed after create")
    return snapshot


def write_plan(path: Path, plan: Mapping[str, Any]) -> Snapshot:
    validate_plan(plan)
    return write_new(path, plan, "dev-update plan")


def validate_plan(value: Mapping[str, Any]) -> None:
    expected = {"schema", "status", "candidate", "offline_report", "chain", "pre_remote_readback", "push"}
    require(set(value) == expected and value["schema"] == PLAN_SCHEMA and value["status"] == "ready", "dev-update plan schema differs")
    candidate = _pin_record(value["candidate"], {"commit", "tree", "source_commit"}, "plan candidate")
    for key in candidate:
        _oid(candidate[key], f"plan candidate {key}")
    report = _pin_record(value["offline_report"], {"path", "sha256", "schema"}, "plan offline report")
    require(report["schema"] == OFFLINE_REPORT_SCHEMA, "plan offline report schema differs")
    _canonical_private_path(report["path"], "plan offline report")
    _sha(report["sha256"], "plan offline report SHA-256")
    chain = _pin_record(value["chain"], {"result", "completion"}, "plan chain")
    for label, item in chain.items():
        record = _pin_record(item, {"path", "sha256"}, f"plan {label}")
        _canonical_private_path(record["path"], f"plan {label}")
        _sha(record["sha256"], f"plan {label} SHA-256")
    pre = _pin_record(value["pre_remote_readback"], {"schema", "origin_dev", "origin_main"}, "pre remote readback")
    require(pre["schema"] == PRE_READBACK_SCHEMA, "pre remote readback schema differs")
    dev = _pin_record(pre["origin_dev"], {"commit", "tree"}, "pre origin/dev")
    main = _pin_record(pre["origin_main"], {"commit"}, "pre origin/main")
    require(dev == {"commit": BASE_DEV, "tree": BASE_DEV_TREE} and main == {"commit": PROTECTED_MAIN}, "pre remote identity differs")
    push = _pin_record(value["push"], {"mode", "argv", "executed"}, "plan push")
    candidate_ref = Candidate(candidate["commit"], candidate["tree"], candidate["source_commit"], Snapshot(Path(report["path"]), b"", report["sha256"], ()), Snapshot(Path(chain["result"]["path"]), b"", chain["result"]["sha256"], ()), Snapshot(Path(chain["completion"]["path"]), b"", chain["completion"]["sha256"], ()))
    require(push == {"mode": "normal-non-force", "argv": list(validate_refspec(candidate_ref)), "executed": False}, "plan push differs")


def load_plan(path: Path) -> Snapshot:
    snapshot = stable_read(Path(path).resolve(), "dev-update plan", mode=0o600)
    validate_plan(strict_json(snapshot.raw, "dev-update plan"))
    return snapshot


def verify_post_update(plan: Snapshot, repository: Path, run: Run = subprocess.run) -> dict[str, Any]:
    """Read the remote after an external normal push; it cannot perform that push."""
    plan_value = strict_json(plan.raw, "dev-update plan")
    validate_plan(plan_value)
    repository = Path(repository).resolve(strict=True)
    candidate = plan_value["candidate"]
    remote_dev, remote_main = _remote_oid(run, repository, "refs/heads/dev", "origin/dev"), _remote_oid(run, repository, "refs/heads/main", "origin/main")
    require(remote_dev == candidate["commit"] and remote_main == PROTECTED_MAIN, "post-update remote refs differ")
    return {
        "schema": REPORT_SCHEMA,
        "status": "passed",
        "plan": {"path": os.fspath(plan.path), "sha256": plan.sha256},
        "candidate": candidate,
        "post_remote_readback": {"schema": POST_READBACK_SCHEMA, "origin_dev": {"before": BASE_DEV, "after": remote_dev}, "origin_main": {"before": PROTECTED_MAIN, "after": remote_main}},
        "push": plan_value["push"],
    }


def write_report(path: Path, report: Mapping[str, Any]) -> Snapshot:
    validate_report(report)
    return write_new(path, report, "dev-update report")


def validate_report(report: Mapping[str, Any]) -> None:
    """Reject incomplete post-push evidence before it can become durable."""
    expected = {"schema", "status", "plan", "candidate", "post_remote_readback", "push"}
    require(set(report) == expected and report["schema"] == REPORT_SCHEMA and report["status"] == "passed", "dev-update report schema differs")
    plan = _pin_record(report["plan"], {"path", "sha256"}, "report plan")
    _canonical_private_path(plan["path"], "report plan")
    _sha(plan["sha256"], "report plan SHA-256")
    candidate = _pin_record(report["candidate"], {"commit", "tree", "source_commit"}, "report candidate")
    for key in candidate:
        _oid(candidate[key], f"report candidate {key}")
    post = _pin_record(report["post_remote_readback"], {"schema", "origin_dev", "origin_main"}, "post remote readback")
    require(post["schema"] == POST_READBACK_SCHEMA, "post remote readback schema differs")
    dev = _pin_record(post["origin_dev"], {"before", "after"}, "post origin/dev")
    main = _pin_record(post["origin_main"], {"before", "after"}, "post origin/main")
    require(dev == {"before": BASE_DEV, "after": candidate["commit"]}, "post origin/dev differs")
    require(main == {"before": PROTECTED_MAIN, "after": PROTECTED_MAIN}, "post origin/main differs")
    temporary = Candidate(candidate["commit"], candidate["tree"], candidate["source_commit"], Snapshot(Path(plan["path"]), b"", plan["sha256"], ()), Snapshot(Path(plan["path"]), b"", plan["sha256"], ()), Snapshot(Path(plan["path"]), b"", plan["sha256"], ()))
    require(report["push"] == {"mode": "normal-non-force", "argv": list(validate_refspec(temporary)), "executed": False}, "report push differs")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan", help="write a create-only push plan without pushing")
    plan_parser.add_argument("--pin", type=Path, default=PIN_PATH)
    plan_parser.add_argument("--repository", type=Path, required=True)
    plan_parser.add_argument("--plan", type=Path, required=True)
    post_parser = commands.add_parser("post-readback", help="write a create-only post-push remote readback")
    post_parser.add_argument("--repository", type=Path, required=True)
    post_parser.add_argument("--plan", type=Path, required=True)
    post_parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            plan = preflight(load_pin(args.pin), args.repository)
            print(f"PLAN: {write_plan(args.plan, plan).path}")
        else:
            report = verify_post_update(load_plan(args.plan), args.repository)
            print(f"REPORT: {write_report(args.report, report).path}")
    except Reject as error:
        print(f"DEV_UPDATE_REJECT: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
