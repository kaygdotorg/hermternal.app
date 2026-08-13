#!/usr/bin/env python3
"""Plan the guarded replay interlock without running any guarded operation."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


BASE = Path(__file__).resolve().parents[1]
LIFECYCLE = BASE / "task409-phase-b-lifecycle-successor" / "phase_b_lifecycle_successor.py"
GIT_AUTHORITY = BASE / "task464-candidate5-git-config-successor" / "candidate5_git_config_successor.py"
FINAL_ROOT = BASE / "task464-candidate5-final"
FINAL_PROVENANCE = FINAL_ROOT / "provenance-manifest.json"
EXPECTED = {
    LIFECYCLE: "e5b6846ad813a2e4b607983f8a95e49e41075195582b12c0ec8225d066a7cd4d",
    GIT_AUTHORITY: "b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a",
}
BASE_COMMIT = "729f2613af2b78d58b07918478e9102d5716f367"
BASE_TREE = "43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f"
MAIN_COMMIT = "3ebf8b3fe4767442490ab3053c0c1ccf84e8019f"
PROVENANCE_SCHEMA = "hermternal.issue-397.candidate-five-provenance.v1"
PROVENANCE_KEYS = frozenset({"schema", "issue", "candidate", "generation", "repository_boundary", "dependencies", "source_inputs", "outputs", "cross_format_authority", "publication", "safety_claims"})
STAGES = ("phase-a", "anchor", "replay", "phase-b")
EVIDENCE_KEYS = {
    "phase-a": frozenset({"manifest_path", "manifest_sha256", "approval_digest", "policy_sha256", "authority_provenance_sha256"}),
    "anchor": frozenset({"anchor_path", "anchor_sha256", "manifest_sha256", "approval_digest", "policy_sha256"}),
    "replay": frozenset({"replay_root", "repository", "result_path", "result_sha256", "final_head", "final_parent", "final_tree"}),
    "phase-b": frozenset({"result_sha256", "manifest_sha256", "anchor_sha256", "phase_a_validation_calls", "git_config_calls", "execution", "mutation", "network", "approval"}),
}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
OID_RE = re.compile(r"[0-9a-f]{40}\Z")


class Reject(Exception):
    """A deliberate fail-closed interlock rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size, value.st_nlink)


def stable_read(path: Path, label: str, limit: int = 8 * 1024 * 1024) -> tuple[bytes, tuple[int, ...]]:
    """Read exact bytes three times through a no-follow descriptor."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path is not canonical")
    observations = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"{label} is not a single-link file")
            require(0 < before.st_size <= limit, f"{label} size is outside its bound")
            chunks = []
            while True:
                chunk = os.read(fd, 131072)
                if not chunk:
                    break
                chunks.append(chunk)
                require(sum(map(len, chunks)) <= limit, f"{label} exceeds its bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.stat(path, follow_symlinks=False)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} identity changed")
        observations.append((b"".join(chunks), _identity(before)))
    require(observations[0] == observations[1] == observations[2], f"{label} changed across reads")
    return observations[0]


def verified_module(path: Path, digest: str, name: str) -> types.ModuleType:
    """Execute only bytes bound to one reviewed SHA-256 value."""
    raw, _ = stable_read(path.resolve(), name)
    require(hashlib.sha256(raw).hexdigest() == digest, f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = str(path.resolve()); module.__loader__ = None; module.__package__ = ""; module.__spec__ = None
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def install_reviewers() -> tuple[types.ModuleType, types.ModuleType]:
    """Load #399 and explicitly install #400 in its Phase B reviewer slot."""
    lifecycle = verified_module(LIFECYCLE, EXPECTED[LIFECYCLE], "issue397_interlock_lifecycle")
    git_authority = verified_module(GIT_AUTHORITY, EXPECTED[GIT_AUTHORITY], "issue397_interlock_git")
    hardened = git_authority.install_successor()
    require(hasattr(lifecycle, "PHASE_B") and hasattr(lifecycle.PHASE_B, "REVIEW"), "Phase B reviewer slot is absent")
    lifecycle.PHASE_B.REVIEW = hardened
    require(lifecycle.PHASE_B.REVIEW is hardened, "#400 was not installed in Phase B")
    return lifecycle, hardened


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    """Decode UTF-8 JSON and reject duplicate keys."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            require(key not in result, f"{label} has duplicate key {key}")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as exc:
        raise Reject(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    require(isinstance(value, dict), f"{label} root is not an object")
    return value


@dataclass(frozen=True)
class Authority:
    """Frozen #403 provenance and repository boundary."""

    raw: bytes
    sha256: str
    integrated_commit: str
    integrated_tree: str
    source_commit: str


def validate_provenance(raw: bytes) -> Authority:
    """Consume only the closed final #403 provenance schema."""
    value = strict_json(raw, "final provenance")
    require(set(value) == PROVENANCE_KEYS, "final provenance fields differ")
    require(value["schema"] == PROVENANCE_SCHEMA and value["issue"] == 397 and value["candidate"] == "five", "final provenance identity differs")
    boundary = value["repository_boundary"]
    require(isinstance(boundary, dict), "repository boundary is absent")
    required = {"integrated_commit", "integrated_tree", "base_commit", "base_tree", "protected_main_commit", "source_commit"}
    require(set(boundary) == required, "repository boundary fields differ")
    require(boundary["base_commit"] == BASE_COMMIT and boundary["base_tree"] == BASE_TREE and boundary["protected_main_commit"] == MAIN_COMMIT, "fixed repository pins differ")
    for key in ("integrated_commit", "integrated_tree", "source_commit"):
        require(isinstance(boundary[key], str) and OID_RE.fullmatch(boundary[key]) is not None, f"{key} is not 40hex")
    outputs = value["outputs"]
    require(isinstance(outputs, dict) and set(outputs) == {"markdown", "json", "shell"}, "final output roles differ")
    for role, name in (("markdown", "candidate-five.md"), ("json", "candidate-five.json"), ("shell", "candidate-five.sh")):
        require(outputs[role].get("path") == str(FINAL_ROOT / name), f"{role} final path differs")
        require(SHA256_RE.fullmatch(outputs[role].get("sha256", "")) is not None, f"{role} SHA-256 differs")
    safety = value["safety_claims"]
    require(safety.get("shell_executed") is False and safety.get("replay_run") is False and safety.get("hermes_used") is False, "#403 safety boundary differs")
    return Authority(raw, hashlib.sha256(raw).hexdigest(), boundary["integrated_commit"], boundary["integrated_tree"], boundary["source_commit"])


def load_authority(expected_sha256: str) -> Authority:
    """Load only the fixed durable final provenance path."""
    require(SHA256_RE.fullmatch(expected_sha256) is not None, "expected provenance SHA-256 is invalid")
    raw, _ = stable_read(FINAL_PROVENANCE.resolve(), "final provenance")
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "final provenance SHA-256 differs")
    return validate_provenance(raw)


def _canonical_private_tmp(path: str, label: str) -> Path:
    value = Path(path)
    require(value.is_absolute() and os.path.realpath(value) == os.fspath(value), f"{label} is not canonical")
    require(os.path.commonpath(("/private/tmp", os.fspath(value))) == "/private/tmp", f"{label} is outside /private/tmp")
    require(value != Path("/private/tmp"), f"{label} is too broad")
    return value


def new_plan(authority: Authority, runtime_parent: str, replay_root: str) -> dict[str, Any]:
    """Create a deterministic dry plan with no filesystem mutation."""
    runtime = _canonical_private_tmp(runtime_parent, "runtime parent")
    replay = _canonical_private_tmp(replay_root, "replay root")
    require(runtime != replay and runtime not in replay.parents and replay not in runtime.parents, "runtime and replay roots overlap")
    checkout = BASE.parents[1].resolve()
    require(checkout not in runtime.parents and checkout not in replay.parents, "runtime root overlaps checkout")
    return {
        "schema": "hermternal.issue-397.execution-interlock.v1", "state": "ready",
        "authority_provenance_sha256": authority.sha256,
        "integrated_commit": authority.integrated_commit, "integrated_tree": authority.integrated_tree,
        "source_commit": authority.source_commit, "base_commit": BASE_COMMIT, "base_tree": BASE_TREE,
        "protected_main_commit": MAIN_COMMIT, "runtime_parent": str(runtime), "replay_root": str(replay),
        "events": [], "tip_event_sha256": None,
    }


def _event_digest(event: Mapping[str, Any]) -> str:
    raw = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(raw).hexdigest()


def validate_plan(plan: Mapping[str, Any]) -> None:
    """Recompute the complete stop/resume chain before the next operation."""
    keys = {"schema", "state", "authority_provenance_sha256", "integrated_commit", "integrated_tree", "source_commit", "base_commit", "base_tree", "protected_main_commit", "runtime_parent", "replay_root", "events", "tip_event_sha256"}
    require(set(plan) == keys and plan["schema"] == "hermternal.issue-397.execution-interlock.v1", "plan schema differs")
    require(plan["base_commit"] == BASE_COMMIT and plan["base_tree"] == BASE_TREE and plan["protected_main_commit"] == MAIN_COMMIT, "plan pins differ")
    events = plan["events"]
    require(isinstance(events, list) and len(events) <= len(STAGES), "event count differs")
    previous = None
    for index, event in enumerate(events):
        require(set(event) == {"stage", "status", "previous_event_sha256", "evidence"}, "event fields differ")
        require(event["stage"] == STAGES[index] and event["status"] == "PASS", "event order or status differs")
        require(event["previous_event_sha256"] == previous, "event chain differs")
        require(isinstance(event["evidence"], dict) and set(event["evidence"]) == EVIDENCE_KEYS[event["stage"]], "stage evidence fields differ")
        previous = _event_digest(event)
    expected_state = "ready" if not events else events[-1]["stage"]
    require(plan["state"] == expected_state, "plan state differs from evidence")
    require(plan["tip_event_sha256"] == previous, "plan tip differs from evidence")


def accept_observation(plan: Mapping[str, Any], stage: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Accept one mocked external observation only at the next exact boundary."""
    validate_plan(plan)
    index = len(plan["events"])
    require(index < len(STAGES) and stage == STAGES[index], "operation is out of order or repeated")
    require(set(evidence) == EVIDENCE_KEYS[stage], f"{stage} evidence fields differ")
    for key, value in evidence.items():
        if key.endswith("sha256") or key.endswith("digest"):
            require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{stage} {key} is not lowercase 64hex")
    if stage == "phase-a":
        require(evidence["authority_provenance_sha256"] == plan["authority_provenance_sha256"], "Phase A authority differs")
        require(evidence["manifest_path"] == f"{plan['runtime_parent']}/phase-a/input-manifest.json", "Phase A manifest path differs")
    elif stage == "anchor":
        phase_a = plan["events"][0]["evidence"]
        require(evidence["anchor_path"] == f"{plan['runtime_parent']}/external-review/phase-a-approval-anchor.json", "anchor path differs")
        for key in ("manifest_sha256", "approval_digest", "policy_sha256"):
            require(evidence[key] == phase_a[key], f"anchor {key} differs")
    elif stage == "replay":
        require(evidence["replay_root"] == plan["replay_root"], "replay root differs")
        require(Path(evidence["repository"]).parent == Path(plan["replay_root"]), "repository is outside replay root")
        require(Path(evidence["result_path"]).parent == Path(plan["replay_root"]), "replay result is outside replay root")
        require(evidence["final_parent"] == plan["base_commit"], "replay parent differs from fixed base")
        require(all(OID_RE.fullmatch(evidence[key]) is not None for key in ("final_head", "final_parent", "final_tree")), "replay OID differs")
    else:
        phase_a = plan["events"][0]["evidence"]; anchor = plan["events"][1]["evidence"]; replay = plan["events"][2]["evidence"]
        require(evidence["result_sha256"] == replay["result_sha256"] and evidence["manifest_sha256"] == phase_a["manifest_sha256"] and evidence["anchor_sha256"] == anchor["anchor_sha256"], "Phase B input identity differs")
        require(evidence["phase_a_validation_calls"] == 1 and evidence["git_config_calls"] >= 1, "Phase B call count differs")
        require((evidence["execution"], evidence["mutation"], evidence["network"], evidence["approval"]) == ("not-run", "not-run", "not-used", "not-claimed"), "Phase B safety result differs")
    previous = None if not plan["events"] else _event_digest(plan["events"][-1])
    event = {"stage": stage, "status": "PASS", "previous_event_sha256": previous, "evidence": dict(evidence)}
    updated = dict(plan); updated["events"] = [*plan["events"], event]; updated["state"] = stage
    updated["tip_event_sha256"] = _event_digest(event)
    validate_plan(updated)
    return updated


def command_for_next(plan: Mapping[str, Any]) -> tuple[str, ...]:
    """Return a non-executable operation label for operator review."""
    validate_plan(plan)
    index = len(plan["events"])
    require(index < len(STAGES), "interlock is complete")
    return ("STOP-BEFORE-EXECUTION", STAGES[index])
