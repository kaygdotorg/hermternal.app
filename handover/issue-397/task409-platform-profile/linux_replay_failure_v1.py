#!/usr/bin/env python3
"""Add durable failure evidence to the approved Linux replay boundary.

This successor verified-loads the approved Phase A v3 adapter. It does not
change Phase A or anchor evidence. It wraps only the already-approved process
boundary and never starts a process while it is loaded.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import types
from pathlib import Path
from typing import Any

import platform_profile

HERE = Path(__file__).resolve().parent
PHASE_A_ADAPTER_PATH = HERE / "linux_phase_a_v3.py"
PHASE_A_ADAPTER_SHA256 = "11204cffbff813e0860349f2128d184191261e509f0a72c92bda1e94d7594587"
SCHEMA = "hermternal.issue-397.replay-failure.v1"
NAME = "replay-failure.json"
EXCERPT_LIMIT = 4096
SHA = re.compile(r"[0-9a-f]{64}\Z")


def _stable_bytes(path: Path, digest: str, label: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"{label} is not a single-link regular file")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            if not block:
                raise RuntimeError(f"{label} read ended early")
            raw += block
        if os.read(descriptor, 1):
            raise RuntimeError(f"{label} grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.lstat(path)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode, value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(final):
        raise RuntimeError(f"{label} changed during read")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{label} SHA-256 differs")
    return raw


def load_phase_a_adapter() -> types.ModuleType:
    """Compile only the exact approved Phase A adapter buffer."""
    raw = _stable_bytes(PHASE_A_ADAPTER_PATH, PHASE_A_ADAPTER_SHA256, "Phase A v3 adapter")
    module = types.ModuleType("issue397_linux_replay_failure_phase_a")
    module.__file__ = os.fspath(PHASE_A_ADAPTER_PATH)
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise RuntimeError(f"{label} is not a SHA-256")
    return value


def _excerpt(raw: bytes) -> dict[str, Any]:
    """Return bounded diagnostic text without credential-shaped values."""
    bounded = raw[:EXCERPT_LIMIT]
    value = bounded.decode("utf-8", errors="backslashreplace")
    patterns = (
        r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s]+",
        r"(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s]+",
        r"\b(?:ghp_|github_pat_|sk-)[A-Za-z0-9_-]{8,}\b",
    )
    for pattern in patterns:
        value = re.sub(pattern, lambda match: match.group(1) + "[REDACTED]" if match.lastindex else "[REDACTED]", value)
    return {"encoding": "utf-8-backslashreplace-redacted", "excerpt": value, "excerpt_input_bytes": len(bounded), "truncated": len(raw) > len(bounded)}


def _stream(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), **_excerpt(raw)}


def _record(adapter, authority, profile, phase_path: Path, phase_sha: str, anchor_sha: str, result) -> dict[str, Any]:
    argv_raw = b"".join(item.encode("utf-8") + b"\0" for item in authority.argv)
    return {
        "schema": SCHEMA,
        "profile": {"id": profile.profile_id, "path": os.fspath(platform_profile.PROFILE_PATH), "sha256": profile.sha256},
        "authority": {"files": dict(adapter.FINAL_PINS), "driver_source_sha256": authority.driver_source_sha256, "derived_stdin_sha256": authority.derived_stdin_sha256},
        "approval": {"phase_a_adapter_sha256": PHASE_A_ADAPTER_SHA256, "phase_a_evidence_path": os.fspath(phase_path.resolve()), "phase_a_evidence_sha256": phase_sha, "anchor_evidence_sha256": anchor_sha},
        "process": {"argv": list(authority.argv), "argv_bytes": len(argv_raw), "argv_sha256": hashlib.sha256(argv_raw).hexdigest(), "stdin_bytes": len(authority.stdin), "stdin_sha256": hashlib.sha256(authority.stdin).hexdigest(), "returncode": result.returncode, "stdout": _stream(result.stdout), "stderr": _stream(result.stderr)},
        "outcome": {"completion_claimed": False, "replay_failure": True, "retry_performed": False},
    }


def _install(wrapper, authority, adapter, profile, anchor_sha: str) -> None:
    predecessor = wrapper.execute_and_publish

    def execute_and_publish(phase_a_evidence, expected_phase_a_evidence_sha256, *, process_boundary=wrapper._run_process):
        def observed(argv, stdin, environment):
            result = process_boundary(argv, stdin, environment)
            failure_path = wrapper._run_root(result.pid) / "replay-root" / NAME
            failed = result.returncode != 0 or result.stdout != wrapper.SUCCESS_OUTPUT or bool(result.stderr)
            if failed:
                record = _record(adapter, authority, profile, Path(phase_a_evidence), _sha(expected_phase_a_evidence_sha256, "Phase A evidence SHA-256"), anchor_sha, result)
                expected = wrapper._canonical_json(record)
                wrapper._write_new(failure_path, expected, "replay failure", lambda _path, _inode: None)
                parent_fd = os.open(failure_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
                snapshot = wrapper.stable_read(failure_path, "replay failure")
                wrapper.require(snapshot.raw == expected, "replay failure changed after publication")
            else:
                wrapper.require(not os.path.lexists(failure_path), "preexisting replay failure evidence rejects success")
            return result

        return predecessor(phase_a_evidence, expected_phase_a_evidence_sha256, process_boundary=observed)

    wrapper.execute_and_publish = execute_and_publish


def load_approved_wrapper(expected_anchor_sha256: str):
    """Return the approved wrapper with failure evidence installed, but do not run it."""
    anchor_sha = _sha(expected_anchor_sha256, "anchor evidence SHA-256")
    adapter = load_phase_a_adapter()
    wrapper, authority = adapter.load_approved_wrapper(anchor_sha, PHASE_A_ADAPTER_SHA256)
    _install(wrapper, authority, adapter, platform_profile.load(), anchor_sha)
    return wrapper, authority
