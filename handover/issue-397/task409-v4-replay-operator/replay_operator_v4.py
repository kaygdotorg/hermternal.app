#!/usr/bin/env python3
"""Run the approved v4 replay boundary with no caller-selected authority.

This is only an operator entry point. It stable-reads the reviewed v4 adapters,
then delegates the single replay call to them. It does not copy or transform
replay logic, and it never accepts a path, digest, profile, or output root from
the caller.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROFILE_DIR = HERE.parent / "task409-platform-profile"
FAILURE_V2_PATH = PROFILE_DIR / "linux_replay_failure_v2.py"
FAILURE_V2_SHA256 = "b364a44e487d8be347e7151aff662c737f0a823d00f74194013617cee60dbe17"
PHASE_A_V4_PATH = PROFILE_DIR / "linux_phase_a_v4.py"
PHASE_A_V4_SHA256 = "f89ec8bdf2e77f45307b5d30a96aa6c4a2da7f576bcecf3ec102ed120283640f"
PROFILE_MODULE_PATH = PROFILE_DIR / "platform_profile.py"
PROFILE_MODULE_SHA256 = "b5a889fcd6ce7d55778f508e1cbd78d0b2e458a36ad48dd70a7d7ef250fed268"
PROFILE_PATH = PROFILE_DIR / "linux-host-v1.json"
PROFILE_SHA256 = "ac89acb0e3f5dcab6d5ac86cab22b67a62d2b393e5e912366345828809906776"
WRAPPER_PATH = PROFILE_DIR / "linux_replay_wrapper.py"
WRAPPER_SHA256 = "faf4abdb90b1e446270f2b93d50c85f6c25decfeef03696526405e10b33c43aa"

V4_ROOT = Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v4")
ANCHOR_PATH = V4_ROOT / "evidence" / "anchor.json"
ANCHOR_SHA256 = "c92ecfed3b0578537d38fc79172bf5d0100096976bfd1a8beb1a5d54968cd193"
FAILURE_V2_ROOT = Path("/home/kayg/Developer/hermternal-issue397-replay-failure-v2")


class Reject(RuntimeError):
    """Report a closed operator rejection without exposing child diagnostics."""


def _require(value: bool, message: str) -> None:
    if not value:
        raise Reject(message)


def _stable_bytes(path: Path, digest: str, label: str) -> bytes:
    """Read one fixed single-link file and reject replacement or hash drift."""
    _require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path differs")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"{label} is not a single-link regular file")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            _require(bool(block), f"{label} read ended early")
            raw += block
        _require(not os.read(descriptor, 1), f"{label} grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.lstat(path)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode, item.st_size, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
    _require(identity(before) == identity(after) == identity(final), f"{label} changed during read")
    _require(hashlib.sha256(raw).hexdigest() == digest, f"{label} SHA-256 differs")
    return raw


def _compile_module(path: Path, raw: bytes, name: str) -> types.ModuleType:
    """Compile exactly the verified buffer; no source rewrite is permitted."""
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def _load_profile() -> tuple[types.ModuleType, Any]:
    """Load the fixed profile module and bind its fixed JSON record."""
    raw = _stable_bytes(PROFILE_MODULE_PATH, PROFILE_MODULE_SHA256, "platform profile module")
    module = _compile_module(PROFILE_MODULE_PATH, raw, "platform_profile")
    _require(module.PROFILE_PATH == PROFILE_PATH, "platform profile path differs")
    profile = module.load(PROFILE_PATH)
    _require(profile.sha256 == PROFILE_SHA256 and profile.profile_id == "linux-host-v1", "platform profile differs")
    return module, profile


def _prepare_imports() -> None:
    """Use only the fixed sibling directory for approved adapter imports."""
    location = os.fspath(PROFILE_DIR)
    if location not in sys.path:
        sys.path.insert(0, location)


def _load_failure_v2() -> tuple[types.ModuleType, Any]:
    """Verify v4 inputs, then compile and return the exact failure-v2 adapter."""
    _prepare_imports()
    _, profile = _load_profile()
    phase_raw = _stable_bytes(PHASE_A_V4_PATH, PHASE_A_V4_SHA256, "Phase A v4 adapter")
    # Compile the same verified v4 bytes now. The approved v2 loader later
    # stable-loads them again when it installs the actual replay boundary.
    compile(phase_raw, os.fspath(PHASE_A_V4_PATH), "exec", dont_inherit=True)
    raw = _stable_bytes(FAILURE_V2_PATH, FAILURE_V2_SHA256, "replay failure v2 adapter")
    module = _compile_module(FAILURE_V2_PATH, raw, "issue397_v4_replay_failure_v2")
    _require(module.PHASE_A_V4_PATH == PHASE_A_V4_PATH and module.PHASE_A_V4_SHA256 == PHASE_A_V4_SHA256, "failure-v2 Phase A v4 pin differs")
    _require(Path(profile.source_repository).parent / module.DIRECTORY_NAME == FAILURE_V2_ROOT, "failure-v2 root differs")
    return module, profile


def _delegate_preflight() -> dict[str, object]:
    """Call the reviewed preflight only; it has no replay process boundary."""
    _prepare_imports()
    _load_profile()
    raw = _stable_bytes(WRAPPER_PATH, WRAPPER_SHA256, "Linux replay wrapper")
    wrapper = _compile_module(WRAPPER_PATH, raw, "issue397_v4_replay_preflight")
    result = wrapper.preflight()
    _require(isinstance(result, dict) and result.get("replay_run") is False and result.get("execution_enabled") is False, "approved preflight result differs")
    return result


def _delegate_run() -> Any:
    """Make one exact call to the approved v4 failure wrapper."""
    adapter, _profile = _load_failure_v2()
    wrapper, _authority = adapter.load_approved_wrapper(ANCHOR_SHA256)
    return wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA256)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the fixed issue #397 v4 replay authority.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true", help="run only the approved no-process preflight")
    mode.add_argument("--run", action="store_true", help="make the one fixed approved replay call")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.preflight:
            print(json.dumps(_delegate_preflight(), sort_keys=True, separators=(",", ":")))
            return 0
        publication = _delegate_run()
    except Exception:
        print("REJECT: fixed v4 replay operator rejected", file=sys.stderr)
        return 2
    try:
        print(f"PASS: {publication.result.path}")
        print(f"COMPLETION: {publication.completion.path}")
    except Exception:
        print("REJECT: fixed v4 replay operator returned an invalid publication", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
