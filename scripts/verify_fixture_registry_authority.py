#!/usr/bin/env python3
"""Verify the v2 aggregate fixture authority from immutable Git objects.

This verifier is intentionally separate from the aggregate scanner. The legacy v1 authority (its schema plus six legacy fields) remains readable
at its historical path, while the new multi-artifact bootstrap uses the distinct
v2 path and schema. Stage two pins
the checked-in predecessor bytes only; the later scanner correction must rebase
onto the merged predecessor and create its next authority independently. The
checkout is compared with authority bytes read from the local Git object
database, so replacing the visible authority file or refreshing local hashes
cannot silently authorize different scanner inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any


LEGACY_AUTHORITY_PATH = "scripts/fixture_registry_authority.json"
LEGACY_AUTHORITY_SCHEMA = "hermternal.fixture-registry-authority.v1"
LEGACY_AUTHORITY_KEYS = (
    "schema",
    "validator_path",
    "validator_size_bytes",
    "validator_sha256",
    "baseline_path",
    "baseline_size_bytes",
    "baseline_sha256",
)
LEGACY_VALIDATOR_PATH = "contracts/fixtures/validator/validate.py"
LEGACY_BASELINE_PATH = "contracts/fixtures/validator/validation-baseline.json"
AUTHORITY_PATH = "scripts/fixture_registry_authority.v2.json"
AUTHORITY_SCHEMA = "hermternal.fixture-registry-authority.v2"
AUTHORITY_ROLE = "bootstrap_predecessor"
EXPECTED_ARTIFACT_PATHS = (
    "contracts/fixtures/index.json",
    "contracts/fixtures/validator/test_validate.py",
    "contracts/fixtures/validator/validate.py",
    "contracts/fixtures/validator/validation-baseline.json",
)
AUTHORITY_KEYS = (
    "schema",
    "role",
    "source_commit",
    "artifact_manifest",
    "canonicalization",
    "synthetic_only",
    "live_claim",
)
RECORD_KEYS = ("path", "blob_oid", "sha256", "size_bytes")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_GIT_OUTPUT = 512 * 1024
MAX_ERROR_LENGTH = 220
SAFE_ERROR_MESSAGE = "fixture registry authority rejected"
GIT_REDIRECT_ENV_VARS = (
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_REPLACE_REF_BASE",
    "GIT_PROMISOR_REMOTE",
)


class AuthorityError(ValueError):
    """Raised for any untrusted checkout or Git-object authority mismatch."""


class ArgumentParseError(ValueError):
    """Raised without allowing argparse to reflect untrusted command-line text."""


def _require(condition: bool) -> None:
    if not condition:
        raise AuthorityError()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError()
        result[key] = value
    return result


def _parse_json(data: bytes) -> dict[str, Any]:
    _require(len(data) <= MAX_GIT_OUTPUT)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (AuthorityError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise AuthorityError() from exc
    _require(type(value) is dict)
    return value


def _strict_git_environment() -> dict[str, str]:
    """Keep every Git read on this checkout's local object database."""

    environment = os.environ.copy()
    # Git variables can redirect repository discovery, object lookup, config,
    # replacement refs, or promisor behavior. Purge all of them, not only the
    # currently known redirect list, before setting the two required safety
    # flags. Non-Git process variables such as PATH remain available so the
    # standard Git executable can be resolved without trusting Git overrides.
    for variable in tuple(environment):
        if variable.startswith("GIT_"):
            environment.pop(variable, None)
    for variable in GIT_REDIRECT_ENV_VARS:
        environment.pop(variable, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def _git(repo_root: Path, *arguments: str) -> bytes:
    """Read only bounded data from the local object database; never fetches."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env=_strict_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuthorityError() from exc
    _require(completed.returncode == 0 and completed.stderr == b"")
    _require(len(completed.stdout) <= MAX_GIT_OUTPUT)
    return completed.stdout


def _authority_introduction_commit(object_repo: Path) -> str:
    output = _git(
        object_repo,
        "log",
        "--format=%H",
        "--diff-filter=A",
        "--first-parent",
        "HEAD",
        "--",
        AUTHORITY_PATH,
    )
    try:
        commits = output.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise AuthorityError() from exc
    _require(len(commits) == 1 and HEX40.fullmatch(commits[0]) is not None)
    return commits[0]


def _git_blob(object_repo: Path, revision: str, path: str) -> tuple[str, bytes]:
    try:
        blob_oid = _git(object_repo, "rev-parse", f"{revision}:{path}").decode("ascii").strip()
    except UnicodeError as exc:
        raise AuthorityError() from exc
    _require(HEX40.fullmatch(blob_oid) is not None)
    _require(_git(object_repo, "cat-file", "-t", blob_oid) == b"blob\n")
    data = _git(object_repo, "cat-file", "blob", blob_oid)
    return blob_oid, data


def _validate_manifest(authority: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    _require(tuple(authority.keys()) == AUTHORITY_KEYS)
    _require(authority["schema"] == AUTHORITY_SCHEMA)
    _require(authority["role"] == AUTHORITY_ROLE)
    source_commit = authority["source_commit"]
    _require(type(source_commit) is str and HEX40.fullmatch(source_commit) is not None)
    _require(authority["canonicalization"] == "exact_bytes")
    _require(authority["synthetic_only"] is True and authority["live_claim"] is False)
    manifest = authority["artifact_manifest"]
    _require(type(manifest) is list and len(manifest) == len(EXPECTED_ARTIFACT_PATHS))
    paths: list[str] = []
    records: list[dict[str, Any]] = []
    for raw in manifest:
        _require(type(raw) is dict and tuple(raw.keys()) == RECORD_KEYS)
        path = raw["path"]
        _require(type(path) is str and path in EXPECTED_ARTIFACT_PATHS)
        _require(path not in paths)
        paths.append(path)
        blob_oid = raw["blob_oid"]
        digest = raw["sha256"]
        size = raw["size_bytes"]
        _require(type(blob_oid) is str and HEX40.fullmatch(blob_oid) is not None)
        _require(type(digest) is str and HEX64.fullmatch(digest) is not None)
        _require(type(size) is int and type(size) is not bool and 0 < size <= MAX_GIT_OUTPUT)
        records.append(raw)
    _require(tuple(paths) == EXPECTED_ARTIFACT_PATHS)
    return source_commit, records


def _validate_legacy_manifest(authority: dict[str, Any]) -> dict[str, Any]:
    """Read the historical v1 schema plus six legacy fields (seven total keys) without treating it as v2 trust."""

    _require(tuple(authority.keys()) == LEGACY_AUTHORITY_KEYS)
    _require(authority["schema"] == LEGACY_AUTHORITY_SCHEMA)
    _require(authority["validator_path"] == LEGACY_VALIDATOR_PATH)
    _require(authority["baseline_path"] == LEGACY_BASELINE_PATH)
    for prefix in ("validator", "baseline"):
        size = authority[f"{prefix}_size_bytes"]
        digest = authority[f"{prefix}_sha256"]
        _require(type(size) is int and type(size) is not bool and 0 < size <= MAX_GIT_OUTPUT)
        _require(type(digest) is str and HEX64.fullmatch(digest) is not None)
    return authority


def load_legacy_authority(checkout_root: Path) -> dict[str, Any]:
    """Load the preserved legacy v1 authority for migration compatibility."""

    return _validate_legacy_manifest(
        _parse_json(_read_checkout_file(checkout_root, LEGACY_AUTHORITY_PATH))
    )


def load_trusted_authority(object_repo: Path) -> dict[str, Any]:
    """Load and verify the v2 authority from immutable Git history."""

    object_repo = object_repo.resolve()
    introduction = _authority_introduction_commit(object_repo)
    authority_bytes = _git(object_repo, "show", f"{introduction}:{AUTHORITY_PATH}")
    authority = _parse_json(authority_bytes)
    source_commit, records = _validate_manifest(authority)
    _require(source_commit != introduction)
    _require(_git(object_repo, "merge-base", "--is-ancestor", source_commit, introduction) == b"")
    for record in records:
        blob_oid, data = _git_blob(object_repo, source_commit, record["path"])
        _require(blob_oid == record["blob_oid"])
        _require(len(data) == record["size_bytes"])
        _require(hashlib.sha256(data).hexdigest() == record["sha256"])
    return {
        "authority_path": AUTHORITY_PATH,
        "schema": AUTHORITY_SCHEMA,
        "authority_commit": introduction,
        "source_commit": source_commit,
        "authority_bytes": authority_bytes,
        "artifact_manifest": records,
    }


def _read_checkout_file(checkout_root: Path, path: str) -> bytes:
    """Read a bounded regular file without traversing checkout symlinks."""

    _require(type(path) is str and path and "\\" not in path and "\x00" not in path)
    relative = PurePosixPath(path)
    _require(not relative.is_absolute() and all(part not in ("", ".", "..") for part in relative.parts))
    _require(not checkout_root.is_symlink())
    root = checkout_root.resolve(strict=True)
    _require(root.is_dir())
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fds: list[int] = []
    file_fd: int | None = None
    try:
        current_fd = os.open(root, directory_flags)
        directory_fds.append(current_fd)
        for component in relative.parts[:-1]:
            current_fd = os.open(component, directory_flags, dir_fd=current_fd)
            directory_fds.append(current_fd)
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=current_fd)
        mode = os.fstat(file_fd).st_mode
        _require(stat.S_ISREG(mode))
        data = bytearray()
        while len(data) < MAX_GIT_OUTPUT + 1:
            chunk = os.read(file_fd, min(64 * 1024, MAX_GIT_OUTPUT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _require(len(data) <= MAX_GIT_OUTPUT)
        return bytes(data)
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for descriptor in reversed(directory_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


def verify_checkout(checkout_root: Path, object_repo: Path) -> dict[str, Any]:
    """Compare checkout trust inputs with the immutable predecessor manifest."""

    authority = load_trusted_authority(object_repo)
    _require(_read_checkout_file(checkout_root, AUTHORITY_PATH) == authority["authority_bytes"])
    for record in authority["artifact_manifest"]:
        data = _read_checkout_file(checkout_root, record["path"])
        _require(len(data) == record["size_bytes"])
        _require(hashlib.sha256(data).hexdigest() == record["sha256"])
    return {
        "ok": True,
        "stage": "bootstrap_predecessor_v2",
        "authority_path": authority["authority_path"],
        "schema": authority["schema"],
        "authority_commit": authority["authority_commit"],
        "source_commit": authority["source_commit"],
        "artifact_count": len(authority["artifact_manifest"]),
        "live_claim": False,
    }


def format_failure() -> str:
    payload = {
        "ok": False,
        "live_claim": False,
        "error": {"code": "fixture_registry_authority_invalid", "message": SAFE_ERROR_MESSAGE},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(encoded) > MAX_ERROR_LENGTH:
        raise AuthorityError()
    return encoded


def emit_failure() -> None:
    print(format_failure())


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ArgumentParseError()


def main(argv: list[str] | None = None) -> int:
    default_repo = Path(__file__).resolve().parents[1]
    parser = _Parser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=default_repo)
    parser.add_argument("--checkout-root", type=Path, default=default_repo)
    try:
        args = parser.parse_args(argv)
        result = verify_checkout(args.checkout_root, args.repo_root)
    except ArgumentParseError:
        emit_failure()
        return 2
    except (AuthorityError, OSError, ValueError):
        emit_failure()
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
