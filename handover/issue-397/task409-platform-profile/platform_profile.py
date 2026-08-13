#!/usr/bin/env python3
"""Load one immutable build-time platform profile.

The profile binds host paths before artifact generation. Runtime environment
variables cannot override these values. Generated artifacts repeat authenticated
literals only because JSON, Markdown, and shell must remain byte-identical.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

SCHEMA = "hermternal.issue-397.platform-profile/v1"
PROFILE_PATH = Path(__file__).resolve().with_name("linux-host-v1.json")
ROOT_KEYS = frozenset({"schema", "profile_id", "predecessor_bindings", "source", "runtime", "tools"})
TOOL_KEYS = frozenset({"path", "realpath", "sha256"})
TOOLS = ("git", "python3", "bash", "env", "mkdir", "rm", "rmdir", "cut", "shasum")
SHA = re.compile(r"[0-9a-f]{64}\Z")
OID = re.compile(r"[0-9a-f]{40}\Z")
MAX_PROFILE_BYTES = 32 * 1024


class Reject(Exception):
    """Reject a profile that is not the exact reviewed host contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


@dataclass(frozen=True)
class Tool:
    """One executable path and the resolved bytes that it identifies."""

    path: str
    realpath: str
    sha256: str


@dataclass(frozen=True)
class PlatformProfile:
    """Immutable values used for build-time artifact derivation."""

    profile_id: str
    source_repository: str
    source_detached_head: str
    temporary_parent: str
    predecessor_bindings: Mapping[str, str]
    tools: Mapping[str, Tool]
    raw: bytes
    sha256: str


def _strict_json(raw: bytes) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            require(key not in result, f"duplicate profile key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"profile is not strict UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), "profile root is not an object")
    return value


def _read_profile(path: Path) -> bytes:
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), "profile path is not canonical")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "profile is not a single-link regular file")
        require(0 < before.st_size <= MAX_PROFILE_BYTES, "profile size is outside its limit")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            require(bool(block), "profile read ended early")
            raw += block
        require(not os.read(descriptor, 1), "profile grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.lstat(path)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    require(identity(before) == identity(after) == identity(final), "profile changed during read")
    return raw


def _hash_file(path: str) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and bool(before.st_mode & 0o111), f"tool is not executable: {path}")
        while True:
            block = os.read(descriptor, 131072)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), f"tool changed during read: {path}")
    return digest.hexdigest()


def load(path: Path = PROFILE_PATH, *, verify_host: bool = True) -> PlatformProfile:
    """Parse a closed profile and, by default, bind it to the current host."""
    raw = _read_profile(Path(path))
    value = _strict_json(raw)
    require(set(value) == ROOT_KEYS and value.get("schema") == SCHEMA, "profile root schema differs")
    require(value.get("profile_id") == "linux-host-v1", "profile identifier differs")
    source = value.get("source")
    runtime = value.get("runtime")
    tools_value = value.get("tools")
    predecessor = value.get("predecessor_bindings")
    require(isinstance(source, dict) and set(source) == {"repository", "detached_head"}, "source profile fields differ")
    require(isinstance(runtime, dict) and set(runtime) == {"temporary_parent"}, "runtime profile fields differ")
    require(isinstance(tools_value, dict) and tuple(sorted(tools_value)) == tuple(sorted(TOOLS)), "tool profile fields differ")
    require(isinstance(predecessor, dict) and set(predecessor) == {"python3", "source_repository", "temporary_parent"} and all(isinstance(item, str) and item.startswith("/") for item in predecessor.values()), "predecessor bindings differ")
    repository = source.get("repository")
    detached_head = source.get("detached_head")
    temporary_parent = runtime.get("temporary_parent")
    require(isinstance(repository, str) and repository.startswith("/") and os.path.realpath(repository) == repository, "source repository is not canonical")
    require(isinstance(detached_head, str) and OID.fullmatch(detached_head) is not None, "source detached head differs")
    require(isinstance(temporary_parent, str) and temporary_parent.startswith("/") and os.path.realpath(temporary_parent) == temporary_parent, "temporary parent differs")
    parsed_tools: dict[str, Tool] = {}
    for name in TOOLS:
        record = tools_value.get(name)
        require(isinstance(record, dict) and set(record) == TOOL_KEYS, f"{name} tool fields differ")
        tool_path, realpath, sha256 = record.get("path"), record.get("realpath"), record.get("sha256")
        require(isinstance(tool_path, str) and tool_path.startswith("/"), f"{name} path differs")
        require(isinstance(realpath, str) and realpath.startswith("/") and os.path.realpath(realpath) == realpath, f"{name} realpath differs")
        require(isinstance(sha256, str) and SHA.fullmatch(sha256) is not None, f"{name} SHA-256 differs")
        parsed_tools[name] = Tool(tool_path, realpath, sha256)
    if verify_host:
        for name, tool in parsed_tools.items():
            require(os.path.realpath(tool.path) == tool.realpath, f"{name} resolved path differs")
            require(_hash_file(tool.path) == tool.sha256, f"{name} executable SHA-256 differs")
        source_stat = os.lstat(repository)
        require(stat.S_ISDIR(source_stat.st_mode) and not stat.S_ISLNK(source_stat.st_mode), "source repository is not a directory")
        temporary_stat = os.lstat(temporary_parent)
        require(stat.S_ISDIR(temporary_stat.st_mode) and temporary_stat.st_mode & stat.S_ISVTX, "temporary parent is not a sticky directory")
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1"}
        command = [parsed_tools["git"].path, "-C", repository, "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never"]
        head = subprocess.run([*command, "rev-parse", "HEAD"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment).stdout.decode("ascii").strip()
        symbolic = subprocess.run([*command, "symbolic-ref", "-q", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        require(head == detached_head and symbolic.returncode == 1 and not symbolic.stdout, "source is not at the reviewed detached head")
    return PlatformProfile("linux-host-v1", repository, detached_head, temporary_parent, MappingProxyType(dict(predecessor)), MappingProxyType(parsed_tools), raw, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    profile = load()
    print(json.dumps({"profile_id": profile.profile_id, "sha256": profile.sha256, "source_detached_head": profile.source_detached_head}, sort_keys=True))
