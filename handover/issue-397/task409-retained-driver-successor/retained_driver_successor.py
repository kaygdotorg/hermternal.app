#!/usr/bin/env python3
"""Derive the retained candidate-five driver without running it.

This successor verifies the frozen #403 authority and the approved generator
chain. It then applies one anchored lifecycle transform to exact frozen shell
bytes. Replay, Git, network, and cleanup operations are never run here.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BASE = Path(__file__).resolve().parents[1]
# The #403 descriptor binds these exact durable paths. A worktree copy has the
# same bytes but is not the approved path authority.
FINAL_ROOT = Path("/home/kayg/Developer/hermternal/handover/issue-397/task464-candidate5-final")
DESCRIPTOR = FINAL_ROOT / "authority-descriptor.json"
PROVENANCE = FINAL_ROOT / "provenance-manifest.json"
FINAL_JSON = FINAL_ROOT / "candidate-five.json"
FINAL_MARKDOWN = FINAL_ROOT / "candidate-five.md"
FINAL_SHELL = FINAL_ROOT / "candidate-five.sh"
AUTHORITY = BASE / "task464-candidate5-authority-successor" / "candidate5_authority.py"
FRAMING = BASE / "task464-candidate5-successor" / "candidate5_framing_range_successor.py"
FROZEN_GENERATOR = BASE / "task464-candidate5" / "f932bc703a5e-task464-candidate5-generator.py"
ORCHESTRATOR = BASE / "task464-candidate5-final-triad" / "generator_orchestrator.py"
FINAL_FREEZE = BASE / "task464-candidate5-final-freeze" / "final_freeze.py"

PINNED_SHA256 = {
    DESCRIPTOR: "cf10f8286eca92d42130c17b9e086b8776dc385fa3a297c90725787415776f34",
    PROVENANCE: "363d6f62335a5ff9f92eefabe87dd568032e71871390fa9fc5ae6fd72e3ac320",
    FINAL_JSON: "dd0e9873941c30aee7515a382e3ca7c282df840d2d4364a7dfa5f21fce0ecd60",
    FINAL_MARKDOWN: "706237ec508d96f564e5395e86dba943a11eb5057fb676bf95b924815158dad9",
    FINAL_SHELL: "f7d5adfc9178431942d62948ffaf1953a2273bdec002661def9d0e80ffc34676",
    AUTHORITY: "1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8",
    FRAMING: "4287f89d87971f62c3f11504713134de9caba4290606b3c90eac63632125861e",
    FROZEN_GENERATOR: "cc73c1743c4059cc995be4a9e097cd16007c8095bc87a7c572418134c4d434dc",
    ORCHESTRATOR: "d9c36a3c3e99d0379186fc9ea0a26a5d93ac26eb4bd1c826c209b9bee0547361",
    FINAL_FREEZE: "714f6ef3fd780acccd1520a090428c3d4c20c1be8178e84114015b1c07f87316",
}

PENDING_SCHEMA = "hermternal.issue-397.replay-result.pending/v1"
SUCCESS_MARKER = "TASK409_RETAINED_REPLAY_OK=1"
SUCCESS_OUTPUT = b"TASK409_RETAINED_REPLAY_OK=1\n"
PENDING_KEYS = frozenset(
    {
        "schema", "replay_root", "replay_root_identity", "repository",
        "repository_identity", "head_state", "final_head", "parent", "tree",
        "base_commit", "base_tree", "protected_main_commit",
        "required_ancestors", "forbidden_ancestors",
    }
)
MAX_FILE_BYTES = 8 * 1024 * 1024
OID = re.compile(r"[0-9a-f]{40}\Z")
COMMIT_KEYS = frozenset(
    {
        "commit",
        "commits",
        "parent",
        "parents",
        "child",
        "raw_semantic_source_commits",
    }
)


class Reject(Exception):
    """A fail-closed derivation rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


@dataclass(frozen=True)
class Snapshot:
    """Exact bytes and one stable local file identity."""

    path: Path
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int, int, int]


@dataclass(frozen=True)
class FrozenAuthority:
    """The exact #403 authority used as the derivation source."""

    descriptor: Snapshot
    provenance: Snapshot
    json: Snapshot
    markdown: Snapshot
    shell: Snapshot
    document: dict[str, Any]


@dataclass(frozen=True)
class DerivedDriver:
    """Exact stdin and invocation contract for the trusted outer wrapper."""

    argv: tuple[str, ...]
    stdin: bytes
    source_sha256: str
    derived_sha256: str


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(value.st_dev), int(value.st_ino), int(value.st_uid),
        int(stat.S_IMODE(value.st_mode)), int(value.st_size), int(value.st_nlink),
        int(value.st_mtime_ns), int(value.st_ctime_ns),
    )


def stable_read(path: Path, label: str, *, mode: int = 0o644) -> Snapshot:
    """Read one canonical single-link file three times without path following."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path differs")
    values: list[Snapshot] = []
    for _ in range(3):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
            require(before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode, f"{label} mode or link count differs")
            require(0 < before.st_size <= MAX_FILE_BYTES, f"{label} size differs")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(descriptor, min(131072, MAX_FILE_BYTES + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                require(total <= MAX_FILE_BYTES, f"{label} exceeds its byte limit")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = os.lstat(path)
        raw = b"".join(chunks)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} changed during read")
        require(len(raw) == before.st_size, f"{label} byte count differs")
        values.append(Snapshot(path, raw, hashlib.sha256(raw).hexdigest(), _identity(before)))
    require(values[0] == values[1] == values[2], f"{label} changed across reads")
    return values[0]


def _verified_module(path: Path, label: str) -> types.ModuleType:
    snapshot = stable_read(path, label)
    require(snapshot.sha256 == PINNED_SHA256[path], f"{label} SHA-256 differs")
    module = types.ModuleType(f"issue397_{label.replace(' ', '_')}")
    module.__file__ = str(path)
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = None
    sys.modules[module.__name__] = module
    exec(compile(snapshot.raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"{label} has duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"{label} is not strict UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), f"{label} root differs")
    return value


def load_frozen_authority() -> FrozenAuthority:
    """Verify #403 descriptor, provenance, triad, #401, and generator chain."""
    framing = _verified_module(FRAMING, "approved framing successor")
    require(framing.FROZEN_GENERATOR_SHA256 == PINNED_SHA256[FROZEN_GENERATOR], "framing generator pin differs")
    generator = framing.install_successor()
    require(callable(getattr(generator, "main", None)), "approved generator entry point differs")
    frozen_generator = stable_read(FROZEN_GENERATOR, "frozen generator")
    require(frozen_generator.sha256 == PINNED_SHA256[FROZEN_GENERATOR], "frozen generator SHA-256 differs")
    orchestrator = _verified_module(ORCHESTRATOR, "approved triad orchestrator")
    final_freeze = _verified_module(FINAL_FREEZE, "approved final freeze")
    require(orchestrator.FINAL_NAMES == {"markdown": "candidate-five.md", "json": "candidate-five.json", "shell": "candidate-five.sh"}, "#403 final names differ")
    require(final_freeze.ORCHESTRATOR_SHA256 == PINNED_SHA256[ORCHESTRATOR], "#403 orchestrator pin differs")
    require(final_freeze.FINAL_ROOT == BASE / "task464-candidate5-final", "#403 final-root rule differs")
    authority_module = _verified_module(AUTHORITY, "approved authority")
    descriptor = stable_read(DESCRIPTOR, "authority descriptor", mode=0o600)
    provenance = stable_read(PROVENANCE, "provenance manifest", mode=0o600)
    snapshots = {
        "json": stable_read(FINAL_JSON, "candidate JSON", mode=0o600),
        "markdown": stable_read(FINAL_MARKDOWN, "candidate Markdown", mode=0o600),
        "shell": stable_read(FINAL_SHELL, "candidate shell", mode=0o600),
    }
    for path, snapshot in ((DESCRIPTOR, descriptor), (PROVENANCE, provenance), (FINAL_JSON, snapshots["json"]), (FINAL_MARKDOWN, snapshots["markdown"]), (FINAL_SHELL, snapshots["shell"])):
        require(snapshot.sha256 == PINNED_SHA256[path], f"frozen {path.name} SHA-256 differs")
    validated = authority_module.validate(DESCRIPTOR, FINAL_ROOT, descriptor.sha256)
    require(validated.artifacts["json"].raw == snapshots["json"].raw, "#401 JSON bytes differ")
    require(validated.artifacts["markdown"].raw == snapshots["markdown"].raw, "#401 Markdown bytes differ")
    require(validated.artifacts["shell"].raw == snapshots["shell"].raw, "#401 shell bytes differ")
    provenance_value = _strict_json(provenance.raw, "provenance")
    require(provenance_value.get("schema") == "hermternal.issue-397.candidate-five-provenance.v1", "provenance schema differs")
    require(provenance_value.get("repository_boundary") == {"output_root": str(FINAL_ROOT)}, "provenance root differs")
    require(provenance_value.get("safety_claims", {}).get("replay_run") is False, "frozen provenance replay claim differs")
    document = _strict_json(snapshots["json"].raw, "candidate JSON")
    require(document.get("execution_driver", {}).get("shell", "").encode("utf-8") == snapshots["shell"].raw, "JSON shell authority differs")
    require(authority_module.extract_shell(snapshots["markdown"].raw) == snapshots["shell"].raw, "Markdown shell authority differs")
    return FrozenAuthority(descriptor, provenance, snapshots["json"], snapshots["markdown"], snapshots["shell"], document)


def _replace_exact(text: str, old: str, new: str, label: str, expected: int = 1) -> str:
    count = text.count(old)
    require(count == expected, f"{label} anchor count differs: {count}")
    return text.replace(old, new, expected)


def _result_writer_heredoc(
    authority: FrozenAuthority,
) -> str:
    base = authority.document["base"]
    forbidden = authority.document["forbidden_ancestry"]
    required = [base["commit"]]
    forbidden_values = list(dict.fromkeys([*forbidden["commits"], *forbidden["raw_semantic_source_commits"]]))
    values = {
        "base": base["commit"],
        "base_tree": base["tree"],
        "main": base["protected_main_commit"],
        "required": required,
        "forbidden": forbidden_values,
    }
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return f'''publish_retained_replay_pending() {{
  local parent="$1"
  "$PYTHON" - "$RESULT_ROOT" "$REPLAY" "$CURRENT_HEAD" "$CURRENT_TREE" "$parent" <<'PY'
import json
import os
import re
import stat
import sys

replay_root, repository, final_head, tree, parent = sys.argv[1:]
authority = json.loads({encoded!r})
OID = re.compile(r'[0-9a-f]{{40}}\\Z')
PENDING_KEYS = {sorted(PENDING_KEYS)!r}

def reject(message):
    raise SystemExit(message)

def canonical(path, label):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        reject(label + ' path is not canonical')
    return path

def dir_identity(path, label):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        reject(label + ' is not an owned mode-0700 directory')
    return {{'st_dev': int(st.st_dev), 'st_ino': int(st.st_ino), 'st_uid': int(st.st_uid), 'st_mode': 0o700, 'st_nlink': int(st.st_nlink)}}

def create_once(path, value, label):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\\n').encode('utf-8')
    parent_fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        fd = os.open(os.path.basename(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=parent_fd)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    reject(label + ' write made no progress')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return raw

canonical(replay_root, 'replay root')
canonical(repository, 'repository')
if os.path.dirname(replay_root) != os.path.dirname(repository) or os.path.basename(replay_root) != 'replay-root' or os.path.basename(repository) != 'repository':
    reject('replay root and repository are not exact siblings')
run_parent = os.path.dirname(replay_root)
parent_identity = dir_identity(run_parent, 'run parent')
if os.path.lexists(replay_root):
    reject('replay root already exists')
repository_identity = dir_identity(repository, 'repository')
if not OID.fullmatch(final_head) or not OID.fullmatch(parent) or not OID.fullmatch(tree):
    reject('final Git identity differs')

# All Git and closure observations are complete before this create-only output.
parent_fd = os.open(run_parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
try:
    os.mkdir('replay-root', 0o700, dir_fd=parent_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
parent_final = dir_identity(run_parent, 'run parent final')
if any(parent_final[key] != parent_identity[key] for key in ('st_dev', 'st_ino', 'st_uid', 'st_mode')):
    reject('run parent identity changed during replay-root creation')
replay_identity = dir_identity(replay_root, 'replay root')

pending = {{
    'schema': {PENDING_SCHEMA!r},
    'replay_root': replay_root, 'replay_root_identity': replay_identity,
    'repository': repository, 'repository_identity': repository_identity,
    'head_state': 'detached', 'final_head': final_head, 'parent': parent, 'tree': tree,
    'base_commit': authority['base'], 'base_tree': authority['base_tree'],
    'protected_main_commit': authority['main'], 'required_ancestors': authority['required'],
    'forbidden_ancestors': authority['forbidden'],
}}
if set(pending) != set(PENDING_KEYS):
    reject('pending replay result fields differ')
create_once(os.path.join(replay_root, 'replay-result.pending.json'), pending, 'pending replay result')
PY
}}
'''


def _required_proof_commit_roots(authority: FrozenAuthority) -> frozenset[str]:
    """Return roots that no derived proof inventory is permitted to omit."""
    document = authority.document
    base = document["base"]
    required = {base["commit"], base["protected_main_commit"]}
    forbidden = document["forbidden_ancestry"]
    required.update(forbidden["commits"])
    required.update(forbidden["raw_semantic_source_commits"])
    endpoints = forbidden["authentication_range"].split("..")
    require(len(endpoints) == 2, "authentication range proof roots differ")
    required.update(endpoints)
    source_commits = {
        lane["source_commit"]["commit"]
        for lane in document["ordered_lanes"]
        if isinstance(lane.get("source_commit"), dict)
    }
    required.update(source_commits)
    require(
        all(isinstance(value, str) and OID.fullmatch(value) for value in required),
        "required proof root is not an exact commit ID",
    )
    return frozenset(required)


def _validate_proof_commit_roots(
    authority: FrozenAuthority, roots: tuple[str, ...]
) -> None:
    """Reject a reordered, duplicate, malformed, or incomplete root inventory."""
    require(
        isinstance(roots, tuple)
        and roots == tuple(sorted(set(roots)))
        and all(isinstance(value, str) and OID.fullmatch(value) for value in roots),
        "proof root inventory shape differs",
    )
    require(
        _required_proof_commit_roots(authority) <= set(roots),
        "authenticated proof root inventory is incomplete",
    )


def _proof_commit_roots(authority: FrozenAuthority) -> tuple[str, ...]:
    """Return every authenticated commit root needed after alternate removal."""
    roots: set[str] = set()

    def collect(value: Any, key: str | None = None) -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                collect(child, child_key)
        elif isinstance(value, list):
            for child in value:
                collect(child, key)
        elif isinstance(value, str) and key in COMMIT_KEYS and re.fullmatch(
            r"[0-9a-f]{40}", value
        ):
            roots.add(value)

    collect(authority.document)
    roots.update(_required_proof_commit_roots(authority))
    result = tuple(sorted(roots))
    _validate_proof_commit_roots(authority, result)
    return result


def _alternate_unlink_python() -> str:
    """Return the shared descriptor-bound alternates unlink implementation."""
    return r'''def file_identity(st):
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid),
            int(stat.S_IMODE(st.st_mode)), int(st.st_size), int(st.st_nlink),
            int(st.st_mtime_ns), int(st.st_ctime_ns))

def read_descriptor(fd, limit, label):
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, min(131072, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise RuntimeError(label + ' exceeds its byte limit')
    return b''.join(chunks)

def unlink_bound_alternate(path, expected):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise RuntimeError('alternates path is not canonical absolute')
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    descriptor = -1
    try:
        parent_before = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent_before.st_mode)
                or parent_before.st_uid != os.getuid()
                or stat.S_IMODE(parent_before.st_mode) & 0o022):
            raise RuntimeError('alternates parent identity is unsafe')
        descriptor = os.open(name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0), dir_fd=parent_fd)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600):
            raise RuntimeError('alternates is not an owned mode-0600 single-link file')
        raw = read_descriptor(descriptor, 8192, 'alternates')
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if file_identity(before) != file_identity(after) or file_identity(before) != file_identity(current):
            raise RuntimeError('alternates identity changed before unlink')
        if raw != expected:
            raise RuntimeError('alternates bytes differ from the bound clean-primary path')
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError('alternates path remains after unlink')
        parent_after = os.fstat(parent_fd)
        if (int(parent_after.st_dev), int(parent_after.st_ino), int(parent_after.st_uid), stat.S_IMODE(parent_after.st_mode)) != (int(parent_before.st_dev), int(parent_before.st_ino), int(parent_before.st_uid), stat.S_IMODE(parent_before.st_mode)):
            raise RuntimeError('alternates parent identity changed during unlink')
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
'''


def _self_contained_heredoc(authority: FrozenAuthority) -> str:
    """Build the exact non-thin pack and alternate-removal shell function."""
    roots = _proof_commit_roots(authority)
    encoded_roots = json.dumps(roots, separators=(",", ":"))
    unlink_source = _alternate_unlink_python()
    return f'''make_retained_repository_self_contained() {{
  "$PYTHON" - "$REPLAY" "$CLEAN_PRIMARY_OBJECTS" <<'PY'
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

repo, clean_objects = sys.argv[1:]
ROOTS = tuple(json.loads({encoded_roots!r}))
OID = re.compile(r'[0-9a-f]{{40}}\\Z')
ENV = {{
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_ATTR_NOSYSTEM': '1',
    'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}}
MAX_OUTPUT = 64 * 1024 * 1024
MAX_PACK = 1024 * 1024 * 1024

def reject(message):
    raise SystemExit(message)

def run(args, input_bytes=None):
    command = [
        '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch',
        '--no-optional-locks', '-C', repo,
        '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args,
    ]
    process = subprocess.run(
        command, input=input_bytes, env=ENV, cwd='/',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if len(process.stdout) > MAX_OUTPUT or len(process.stderr) > MAX_OUTPUT:
        reject('self-contained Git output exceeds its byte bound')
    return process

def require_success(process, label, stderr_empty=True):
    if process.returncode != 0:
        reject(label + ' failed')
    if stderr_empty and process.stderr:
        reject(label + ' wrote stderr')

def snapshot(path, label):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        reject(label + ' path is not canonical absolute')
    values = []
    for _ in range(2):
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
                    or before.st_size <= 0 or before.st_size > MAX_PACK):
                reject(label + ' file identity is unsafe')
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(fd, 131072)
                if not block:
                    break
                digest.update(block)
                total += len(block)
                if total > MAX_PACK:
                    reject(label + ' exceeds its byte bound')
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        value = (file_identity(before), digest.hexdigest())
        if file_identity(before) != file_identity(after) or file_identity(before) != file_identity(final) or total != before.st_size:
            reject(label + ' changed during read')
        values.append(value)
    if values[0] != values[1]:
        reject(label + ' changed across reads')
    return values[0]

def assert_snapshot(path, expected, label):
    if snapshot(path, label) != expected:
        reject(label + ' changed after alternate removal')

def require_empty_pack_directory(path):
    if (not os.path.isabs(path) or os.path.realpath(path) != path
            or not os.path.isdir(path) or os.path.islink(path)):
        reject('retained pack directory differs')
    if os.listdir(path):
        reject('retained pack directory has a pre-existing entry')

{unlink_source}
if (not os.path.isabs(repo) or os.path.realpath(repo) != repo
        or not os.path.isabs(clean_objects) or os.path.realpath(clean_objects) != clean_objects):
    reject('self-contained input path differs')
if not ROOTS or len(ROOTS) != len(set(ROOTS)) or not all(OID.fullmatch(root) for root in ROOTS):
    reject('self-contained proof root inventory differs')
git_dir = os.path.join(repo, '.git')
objects = os.path.join(git_dir, 'objects')
pack_dir = os.path.join(objects, 'pack')
alternates = os.path.join(objects, 'info', 'alternates')
require_empty_pack_directory(pack_dir)

enumerated = run(['rev-list', '--objects', '--no-object-names', '--end-of-options', *ROOTS])
require_success(enumerated, 'proof-root closure enumeration')
object_ids = enumerated.stdout.splitlines()
if (not object_ids or len(object_ids) != len(set(object_ids))
        or not all(re.fullmatch(rb'[0-9a-f]{{40}}', value) for value in object_ids)):
    reject('proof-root closure object inventory differs')
pack_input = b'\\n'.join(object_ids) + b'\\n'
pack_prefix = os.path.join(pack_dir, 'pack')
packed = run(['pack-objects', pack_prefix], input_bytes=pack_input)
require_success(packed, 'non-thin self-contained object pack')
if not re.fullmatch(rb'[0-9a-f]{{40}}\\n', packed.stdout):
    reject('pack-objects output differs')
pack_hash = packed.stdout[:-1].decode('ascii')
pack_path = os.path.join(pack_dir, 'pack-' + pack_hash + '.pack')
index_path = os.path.join(pack_dir, 'pack-' + pack_hash + '.idx')
if sorted(os.listdir(pack_dir)) != sorted([os.path.basename(pack_path), os.path.basename(index_path)]):
    reject('retained pack output set differs')
pack_snapshot = snapshot(pack_path, 'retained pack')
index_snapshot = snapshot(index_path, 'retained pack index')

try:
    unlink_bound_alternate(alternates, (clean_objects + '\\n').encode('utf-8'))
except Exception as error:
    reject('bound alternates unlink failed: ' + str(error))
if os.path.lexists(alternates):
    reject('alternates exists after self-contained conversion')
assert_snapshot(pack_path, pack_snapshot, 'retained pack')
assert_snapshot(index_path, index_snapshot, 'retained pack index')

fsck = run(['fsck', '--strict', '--full', '--no-reflogs', '--no-progress'])
require_success(fsck, 'self-contained strict fsck', stderr_empty=False)
fsck_text = (fsck.stdout + b'\\n' + fsck.stderr).lower()
if re.search(rb'(?:missing|broken|corrupt|fatal|error):?', fsck_text):
    reject('self-contained strict fsck reported invalid state')
closure = run(['rev-list', '--objects', '--all', '--missing=error'])
require_success(closure, 'self-contained all-ref closure')
for root in ROOTS:
    typed = run(['cat-file', '-t', root])
    require_success(typed, 'self-contained proof-root type')
    if typed.stdout != b'commit\\n':
        reject('self-contained proof root is not a commit: ' + root)
if os.path.lexists(alternates):
    reject('alternates reappeared after closure checks')
assert_snapshot(pack_path, pack_snapshot, 'retained pack final')
assert_snapshot(index_path, index_snapshot, 'retained pack index final')
PY
}}
'''


def transform_shell(authority: FrozenAuthority) -> bytes:
    """Apply only the reviewed retained-success lifecycle transform."""
    # Derive from JSON authority after load_frozen_authority proves that the
    # JSON, Markdown fence, and standalone frozen shell bytes are identical.
    shell = authority.document["execution_driver"]["shell"]
    shell = _replace_exact(
        shell,
        'readonly REPLAY_ROOT="/private/tmp/hermternal-task409-final-replay.$$"\nreadonly REPLAY="$REPLAY_ROOT/replay"\n',
        'readonly REPLAY_ROOT="/private/tmp/hermternal-task409-final-replay.$$"\n'
        'readonly RESULT_ROOT="$REPLAY_ROOT/replay-root"\n'
        'readonly REPLAY="$REPLAY_ROOT/repository"\n',
        "retained sibling layout",
    )
    shell = _replace_exact(
        shell,
        '  test "$REPLAY" = "$REPLAY_ROOT/replay" || fail "replay checkout escaped its root"\n',
        '  test "$RESULT_ROOT" = "$REPLAY_ROOT/replay-root" || fail "replay evidence root escaped its parent"\n'
        '  test "$REPLAY" = "$REPLAY_ROOT/repository" || fail "replay repository escaped its parent"\n',
        "root-shape sibling assertion",
    )
    shell = _replace_exact(
        shell,
        'create_replay_root\nassert_replay_preinit_state\nCLEANUP_ALLOWLIST=("$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT" "$REPLAY_ROOT")\nCLEAN_PRIMARY_CLEANUP_ALLOWLIST=("$CLEAN_PRIMARY_ROOT")\n',
        'create_replay_root\nassert_replay_preinit_state\n'
        'test "$RESULT_ROOT" = "$REPLAY_ROOT/replay-root" || fail "replay evidence root differs"\n'
        'test ! -e "$RESULT_ROOT" && test ! -L "$RESULT_ROOT" || fail "replay evidence root already exists"\n'
        'CLEANUP_ALLOWLIST=()\nCLEAN_PRIMARY_CLEANUP_ALLOWLIST=()\n',
        "disable success cleanup",
    )
    shell = _replace_exact(
        shell,
        '  git_replay -c user.name="$COMMITTER_NAME" -c user.email="$COMMITTER_EMAIL" commit --no-verify -m "$message"\n',
        '  git_replay -c user.name="$COMMITTER_NAME" -c user.email="$COMMITTER_EMAIL" commit --no-verify -m "$message" >/dev/null\n',
        "successful commit output suppression",
    )
    shell = _replace_exact(
        shell,
        "before_mutation\nassert_final_matrix\nassert_forbidden_ancestry\nassert_primary_pins\n",
        "before_mutation\nassert_final_matrix\nassert_forbidden_ancestry\nassert_primary_pins\n",
        "final validation anchor",
    )
    shell = _replace_exact(
        shell,
        "  # Closure is checked after replay bootstrap and again immediately before\n"
        "  # cleanup. The replay alternate is intentional, but only its exact bound\n"
        "  # clean-primary object store is allowed; HTTP, replacement, promisor, partial,\n"
        "  # helper, shallow, and graft metadata remain forbidden.\n",
        "  # Bootstrap permits only the exact bound clean-primary alternate. The\n"
        "  # retained-success boundary removes it after it creates and verifies a\n"
        "  # complete non-thin self-contained pack. External object state is forbidden.\n",
        "self-contained closure documentation",
    )
    old_alternate_check = '''alternate = os.path.join(objects, 'info', 'alternates')
alt_st = require_regular(alternate, 'replay alternates')
fd = os.open(alternate, os.O_RDONLY | os.O_NOFOLLOW)
try:
    first = os.fstat(fd)
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    second = os.fstat(fd)
finally:
    os.close(fd)
final = os.stat(alternate, follow_symlinks=False)
if identity(first) != identity(second) or identity(first) != identity(final):
    raise SystemExit('replay alternates changed during closure check')
expected_alternate = (os.path.realpath(clean_objects) + '\\n').encode('utf-8')
if b''.join(chunks) != expected_alternate:
    raise SystemExit('replay alternates are not the exact clean-primary object store')
'''
    new_alternate_check = '''alternate = os.path.join(objects, 'info', 'alternates')
if os.path.lexists(alternate):
    alt_st = require_regular(alternate, 'replay alternates')
    fd = os.open(alternate, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = os.fstat(fd)
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        second = os.fstat(fd)
    finally:
        os.close(fd)
    final = os.stat(alternate, follow_symlinks=False)
    if identity(first) != identity(second) or identity(first) != identity(final):
        raise SystemExit('replay alternates changed during closure check')
    expected_alternate = (os.path.realpath(clean_objects) + '\\n').encode('utf-8')
    if b''.join(chunks) != expected_alternate:
        raise SystemExit('replay alternates are not the exact clean-primary object store')
'''
    shell = _replace_exact(
        shell,
        old_alternate_check,
        new_alternate_check,
        "optional bootstrap alternate closure",
    )
    cleanup_start = shell.index("cleanup_success_only() {\n")
    cleanup_end = shell.index("\n\n# Static manifest validation is read-only.", cleanup_start)
    cleanup_stubs = '''cleanup_success_only() {
  fail "retained driver forbids replay repository cleanup"
}

cleanup_clean_primary_success_only() {
  fail "retained driver forbids clean-primary cleanup"
}'''
    shell = shell[:cleanup_start] + cleanup_stubs + shell[cleanup_end:]
    self_contained = _self_contained_heredoc(authority)
    writer = _result_writer_heredoc(authority)
    shell = _replace_exact(
        shell,
        "\n# Static manifest validation is read-only.",
        "\n" + self_contained + writer + "\n# Static manifest validation is read-only.",
        "retained helper insertion",
    )
    old_tail = '''printf 'FINAL_HEAD=%s\\nREMOTE_DEV=%s\\nINDEPENDENT_APPROVAL_REQUIRED=1\\nNO_PUSH_PERFORMED=1\\n' "$CURRENT_HEAD" "$(git_primary rev-parse origin/dev)"
assert_replay_closure
cleanup_success_only "$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT"
# Keep the post-call lifecycle ledger explicit: cleanup_success_only resets this only after the replay child was removed.
REPLAY_GIT_BOUND=0
cleanup_clean_primary_success_only
printf 'TASK409_FINAL_REPLAY_OK=1\\nCLEAN_PRIMARY_REMOVED=1\\n'
'''
    new_tail = '''assert_replay_closure
before_mutation
make_retained_repository_self_contained
test ! -e "$REPLAY/.git/objects/info/alternates" && test ! -L "$REPLAY/.git/objects/info/alternates" || fail "retained alternates remains after conversion"
before_mutation
assert_forbidden_ancestry
git_replay merge-base --is-ancestor "$BASE" "$CURRENT_HEAD" || fail "required base ancestor is absent after self-contained conversion"
assert_replay_closure
test ! -e "$REPLAY/.git/objects/info/alternates" && test ! -L "$REPLAY/.git/objects/info/alternates" || fail "retained alternates reappeared after final proof"
test ! -e "$RESULT_ROOT" && test ! -L "$RESULT_ROOT" || fail "replay evidence root appeared before publication"
RETAINED_PARENT="$(git_replay rev-parse "$CURRENT_HEAD^")"
publish_retained_replay_pending "$RETAINED_PARENT"
printf 'TASK409_RETAINED_REPLAY_OK=1\\n'
'''
    shell = _replace_exact(shell, old_tail, new_tail, "retained success tail")
    forbidden = (
        'cleanup_success_only "$REPLAY"',
        "cleanup_clean_primary_success_only\nprintf 'TASK409_FINAL_REPLAY_OK",
        "CLEAN_PRIMARY_REMOVED=1",
        '"$RM" -rf -- "$REPLAY_ROOT"',
        '"$RMDIR" -- "$REPLAY_ROOT"',
        "os.popen(",
    )
    require(not any(token in shell for token in forbidden), "retained success path still deletes retained data")
    require(shell.count("publish_retained_replay_pending") == 2, "pending writer count differs")
    require(shell.count("make_retained_repository_self_contained") == 2, "self-contained helper count differs")
    require(shell.count(PENDING_SCHEMA) == 1, "pending schema count differs")
    require("replay-result.json" not in shell and "replay-completion.json" not in shell, "driver publishes final evidence")
    success_markers = shell.count(SUCCESS_MARKER)
    require(success_markers == 1, f"success marker count differs: {success_markers}")
    require(shell.endswith(f"printf '{SUCCESS_MARKER}\\n'\n"), "terminal marker is not the final shell built-in")
    return shell.encode("utf-8")


def extract_python_heredocs(shell: bytes) -> tuple[str, ...]:
    """Return exact Python heredoc bodies without executing the shell."""
    text = shell.decode("utf-8")
    bodies: list[str] = []
    position = 0
    marker = "<<'PY'\n"
    while True:
        start = text.find(marker, position)
        if start < 0:
            return tuple(bodies)
        body_start = start + len(marker)
        end = text.find("\nPY\n", body_start)
        require(end >= 0, "generated Python heredoc is unterminated")
        bodies.append(text[body_start:end] + "\n")
        position = end + 4


def compile_derived(shell: bytes) -> None:
    """Compile every generated Python heredoc without running shell or Git."""
    bodies = extract_python_heredocs(shell)
    require(len(bodies) >= 1, "derived driver has no Python heredocs")
    for index, body in enumerate(bodies):
        try:
            ast.parse(body, filename=f"retained-driver-heredoc-{index}.py")
            compile(body, f"retained-driver-heredoc-{index}.py", "exec", dont_inherit=True)
        except SyntaxError as error:
            raise Reject(f"generated Python heredoc {index} does not compile: {error}") from error


def derive() -> bytes:
    """Verify authority, transform exact shell bytes, and compile its heredocs."""
    authority = load_frozen_authority()
    result = transform_shell(authority)
    compile_derived(result)
    return result


def derive_contract() -> DerivedDriver:
    """Return the exact argv and stdin bytes that an outer wrapper must use."""
    authority = load_frozen_authority()
    stdin = transform_shell(authority)
    compile_derived(stdin)
    argv = tuple(authority.document["execution_driver"]["argv"])
    return DerivedDriver(
        argv=argv,
        stdin=stdin,
        source_sha256=authority.shell.sha256,
        derived_sha256=hashlib.sha256(stdin).hexdigest(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Derive a retained driver without running it.")
    parser.add_argument("--output", type=Path, help="Optional create-only output path")
    arguments = parser.parse_args(argv)
    raw = derive()
    summary = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "python_heredocs": len(extract_python_heredocs(raw)), "replay_run": False}
    if arguments.output is not None:
        output = arguments.output.resolve()
        require(not os.path.lexists(output), "output already exists")
        require(output.parent.is_dir() and os.path.realpath(output.parent) == os.fspath(output.parent), "output parent differs")
        parent_descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_descriptor)
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                require(count > 0, "output write made no progress")
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
        os.close(parent_descriptor)
        published = stable_read(output, "derived output", mode=0o600)
        require(published.raw == raw, "derived output bytes differ")
        summary["output"] = str(output)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
