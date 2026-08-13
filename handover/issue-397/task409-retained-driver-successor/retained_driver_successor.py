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

RESULT_SCHEMA = "task409-execution-preflight/replay-result/v2"
RESULT_PHASE = "B-post-replay-detached-final-head"
RESULT_LANE = "candidate-4"
COMPLETION_SCHEMA = "hermternal.issue-397.replay-completion.v1"
COMPLETION_MARKER = "replay-complete-retained"
SUCCESS_MARKER = "TASK409_RETAINED_REPLAY_OK=1"
SUCCESS_OUTPUT = (
    b"TASK409_FINAL_REPLAY_OK=1\n"
    b"TASK409_RETAINED_REPLAY_OK=1\n"
    b"REPOSITORY_RETAINED=1\n"
    b"CLEAN_PRIMARY_RETAINED=1\n"
)
PHASE_A_MANIFEST_PATH = "/private/tmp/hermternal-task409-phase-a/input-manifest.json"
PHASE_A_ANCHOR_PATH = "/private/tmp/hermternal-task409-phase-a-approval/phase-a-approval-anchor.json"
RESULT_KEYS = frozenset(
    {
        "schema", "phase", "lane", "phase_a_manifest_sha256",
        "phase_a_approval_digest", "replay_root", "replay_root_identity",
        "repository", "repository_identity", "head_state", "final_head",
        "parent", "tree", "base_commit", "base_tree",
        "protected_main_commit", "required_ancestors", "forbidden_ancestors",
    }
)
COMPLETION_KEYS = frozenset(
    {
        "schema", "completion_marker", "result_path", "result_sha256",
        "result_identity", "driver_sha256", "markdown_sha256", "json_sha256",
        "shell_sha256", "provenance_sha256", "source_commit", "argv_sha256",
        "stdin_sha256", "stdout_sha256", "stderr_sha256", "stdout_bytes",
        "stderr_bytes",
    }
)
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 8 * 1024 * 1024


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
    *,
    phase_a_manifest_path: str = PHASE_A_MANIFEST_PATH,
    phase_a_anchor_path: str = PHASE_A_ANCHOR_PATH,
) -> str:
    base = authority.document["base"]
    forbidden = authority.document["forbidden_ancestry"]
    required = [base["commit"]]
    forbidden_values = list(dict.fromkeys([*forbidden["commits"], *forbidden["raw_semantic_source_commits"]]))
    source = next(
        lane["source_commit"]["commit"]
        for lane in authority.document["ordered_lanes"]
        if lane.get("source_commit")
    )
    argv = tuple(authority.document["execution_driver"]["argv"])
    argv_sha = hashlib.sha256(("\0".join(argv) + "\0").encode("utf-8")).hexdigest()
    values = {
        "base": base["commit"],
        "base_tree": base["tree"],
        "main": base["protected_main_commit"],
        "required": required,
        "forbidden": forbidden_values,
        "source": source,
        "descriptor": authority.descriptor.sha256,
        "provenance": authority.provenance.sha256,
        "json": authority.json.sha256,
        "markdown": authority.markdown.sha256,
        "shell": authority.shell.sha256,
        "argv": argv_sha,
    }
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return f'''publish_retained_replay_evidence() {{
  local parent="$1"
  "$PYTHON" - "$RESULT_ROOT" "$REPLAY" "$CURRENT_HEAD" "$CURRENT_TREE" "$parent" {phase_a_manifest_path!r} {phase_a_anchor_path!r} <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

replay_root, repository, final_head, tree, parent, manifest_path, anchor_path = sys.argv[1:]
authority = json.loads({encoded!r})
OID = re.compile(r'[0-9a-f]{{40}}\\Z')
SHA = re.compile(r'[0-9a-f]{{64}}\\Z')
RESULT_KEYS = {sorted(RESULT_KEYS)!r}
COMPLETION_KEYS = {sorted(COMPLETION_KEYS)!r}

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

def read_private(path, label, limit=2 * 1024 * 1024):
    canonical(path, label)
    samples = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o077:
                reject(label + ' is not private and single-link')
            raw = bytearray()
            while True:
                block = os.read(fd, min(131072, limit + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                if len(raw) > limit:
                    reject(label + ' exceeds its byte limit')
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        identity = (before.st_dev, before.st_ino, before.st_uid, stat.S_IMODE(before.st_mode), before.st_size, before.st_nlink)
        if identity != (after.st_dev, after.st_ino, after.st_uid, stat.S_IMODE(after.st_mode), after.st_size, after.st_nlink) or identity != (final.st_dev, final.st_ino, final.st_uid, stat.S_IMODE(final.st_mode), final.st_size, final.st_nlink):
            reject(label + ' changed during read')
        samples.append((bytes(raw), identity))
    if samples[0] != samples[1] or samples[0] != samples[2]:
        reject(label + ' changed across reads')
    return samples[0]

def strict_json(raw, label):
    def pairs(items):
        value = {{}}
        for key, item in items:
            if key in value:
                reject(label + ' contains a duplicate key')
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs)
    except Exception as error:
        reject(label + ' JSON failed: ' + str(error))
    if not isinstance(value, dict):
        reject(label + ' root differs')
    return value

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
    observed, identity = read_private(path, label)
    if observed != raw:
        reject(label + ' bytes differ after creation')
    return observed, identity

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
manifest_raw, _ = read_private(canonical(manifest_path, 'Phase A manifest'), 'Phase A manifest')
manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
manifest = strict_json(manifest_raw, 'Phase A manifest')
policy = manifest.get('policy')
if not isinstance(policy, dict):
    reject('Phase A policy is absent')
if policy.get('base_commit') != authority['base'] or policy.get('base_tree') != authority['base_tree'] or policy.get('main_commit') != authority['main']:
    reject('Phase A base policy differs from frozen authority')
if policy.get('required_ancestors') != authority['required'] or policy.get('forbidden_ancestors') != authority['forbidden']:
    reject('Phase A ancestry policy differs from frozen authority')
approval_payload = {{key: manifest[key] for key in ('schema', 'phase', 'artifacts', 'shell_metadata', 'normalized_json_sha256', 'inputs', 'stale', 'policy')}}
approval = hashlib.sha256(json.dumps(approval_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest()
anchor_raw, _ = read_private(canonical(anchor_path, 'Phase A approval anchor'), 'Phase A approval anchor', 4096)
anchor = strict_json(anchor_raw, 'Phase A approval anchor')
anchor_keys = {{'schema', 'phase', 'manifest_sha256', 'phase_a_approval_digest', 'policy_sha256', 'decision', 'provisioning_boundary'}}
policy_sha = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest()
if set(anchor) != anchor_keys or anchor.get('schema') != 'task409-execution-preflight/phase-a-approval-anchor/v1' or anchor.get('phase') != 'external-review-of-phase-a-consistency':
    reject('Phase A approval anchor schema differs')
if anchor.get('manifest_sha256') != manifest_sha or anchor.get('phase_a_approval_digest') != approval or anchor.get('policy_sha256') != policy_sha or anchor.get('decision') != 'approve-consistency-only' or anchor.get('provisioning_boundary') != 'external-review-input':
    reject('Phase A approval anchor differs')

# Create the result root only after all external evidence is authenticated.
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

result = {{
    'schema': {RESULT_SCHEMA!r}, 'phase': {RESULT_PHASE!r}, 'lane': {RESULT_LANE!r},
    'phase_a_manifest_sha256': manifest_sha, 'phase_a_approval_digest': approval,
    'replay_root': replay_root, 'replay_root_identity': replay_identity,
    'repository': repository, 'repository_identity': repository_identity,
    'head_state': 'detached', 'final_head': final_head, 'parent': parent, 'tree': tree,
    'base_commit': authority['base'], 'base_tree': authority['base_tree'],
    'protected_main_commit': authority['main'], 'required_ancestors': authority['required'],
    'forbidden_ancestors': authority['forbidden'],
}}
if set(result) != set(RESULT_KEYS):
    reject('replay result fields differ')
result_path = os.path.join(replay_root, 'replay-result.json')
result_raw, result_identity = create_once(result_path, result, 'replay result')
completion = {{
    'schema': {COMPLETION_SCHEMA!r}, 'completion_marker': {COMPLETION_MARKER!r},
    'result_path': result_path, 'result_sha256': hashlib.sha256(result_raw).hexdigest(),
    'result_identity': {{'st_dev': result_identity[0], 'st_ino': result_identity[1], 'st_uid': result_identity[2], 'st_mode': result_identity[3], 'st_size': result_identity[4], 'st_nlink': result_identity[5]}},
    'driver_sha256': authority['shell'], 'markdown_sha256': authority['markdown'],
    'json_sha256': authority['json'], 'shell_sha256': authority['shell'],
    'provenance_sha256': authority['provenance'], 'source_commit': authority['source'],
    'argv_sha256': authority['argv'], 'stdin_sha256': authority['shell'],
    'stdout_sha256': hashlib.sha256((f'FINAL_HEAD={{final_head}}\\nREMOTE_DEV={{authority["base"]}}\\nINDEPENDENT_APPROVAL_REQUIRED=1\\nNO_PUSH_PERFORMED=1\\n').encode('ascii') + {SUCCESS_OUTPUT!r}).hexdigest(),
    'stderr_sha256': hashlib.sha256(b'').hexdigest(),
    'stdout_bytes': len((f'FINAL_HEAD={{final_head}}\\nREMOTE_DEV={{authority["base"]}}\\nINDEPENDENT_APPROVAL_REQUIRED=1\\nNO_PUSH_PERFORMED=1\\n').encode('ascii') + {SUCCESS_OUTPUT!r}), 'stderr_bytes': 0,
}}
if set(completion) != set(COMPLETION_KEYS):
    reject('replay completion fields differ')
completion_path = os.path.join(replay_root, 'replay-completion.json')
create_once(completion_path, completion, 'replay completion')
read_private(result_path, 'replay result final')
read_private(completion_path, 'replay completion final')
dir_identity(replay_root, 'replay root final')
dir_identity(repository, 'repository final')
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
    cleanup_start = shell.index("cleanup_success_only() {\n")
    cleanup_end = shell.index("\n\n# Static manifest validation is read-only.", cleanup_start)
    cleanup_stubs = '''cleanup_success_only() {
  fail "retained driver forbids replay repository cleanup"
}

cleanup_clean_primary_success_only() {
  fail "retained driver forbids clean-primary cleanup"
}'''
    shell = shell[:cleanup_start] + cleanup_stubs + shell[cleanup_end:]
    writer = _result_writer_heredoc(authority)
    shell = _replace_exact(shell, "\n# Static manifest validation is read-only.", "\n" + writer + "\n# Static manifest validation is read-only.", "evidence-writer insertion")
    old_tail = '''printf 'FINAL_HEAD=%s\\nREMOTE_DEV=%s\\nINDEPENDENT_APPROVAL_REQUIRED=1\\nNO_PUSH_PERFORMED=1\\n' "$CURRENT_HEAD" "$(git_primary rev-parse origin/dev)"
assert_replay_closure
cleanup_success_only "$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT"
# Keep the post-call lifecycle ledger explicit: cleanup_success_only resets this only after the replay child was removed.
REPLAY_GIT_BOUND=0
cleanup_clean_primary_success_only
printf 'TASK409_FINAL_REPLAY_OK=1\\nCLEAN_PRIMARY_REMOVED=1\\n'
'''
    new_tail = '''printf 'FINAL_HEAD=%s\\nREMOTE_DEV=%s\\nINDEPENDENT_APPROVAL_REQUIRED=1\\nNO_PUSH_PERFORMED=1\\n' "$CURRENT_HEAD" "$(git_primary rev-parse origin/dev)"
assert_replay_closure
test ! -e "$RESULT_ROOT" && test ! -L "$RESULT_ROOT" || fail "replay evidence root appeared before publication"
RETAINED_PARENT="$(git_replay rev-parse "$CURRENT_HEAD^")"
publish_retained_replay_evidence "$RETAINED_PARENT"
assert_replay_closure
printf 'TASK409_FINAL_REPLAY_OK=1\\nTASK409_RETAINED_REPLAY_OK=1\\nREPOSITORY_RETAINED=1\\nCLEAN_PRIMARY_RETAINED=1\\n'
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
    require(shell.count("publish_retained_replay_evidence") == 2, "retained evidence writer count differs")
    require(shell.count(RESULT_SCHEMA) == 1 and shell.count(COMPLETION_SCHEMA) == 1, "retained schema count differs")
    require(shell.count(COMPLETION_MARKER) == 1, "completion marker count differs")
    success_markers = shell.count(SUCCESS_MARKER)
    require(success_markers == 3, f"success marker count differs: {success_markers}")
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
