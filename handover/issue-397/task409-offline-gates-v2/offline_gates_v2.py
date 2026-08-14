#!/usr/bin/env python3
"""Create a Linux-bound, evidence-only offline-gate report after replay.

The committed pins are deliberately incomplete until the reviewed Linux
authority and #405 successor exist. This program rejects that state instead
of falling back to the retired macOS authority. It never pulls, installs, or
contacts a service: a reviewed local Podman image must already contain the
exact Bun, browser, and locked dependency set.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

PINS_PATH = Path(__file__).resolve().with_name("final-linux-pins.json")
REPORT_SCHEMA = "hermternal.issue-397.offline-gates/v3"
PINS_SCHEMA = "hermternal.issue-397.offline-gates/v4-final-linux-pins"
MAX_OUTPUT = 2 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
PHASE_EVIDENCE_SCHEMA_RE = re.compile(
    r"hermternal\.issue-397\.phase-a-anchor-evidence\.v[1-9][0-9]*\Z"
)
SAFE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "CI": "1", "NO_COLOR": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1", "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright", "BUN_INSTALL_CACHE_DIR": "/tmp/bun-cache"}
LOCAL_GIT_ENV = {**SAFE_ENV, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"}
PODMAN_INFO_FORMAT = "{{.Host.Security.Rootless}}\n{{.Store.GraphRoot}}\n{{.Store.RunRoot}}"
RENDERER_ADAPTATION_CONTRACT = (
    "/workspace/apps/web/src/lib/terminal/renderer.test.ts",
    "100644",
    "8d489b746e2dc0f6c15b32b0174f62db58c308e3",
    "776a517e44dd274066e97d1f26a2be17a35793d9e556fc60f1e4391a18b6512f",
    "#!/opt/homebrew/bin/bun",
    "#!${process.execPath}",
    "47d78dc3e3390ae82528072af5ce09948a9c20190ec597996b5b9bcd8f7a2cce",
)
RENDERER_ADAPTATION_CONTRACT_SHA256 = "7efa9ccaf939ea3fe1debc6e252d9dc368cbc65b0c820b268d221fd33c2df293"
RENDERER_ADAPTATION_SCRIPT = """import hashlib
import os
import stat
import sys

def stop(message):
    raise SystemExit("renderer adaptation: " + message)

if len(sys.argv) != 8:
    stop("argument set differs")
path, git_mode, git_blob, before_sha, old_text, new_text, after_sha = sys.argv[1:]
if path != "/workspace/apps/web/src/lib/terminal/renderer.test.ts":
    stop("path differs")
if git_mode != "100644" or git_blob != "8d489b746e2dc0f6c15b32b0174f62db58c308e3":
    stop("final Git mode or blob differs")
if before_sha != "776a517e44dd274066e97d1f26a2be17a35793d9e556fc60f1e4391a18b6512f":
    stop("source SHA-256 differs")
if old_text != "#!/opt/homebrew/bin/bun" or new_text != "#!${process.execPath}":
    stop("literal contract differs")
if after_sha != "47d78dc3e3390ae82528072af5ce09948a9c20190ec597996b5b9bcd8f7a2cce":
    stop("result SHA-256 differs")
if os.path.realpath(path) != path:
    stop("path is not canonical")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
descriptor = os.open(path, flags)
try:
    before = os.fstat(descriptor)
    raw = bytearray()
    while True:
        block = os.read(descriptor, 131072)
        if not block:
            break
        raw.extend(block)
        if len(raw) > 8 * 1024 * 1024:
            stop("source exceeds byte limit")
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
final = os.lstat(path)
identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
if identity(before) != identity(after) or identity(after) != identity(final):
    stop("source changed during verified load")
if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o644 or before.st_nlink != 1:
    stop("source metadata differs")
source = bytes(raw)
if hashlib.sha256(source).hexdigest() != before_sha:
    stop("source SHA-256 differs")
git_object = b"blob " + str(len(source)).encode("ascii") + b"\\0" + source
if hashlib.sha1(git_object).hexdigest() != git_blob:
    stop("final Git blob differs")
old = old_text.encode("utf-8")
new = new_text.encode("utf-8")
old_count = source.count(old)
if old_count != 3:
    stop("literal count differs")
updated = source.replace(old, new)
if updated.count(old) != 0:
    stop("replacement count differs")
if hashlib.sha256(updated).hexdigest() != after_sha:
    stop("result SHA-256 differs")
temporary = path + ".hermternal-linux-adaptation"
output = -1
try:
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    view = memoryview(updated)
    while view:
        written = os.write(output, view)
        if written <= 0:
            stop("result write failed")
        view = view[written:]
    os.fchmod(output, 0o644)
    os.fsync(output)
    result = os.fstat(output)
    if not stat.S_ISREG(result.st_mode) or stat.S_IMODE(result.st_mode) != 0o644 or result.st_nlink != 1 or result.st_size != len(updated):
        stop("result metadata differs")
    os.close(output)
    output = -1
    os.replace(temporary, path)
except BaseException:
    if output >= 0:
        os.close(output)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
result = os.lstat(path)
if not stat.S_ISREG(result.st_mode) or stat.S_IMODE(result.st_mode) != 0o644 or result.st_nlink != 1:
    stop("published result metadata differs")
descriptor = os.open(path, flags)
try:
    published_before = os.fstat(descriptor)
    published = b""
    while len(published) < len(updated):
        block = os.read(descriptor, len(updated) - len(published))
        if not block:
            break
        published += block
    trailing = os.read(descriptor, 1)
    published_after = os.fstat(descriptor)
finally:
    os.close(descriptor)
published_final = os.lstat(path)
if identity(published_before) != identity(published_after) or identity(published_after) != identity(published_final):
    stop("published result changed during verified load")
if published_final.st_size != len(updated) or trailing != b"":
    stop("published result size differs")
if published != updated or hashlib.sha256(published).hexdigest() != after_sha:
    stop("published result differs")
"""
RENDERER_ADAPTATION_SCRIPT_SHA256 = "94ac1f3390c58cffaf4c6c27815fbdef05d29c3ce5ec9c821b5854b04fac0d91"


class Reject(Exception):
    """The pinned replay chain or an offline gate is unacceptable."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
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
    require(isinstance(value, dict), f"{label} root is not an object")
    return value


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int, int, int]


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)


def stable_read(path: Path, label: str, limit: int = MAX_FILE, mode: int | None = None) -> Snapshot:
    """Read a canonical private file three times and reject replacement races."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path is not canonical")
    reads: list[Snapshot] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit, f"{label} metadata differs")
            require(mode is None or stat.S_IMODE(before.st_mode) == mode, f"{label} mode differs")
            raw = bytearray()
            while True:
                block = os.read(fd, min(131072, limit + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                require(len(raw) <= limit, f"{label} exceeds its byte limit")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        require(_identity(before) == _identity(after) == _identity(final) and len(raw) == before.st_size, f"{label} changed during read")
        reads.append(Snapshot(path, bytes(raw), digest(bytes(raw)), _identity(before)))
    require(reads[0] == reads[1] == reads[2], f"{label} changed across reads")
    return reads[0]


def verified_module(path: Path, expected: str, name: str) -> types.ModuleType:
    source = stable_read(path.resolve(), name, 2 * 1024 * 1024, 0o644)
    require(source.sha256 == expected, f"{name} SHA-256 differs")
    module = types.ModuleType(name); module.__file__ = os.fspath(path); module.__loader__ = None
    sys.modules[name] = module
    exec(compile(source.raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


@dataclass(frozen=True)
class Pins:
    profile_path: Path
    profile_sha256: str
    authority_root: Path
    authority_module: Path
    authority_sha256: str
    wrapper_module: Path
    wrapper_sha256: str
    phase_a_module: Path
    phase_a_sha256: str
    result_path: Path
    result_sha256: str
    completion_path: Path
    completion_sha256: str
    expected_dev_base: str
    image: str
    image_digest: str
    dependencies_sha256: str


def _pin_path(value: Any, label: str, pins_path: Path, base: Path) -> Path:
    require(isinstance(value, str) and value and not os.path.isabs(value), f"{label} path differs")
    path = (pins_path.parent / value).resolve()
    require(path.is_relative_to(base), f"{label} escapes handover")
    return path


def _publication_path(value: Any, name: str, label: str) -> Path:
    """Bind one real create-only publication path without a fallback root."""
    require(isinstance(value, str) and value and os.path.isabs(value), f"{label} path differs")
    path = Path(value)
    require(os.fspath(path) == os.path.realpath(path), f"{label} path is not canonical")
    require(path.name == name and path.parent.name == "replay-root", f"{label} placement differs")
    return path


def _authority_root(value: Any, pins_path: Path, base: Path) -> Path:
    """Accept only the path-bound approved v3 root-shape authority."""
    require(isinstance(value, str) and value, "Linux authority root differs")
    root = Path(value) if os.path.isabs(value) else (pins_path.parent / value).resolve()
    require(os.fspath(root) == os.path.realpath(root), "Linux authority root is not canonical")
    require(root.name == "task464-candidate5-linux-v3-root-shape-final",
            "Linux authority is not the approved v3 root-shape boundary")
    if not os.path.isabs(value):
        require(root.is_relative_to(base), "Linux authority root escapes handover")
    return root


def load_pins(path: Path | None = None) -> Pins:
    """Load the one finalization file; deferred values are an execution stop."""
    pins_path = Path(path or PINS_PATH).resolve()
    base = pins_path.parents[1]
    raw = stable_read(pins_path, "final Linux pins", 64 * 1024, 0o644)
    value = strict_json(raw.raw, "final Linux pins")
    required = {"schema", "status", "platform_profile", "linux_authority", "replay", "publication", "expected_dev_base", "toolchain"}
    require(set(value) == required and value.get("schema") == PINS_SCHEMA, "final Linux pins schema differs")
    require(value.get("status") == "final", "final Linux pins are not finalized")
    profile, authority, replay = value["platform_profile"], value["linux_authority"], value["replay"]
    publication, toolchain = value["publication"], value["toolchain"]
    require(isinstance(profile, dict) and set(profile) == {"path", "sha256"}, "platform profile pins differ")
    require(isinstance(authority, dict) and set(authority) == {"root", "module_path", "module_sha256"}, "Linux authority pins differ")
    require(isinstance(replay, dict) and set(replay) == {"wrapper_path", "wrapper_sha256", "phase_a_path", "phase_a_sha256"}, "Linux replay pins differ")
    require(isinstance(publication, dict) and set(publication) == {"result_path", "result_sha256", "completion_path", "completion_sha256"}, "Linux publication pins differ")
    require(isinstance(toolchain, dict) and set(toolchain) == {"image", "repo_digest", "bun", "node", "playwright", "dependencies_sha256"}, "toolchain pins differ")
    strings = [(profile["sha256"], "profile SHA-256"), (authority["module_sha256"], "authority SHA-256"), (replay["wrapper_sha256"], "wrapper SHA-256"), (replay["phase_a_sha256"], "Phase A SHA-256"), (publication["result_sha256"], "result SHA-256"), (publication["completion_sha256"], "completion SHA-256"), (toolchain["repo_digest"], "image digest"), (toolchain["dependencies_sha256"], "dependency SHA-256")]
    require(all(isinstance(item, str) and SHA_RE.fullmatch(item) for item, _ in strings), "final Linux pin digest differs")
    require(isinstance(value["expected_dev_base"], str) and OID_RE.fullmatch(value["expected_dev_base"]), "expected dev base differs")
    require(isinstance(toolchain["image"], str) and "@sha256:" in toolchain["image"] and toolchain["image"].endswith(toolchain["repo_digest"]), "toolchain image differs")
    require(toolchain["bun"] == "1.3.14" and toolchain["node"] == "26.7.0" and toolchain["playwright"] == "1.62.1", "toolchain version pins differ")
    root = _authority_root(authority["root"], pins_path, base)
    result_path = _publication_path(publication["result_path"], "replay-result.json", "result")
    completion_path = _publication_path(publication["completion_path"], "replay-completion.json", "completion")
    require(result_path.parent == completion_path.parent, "publication paths have different replay roots")
    return Pins(_pin_path(profile["path"], "platform profile", pins_path, base), profile["sha256"], root, _pin_path(authority["module_path"], "Linux authority", pins_path, base), authority["module_sha256"], _pin_path(replay["wrapper_path"], "Linux wrapper", pins_path, base), replay["wrapper_sha256"], _pin_path(replay["phase_a_path"], "Linux Phase A", pins_path, base), replay["phase_a_sha256"], result_path, publication["result_sha256"], completion_path, publication["completion_sha256"], value["expected_dev_base"], toolchain["image"], toolchain["repo_digest"], toolchain["dependencies_sha256"])


@dataclass(frozen=True)
class Chain:
    repository: Path
    repository_identity: tuple[int, int, int, int, int, int, int, int]
    final_head: str
    final_tree: str
    protected_main: str
    expected_dev_base: str
    result: Snapshot
    completion: Snapshot
    phase_anchor: Snapshot
    provenance: Snapshot


@dataclass(frozen=True)
class WorkspaceArchive:
    root: Path
    root_identity: tuple[int, int, int, int]
    head: str
    tree: str
    members: tuple[str, ...]
    snapshot: Snapshot


@dataclass(frozen=True)
class HistoricalObjects:
    """The Phase-v11 guarded object store used by exact parent-source tests."""

    repository: Path
    repository_identity: tuple[int, int, int, int]
    object_dir: Path
    object_dir_identity: tuple[int, int, int, int]
    head: str
    tree: str


@dataclass(frozen=True)
class GitRequirement:
    """One exact commit/path state that a selected web test reads with Git."""

    commit: str
    path: str
    blob: str
    purpose: str
    guarded_only: bool = False


def _require_oid(value: Any, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value), f"{label} differs")
    return value


def _load_chain(result_path: Path, completion_path: Path, pins: Pins | None = None) -> Chain:
    """Validate only the final Linux #403 → #404 → #405 contract."""
    pins = pins or load_pins()
    result_path = Path(result_path).resolve()
    completion_path = Path(completion_path).resolve()
    require(result_path == pins.result_path and completion_path == pins.completion_path,
            "runtime publication paths differ from final Linux pins")
    profile = verified_module(pins.profile_path, pins.profile_sha256, "issue397_offline_platform_profile")
    loaded_profile = profile.load()
    require(Path(loaded_profile.authority_root) == pins.authority_root, "profile authority root differs")
    authority = verified_module(pins.authority_module, pins.authority_sha256, "issue397_offline_authority")
    wrapper = verified_module(pins.wrapper_module, pins.wrapper_sha256, "issue397_offline_wrapper")
    phase = verified_module(pins.phase_a_module, pins.phase_a_sha256, "issue397_offline_phase_a")
    phase_schema = getattr(phase, "EVIDENCE_SCHEMA", None)
    require(isinstance(phase_schema, str) and PHASE_EVIDENCE_SCHEMA_RE.fullmatch(phase_schema) is not None, "Linux Phase A schema differs")
    descriptor = stable_read(pins.authority_root / "authority-descriptor.json", "Linux authority descriptor", mode=0o600)
    provenance = stable_read(pins.authority_root / "provenance-manifest.json", "Linux provenance", mode=0o600)
    validated = authority.validate(descriptor.path, pins.authority_root, descriptor.sha256)
    replay_authority = wrapper.load_authority()
    result = stable_read(result_path, "#405 result", mode=0o600)
    completion = stable_read(completion_path, "#405 completion", mode=0o600)
    require(result.sha256 == pins.result_sha256 and completion.sha256 == pins.completion_sha256,
            "runtime publication SHA-256 differs from final Linux pins")
    result_value, completion_value = strict_json(result.raw, "#405 result"), strict_json(completion.raw, "#405 completion")
    require(set(result_value) == set(wrapper.RESULT_KEYS) and result_value.get("schema") == wrapper.RESULT_SCHEMA and result_value.get("phase") == wrapper.RESULT_PHASE and result_value.get("lane") == wrapper.RESULT_LANE, "#405 result schema differs")
    require(set(completion_value) == set(wrapper.COMPLETION_KEYS) and completion_value.get("schema") == wrapper.COMPLETION_SCHEMA and completion_value.get("completion_marker") == wrapper.SUCCESS_OUTPUT.decode("ascii").strip() and completion_value.get("stderr_policy") == wrapper.STDERR_POLICY and completion_value.get("returncode") == 0, "#405 completion state differs")
    require(completion_value.get("result_path") == os.fspath(result.path) and completion_value.get("result_sha256") == result.sha256, "#405 completion result binding differs")
    require(completion_value.get("driver_module_sha256") == wrapper.DRIVER_SHA256 and completion_value.get("driver_source_sha256") == validated.artifacts["shell"].sha256, "#405 driver binding differs")
    require(completion_value.get("markdown_sha256") == validated.artifacts["markdown"].sha256 and completion_value.get("json_sha256") == validated.artifacts["json"].sha256 and completion_value.get("shell_sha256") == validated.artifacts["shell"].sha256 and completion_value.get("provenance_sha256") == provenance.sha256, "Linux/#405 authority binding differs")
    for key in ("base_commit", "base_tree", "protected_main_commit", "required_ancestors", "forbidden_ancestors"):
        require(result_value.get(key) == getattr(replay_authority, key), f"#405 {key} differs")
    require(completion_value.get("source_commit") == replay_authority.source_commit, "#405 source commit differs")
    final_head, final_tree = _require_oid(result_value.get("final_head"), "#405 final_head"), _require_oid(result_value.get("tree"), "#405 tree")
    repository = Path(result_value.get("repository", "")); replay_root = Path(result_value.get("replay_root", ""))
    require(repository.is_absolute() and replay_root.is_absolute() and repository.name == "repository" and replay_root.name == "replay-root" and repository.parent == replay_root.parent, "#405 retained root layout differs")
    repo_meta = os.lstat(repository)
    require(stat.S_ISDIR(repo_meta.st_mode) and repo_meta.st_uid == os.getuid() and stat.S_IMODE(repo_meta.st_mode) == 0o700, "retained repository is not private")
    evidence = wrapper.load_phase_a_evidence(Path(completion_value.get("phase_a_evidence_path", "")), completion_value.get("phase_a_evidence_sha256", ""))
    phase_anchor = strict_json(evidence.snapshot.raw, "Phase A anchor")
    require(phase_anchor.get("schema") == phase_schema, "Phase A anchor schema differs")
    require(result_value.get("phase_a_manifest_sha256") == evidence.manifest_sha256 and result_value.get("phase_a_approval_digest") == evidence.approval_digest, "Linux/#405 Phase A binding differs")
    return Chain(repository, _identity(repo_meta), final_head, final_tree, result_value["protected_main_commit"], pins.expected_dev_base, result, completion, evidence.snapshot, provenance)


@dataclass(frozen=True)
class Gate:
    gate_id: str
    workdir: str
    command: tuple[str, ...]


GATES = (Gate("git-head", "/workspace", ("git", "rev-parse", "HEAD^{commit}")), Gate("git-tree", "/workspace", ("git", "rev-parse", "HEAD^{tree}")), Gate("git-main", "/workspace", ("git", "rev-parse", "refs/remotes/origin/main^{commit}")), Gate("git-dev-base", "/workspace", ("git", "rev-parse", "refs/remotes/origin/dev^{commit}")), Gate("git-clean", "/workspace", ("git", "status", "--porcelain=v1", "--untracked-files=all")), Gate("git-fsck", "/workspace", ("git", "fsck", "--full", "--strict")), Gate("web-typecheck", "/workspace/apps/web", ("bun", "x", "--no-install", "svelte-check", "--tsconfig", "./tsconfig.json")), Gate("web-unit", "/workspace/apps/web", ("bun", "x", "--no-install", "vitest", "run")), Gate("web-build", "/workspace/apps/web", ("bun", "x", "--no-install", "vite", "build")), Gate("privacy-redaction", "/workspace/apps/web", ("bun", "x", "--no-install", "vitest", "run", "src/lib/live-artifact-policy.test.ts", "src/lib/live-screenshot-contract.test.ts")), Gate("accessibility", "/workspace/apps/web", ("bun", "run", "--no-install", "test:a11y")), Gate("no-network-browser", "/workspace/apps/web", ("bun", "run", "--no-install", "test:no-network")), Gate("auth-click-enter", "/workspace/apps/web", ("bun", "x", "--no-install", "playwright", "test", "tests/e2e/ui-preview.spec.ts", "--grep", "native password activation clears live values")))
GATE_LIST_SHA256 = digest(json.dumps([[g.gate_id, g.workdir, list(g.command)] for g in GATES], separators=(",", ":")).encode())
LOCAL_GIT_GATE_IDS = ("git-head", "git-tree", "git-main", "git-dev-base", "git-clean", "git-fsck")
PODMAN_GATE_IDS = ("web-typecheck", "web-unit", "web-build", "privacy-redaction", "accessibility", "no-network-browser", "auth-click-enter")
WORKSPACE_TRACKED_INPUTS = (
    "apps/web/.bun-version", "apps/web/bun.lock", "apps/web/package.json",
    "apps/web/playwright.config.ts", "apps/web/playwright.live.config.ts",
    "apps/web/svelte.config.js", "apps/web/tsconfig.json",
    "apps/web/vite.config.ts", "apps/web/vitest.config.ts", "apps/web/src",
    "apps/web/static", "apps/web/tests/setup.ts", "apps/web/tests/e2e",
    "apps/web/tests/live", "apps/web/tests/static", "apps/web/tests/bench",
    "contracts/fixtures/behavioral-probe/probe-fixtures.json",
    "contracts/fixtures/compatibility-attestation/cases.json",
    "contracts/fixtures/compatibility-attestation/revision_attestation.json",
    "contracts/hermes-dashboard/manifest.md",
)
WORKSPACE_TRACKED_INPUTS_SHA256 = "8305ef9d20a15b6b78f94654c98942045ae9e040272b735fdbba8541f466ec24"
GIT_REQUIREMENTS = (
    GitRequirement("d88cd9adfcef94980ae674f40d99c65e1cf9b666", "apps/web/src/lib/auth-ui/AuthPreview.svelte", "8e6e652129f6fd90ce941a02c067e31fcc53bfd3", "approved authentication parent"),
    GitRequirement("f87ce048b5afc4fad7ac361baa589d47745b580b", "apps/web/src/lib/auth-ui/AuthPreview.svelte", "7f847ea0762ad90eb6d4e04effafc6763792c22f", "authentication correction parent"),
    GitRequirement("a7d43f636424dcd02bf65743966db30e5aeb30f0", "apps/web/tests/live/live-proof-ledger.mjs", "838a905b24e81c877e891e6c41bfdf0fc11f51c6", "live-proof ledger parent", True),
    GitRequirement("4c1cd74f6d703a99a29ef85a08142df45234e9f5", "apps/web/tests/live/live-proof-page-bridge.mjs", "cb5a853525889f3044ffb170ae65d07f59df2939", "live-proof bridge parent", True),
    GitRequirement("77c6701c652a6bbd23d2c32227dcd61c34dd8c33", "apps/web/src/lib/live-screenshot-capture.test.ts", "c30e3ea50b6ba5db2cccc554a69f8483a9f75171", "live-support parent"),
    GitRequirement("77c6701c652a6bbd23d2c32227dcd61c34dd8c33", "apps/web/tests/live/live-screenshot-contract.mjs", "8998659df76513ba7c7a7a0256dd90f37a98a0f8", "live-support screenshot contract"),
    GitRequirement("77c6701c652a6bbd23d2c32227dcd61c34dd8c33", "apps/web/tests/live/official-hermes.spec.ts", "fe269bb21d40690463b320dc59d9023950d0dd1d", "live-support official specification"),
    GitRequirement("5559e9ad4cf78debc98e8935c47cdc956535f96c", "apps/web/src/lib/terminal/renderer.test.ts", "6448ddf3286a1e3d04dbeeab6dfe18e60d3da14d", "renderer deadline parent"),
    GitRequirement("9d9756b2a0a20130258766ea3a532c067e2f13f6", "apps/web/src/lib/terminal/renderer.test.ts", "fc1989b7a00baf9f3846ac88e916d64ea8d9e059", "renderer stream-cleanup parent"),
    GitRequirement("d36d68ab795608d2c96db0bcfe1d213e64081103", "apps/web/tests/bench/terminal-renderer.evidence.json", "98dfd03ef22c02705f7e9cf5f611d166aeab6c84", "renderer benchmark source"),
    GitRequirement("2de293cf2b7d84386bbffaf3f41ace8a73e4c19a", "apps/web/tests/bench/terminal-renderer.evidence.json", "b005ae8ffd930a4814a70fc9db931fd6c5b8146c", "renderer benchmark evidence child"),
)
GIT_REQUIREMENTS_SHA256 = "286bdccb8c4221d65c1784b5f0142f7fe5768a068703492061ecdf10c3574b53"
GIT_DECLARATIONS = (
    ("apps/web/src/lib/auth-ui/AuthPreview.test.ts", "d88cd9adfcef94980ae674f40d99c65e1cf9b666"),
    ("apps/web/src/lib/auth-ui/AuthPreview.test.ts", "f87ce048b5afc4fad7ac361baa589d47745b580b"),
    ("apps/web/tests/live/live-proof-parent-compat.mjs", "a7d43f636424dcd02bf65743966db30e5aeb30f0"),
    ("apps/web/tests/live/live-proof-parent-compat.mjs", "4c1cd74f6d703a99a29ef85a08142df45234e9f5"),
    ("apps/web/tests/live/live-support-parent-compat.mjs", "77c6701c652a6bbd23d2c32227dcd61c34dd8c33"),
    ("apps/web/src/lib/terminal/renderer.test.ts", "5559e9ad4cf78debc98e8935c47cdc956535f96c"),
    ("apps/web/src/lib/terminal/renderer.test.ts", "9d9756b2a0a20130258766ea3a532c067e2f13f6"),
    ("apps/web/tests/bench/terminal-renderer.evidence.json", "d36d68ab795608d2c96db0bcfe1d213e64081103"),
)
GIT_DECLARATIONS_SHA256 = "ee3b20585e5da7fb67e1ea1bf87ee7c7508ebb6e76631d738b3d7b616b022655"
BENCHMARK_EVIDENCE_PATH = "apps/web/tests/bench/terminal-renderer.evidence.json"
BENCHMARK_SOURCE_COMMIT = "d36d68ab795608d2c96db0bcfe1d213e64081103"
BENCHMARK_ANCHOR_COMMIT = "2de293cf2b7d84386bbffaf3f41ace8a73e4c19a"
BENCHMARK_EVIDENCE_BLOB = "b005ae8ffd930a4814a70fc9db931fd6c5b8146c"
GUARDED_SOURCE_HEAD = "c6b9a185500a1928055b9b3a475c14b0add38f05"
GUARDED_SOURCE_TREE = "ecf9c8e5712249ded71120d62e29981c4a59219b"


def rootless_podman_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Bind Podman to this account's canonical private storage boundary."""
    source = os.environ if environment is None else environment
    uid = os.getuid()
    home = Path(pwd.getpwuid(uid).pw_dir)
    runtime = Path(f"/run/user/{uid}")
    require(source.get("HOME") == os.fspath(home), "Podman HOME differs from the real user home")
    require(source.get("XDG_RUNTIME_DIR") == os.fspath(runtime), "Podman runtime directory differs")
    for path, label in (
        (home, "Podman HOME"),
        (runtime, "Podman runtime directory"),
        (home / ".local/share/containers/storage", "Podman graph storage"),
        (runtime / "containers", "Podman run storage"),
    ):
        metadata = os.lstat(path)
        require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} is not canonical")
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == uid and stat.S_IMODE(metadata.st_mode) == 0o700,
                f"{label} privacy differs")
    return {
        "PATH": "/usr/bin:/bin", "HOME": os.fspath(home),
        "XDG_RUNTIME_DIR": os.fspath(runtime), "LANG": "C", "LC_ALL": "C",
    }


def podman_argv(repository: Path, archive: WorkspaceArchive, historical: HistoricalObjects,
                gate: Gate, pins: Pins) -> tuple[str, ...]:
    """Run a fixed gate from an authenticated private final-tree workspace.

    The reviewed image carries immutable dependencies at /opt/hermternal. The
    entry script extracts only reviewed tracked inputs without restoring archive
    ownership, copies image dependencies into the dedicated tmpfs, and generates
    SvelteKit metadata before Bun runs. Explicit no-same-owner is required because
    rootless ID mapping can otherwise make extracted parent directories read-only
    to the fixed image user. Podman starts in the existing workspace mount; it
    must not create the later web working directory before this script runs. A
    private Git directory keeps reviewed tests on the retained objects plus the
    Phase-v11 guarded object store even when a test removes inherited Git
    environment variables. Both stores are read-only. No object or ref enters
    the replay repository, and no package install or download is permitted.
    One verified private-workspace adaptation replaces the three reviewed
    macOS Bun shebang literals with the portable process executable literal.
    It binds the final-tree mode, blob, source bytes, count, and result bytes.
    The archive, retained checkout, and object stores remain unchanged.
    The private init process reaps descendant test processes after bounded
    process-group cleanup. Without it, closed inherited pipes can remain held
    by container zombies and turn the reviewed timeout result into a false
    cleanup-timeout failure.
    """
    uid, gid = os.getuid(), os.getgid()
    require(
        digest(b"\0".join(value.encode("utf-8") for value in RENDERER_ADAPTATION_CONTRACT))
        == RENDERER_ADAPTATION_CONTRACT_SHA256,
        "renderer adaptation contract differs",
    )
    require(
        digest(RENDERER_ADAPTATION_SCRIPT.encode("utf-8"))
        == RENDERER_ADAPTATION_SCRIPT_SHA256,
        "renderer adaptation program differs",
    )
    adaptation = shlex.join((
        "/usr/bin/python3", "-c", RENDERER_ADAPTATION_SCRIPT,
        *RENDERER_ADAPTATION_CONTRACT,
    ))
    setup = "tar --no-same-owner -xf /workspace-input.tar -C /workspace; umask 077; mkdir -m 0700 /workspace/.gitdir /workspace/.gitdir/objects /workspace/.gitdir/objects/info /workspace/.gitdir/refs /workspace/.gitdir/refs/heads /tmp/home; mkdir -m 0700 -p /tmp/home/.bun/install/cache; printf 'gitdir: /workspace/.gitdir\\n' > /workspace/.git; printf '[core]\\n\\trepositoryformatversion = 0\\n\\tbare = false\\n\\tworktree = /workspace\\n' > /workspace/.gitdir/config; printf '%s\\n' '" + archive.head + "' > /workspace/.gitdir/HEAD; printf '/source/.git/objects\\n/authority-objects\\n' > /workspace/.gitdir/objects/info/alternates; " + adaptation + "; for cache_source in /usr/local/install/cache/* /usr/local/install/cache/.[!.]* /usr/local/install/cache/..?*; do { [ -e \"$cache_source\" ] || [ -L \"$cache_source\" ]; } || continue; cp -a --no-preserve=ownership -- \"$cache_source\" /tmp/home/.bun/install/cache/; done; mkdir -m 0700 /workspace/apps/web/node_modules; for source in /opt/hermternal/node_modules/* /opt/hermternal/node_modules/.[!.]* /opt/hermternal/node_modules/..?*; do { [ -e \"$source\" ] || [ -L \"$source\" ]; } || continue; cp -a --no-preserve=ownership -- \"$source\" /workspace/apps/web/node_modules/; done; cd /workspace/apps/web; bun x --no-install svelte-kit sync; exec \"$@\""
    container_environment = {**SAFE_ENV, "HOME": "/tmp/home", "BUN_INSTALL_CACHE_DIR": "/tmp/home/.bun/install/cache", "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"}
    return ("/usr/bin/podman", "run", "--init", "--rm", "--pull=never", "--network=none", "--userns=keep-id", "--user", f"{uid}:{gid}", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--security-opt=label=disable", "--mount", f"type=bind,src={repository},dst=/source,ro=true", "--mount", f"type=bind,src={historical.object_dir},dst=/authority-objects,ro=true", "--mount", f"type=bind,src={archive.snapshot.path},dst=/workspace-input.tar,ro=true", "--mount", "type=tmpfs,destination=/workspace,tmpfs-size=4026531840,tmpfs-mode=0700,U=true,notmpcopyup", "--mount", "type=tmpfs,destination=/tmp,tmpfs-size=805306368,tmpfs-mode=0700,U=true,notmpcopyup", "--workdir", "/workspace", *sum((("--env", f"{key}={value}") for key, value in sorted(container_environment.items())), ()), "--entrypoint", "/bin/sh", pins.image, "-eu", "-c", setup, "--", *gate.command)


def attest_image(pins: Pins, run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run) -> None:
    """Inspect a local image only. Exact labels prevent a tag from being trust."""
    environment = rootless_podman_environment()
    home = Path(environment["HOME"])
    runtime = Path(environment["XDG_RUNTIME_DIR"])
    try:
        rootless = run(("/usr/bin/podman", "info", "--format", PODMAN_INFO_FORMAT), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd="/", timeout=30, check=False)
        result = run(("/usr/bin/podman", "image", "inspect", pins.image), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd="/", timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Reject("pre-staged Podman image is unavailable") from error
    try:
        store_lines = bytes(rootless.stdout or b"").decode("utf-8", "strict").strip().splitlines()
    except UnicodeDecodeError as error:
        raise Reject("Podman rootless storage boundary differs") from error
    expected_graph = home / ".local/share/containers/storage"
    expected_run = runtime / "containers"
    require(rootless.returncode == 0 and len(store_lines) == 3 and store_lines[0] == "true",
            "Podman rootless storage boundary differs")
    require(all(os.path.isabs(item) for item in store_lines[1:]), "Podman rootless storage boundary differs")
    # Podman can retain a former home-directory symlink spelling in its store
    # metadata. Resolve it, then require the exact current account-owned store.
    require(os.path.realpath(store_lines[1]) == os.fspath(expected_graph)
            and os.path.realpath(store_lines[2]) == os.fspath(expected_run),
            "Podman rootless storage boundary differs")
    require(result.returncode == 0 and len(result.stdout or b"") <= MAX_OUTPUT, "pre-staged Podman image is unavailable")
    value = strict_json(bytes(result.stdout).strip().removeprefix(b"[").removesuffix(b"]"), "Podman image inspection")
    configuration = value.get("Config")
    require(isinstance(configuration, dict)
            and configuration.get("User") == f"{os.getuid()}:{os.getgid()}",
            "pre-staged image user differs")
    digests = value.get("RepoDigests"); labels = value.get("Labels") or configuration.get("Labels")
    require(isinstance(digests, list) and any(isinstance(item, str) and item.endswith(pins.image_digest) for item in digests), "pre-staged image digest differs")
    require(isinstance(labels, dict) and labels.get("org.hermternal.bun") == "1.3.14" and labels.get("org.hermternal.node") == "26.7.0" and labels.get("org.hermternal.playwright") == "1.62.1" and labels.get("org.hermternal.dependencies-sha256") == pins.dependencies_sha256, "pre-staged image toolchain attestation differs")


SEMANTIC_PATHS = {
    "auth": "apps/web/tests/e2e/ui-preview.spec.ts",
    "privacy": "apps/web/src/lib/live-artifact-policy.test.ts",
    "screenshots": "apps/web/src/lib/live-screenshot-contract.test.ts",
}


def local_git_argv(repository: Path, *args: str) -> tuple[str, ...]:
    """Return the only permitted host-Git command boundary."""
    return ("/usr/bin/git", "-C", os.fspath(repository), "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", *args)


def _run_local_git(repository: Path, *args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    """Capture one bounded local Git result without losing stderr or status."""
    command = local_git_argv(repository, *args)
    try:
        result = subprocess.run(command, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(LOCAL_GIT_ENV), cwd="/", timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Reject("semantic Git binding is unavailable") from error
    stdout, stderr = bytes(result.stdout or b""), bytes(result.stderr or b"")
    require(len(stdout) <= MAX_OUTPUT and len(stderr) <= MAX_OUTPUT, "semantic Git binding differs")
    return subprocess.CompletedProcess(command, result.returncode, stdout, stderr)


def _local_git(repository: Path, *args: str, stdin: bytes = b"") -> bytes:
    """Read only local Git objects with every config and fetch path disabled."""
    result = _run_local_git(repository, *args, stdin=stdin)
    require(result.returncode == 0, "semantic Git binding differs")
    return bytes(result.stdout or b"")


def _directory_binding(path: Path, label: str) -> tuple[int, int, int, int]:
    metadata = os.lstat(path)
    binding = (metadata.st_dev, metadata.st_ino, metadata.st_uid, stat.S_IMODE(metadata.st_mode))
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path differs")
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid(), f"{label} metadata differs")
    return binding


def _git_requirements_bytes() -> bytes:
    rows = [[item.commit, item.path, item.blob, item.purpose, item.guarded_only] for item in GIT_REQUIREMENTS]
    return json.dumps(rows, separators=(",", ":")).encode()


def _historical_git(repository: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            local_git_argv(repository, *args), input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(LOCAL_GIT_ENV), cwd="/", timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Reject("historical Git dependency check is unavailable") from error
    require(len(result.stdout or b"") <= MAX_OUTPUT and len(result.stderr or b"") <= MAX_OUTPUT,
            "historical Git dependency output differs")
    return result


def historical_objects(chain: Chain) -> HistoricalObjects:
    """Authenticate the Phase-v11 source and the exact web-test Git objects.

    The retained replay intentionally lacks two rejected-history commits that
    focused regression tests read by OID. The durable Phase-v11 record already
    binds the guarded worktree and common object directory. This check exposes
    that directory read-only; it never imports objects or refs into the replay.
    """
    require(digest(_git_requirements_bytes()) == GIT_REQUIREMENTS_SHA256,
            "historical Git dependency list differs")
    declaration_bytes = json.dumps([list(item) for item in GIT_DECLARATIONS], separators=(",", ":")).encode()
    require(digest(declaration_bytes) == GIT_DECLARATIONS_SHA256,
            "historical Git declaration list differs")
    anchor = strict_json(chain.phase_anchor.raw, "Phase A anchor")
    phase_anchor_path = Path(chain.phase_anchor.path)
    phase_path = phase_anchor_path.with_name("phase-a.json")
    require(phase_anchor_path.name == "anchor.json" and phase_path.parent.name == "evidence",
            "Phase A evidence placement differs")
    phase = stable_read(phase_path, "Phase A execution evidence", mode=0o600)
    require(anchor.get("prior_sha256") == phase.sha256, "Phase A execution evidence SHA-256 differs")
    phase_value = strict_json(phase.raw, "Phase A execution evidence")
    guarded = phase_value.get("observations", {}).get("guarded_worktree")
    require(isinstance(guarded, dict), "Phase A guarded-worktree evidence differs")
    repository = Path(guarded.get("path", ""))
    object_record = guarded.get("git_object_dir")
    require(isinstance(object_record, dict), "Phase A guarded object-directory evidence differs")
    object_dir = Path(object_record.get("path", ""))
    repository_binding = _directory_binding(repository, "Phase A guarded repository")
    object_dir_binding = _directory_binding(object_dir, "Phase A guarded object directory")
    expected_repository = guarded.get("binding")
    expected_objects = object_record.get("binding")
    require(isinstance(expected_repository, dict) and repository_binding == (
        expected_repository.get("st_dev"), expected_repository.get("st_ino"),
        expected_repository.get("st_uid"), expected_repository.get("st_mode"),
    ), "Phase A guarded repository binding differs")
    require(isinstance(expected_objects, dict) and object_dir_binding == (
        expected_objects.get("st_dev"), expected_objects.get("st_ino"),
        expected_objects.get("st_uid"), expected_objects.get("st_mode"),
    ), "Phase A guarded object-directory binding differs")
    require(guarded.get("detached") is True and guarded.get("head") == GUARDED_SOURCE_HEAD
            and guarded.get("tree") == GUARDED_SOURCE_TREE,
            "Phase A guarded source revision differs")
    for arguments, expected in (("HEAD^{commit}", GUARDED_SOURCE_HEAD), ("HEAD^{tree}", GUARDED_SOURCE_TREE)):
        observed = _historical_git(repository, "rev-parse", arguments)
        require(observed.returncode == 0 and observed.stderr == b""
                and observed.stdout.decode("ascii", "strict").strip() == expected,
                "Phase A guarded source revision changed")

    declarations: dict[str, list[str]] = {}
    for path, commit in GIT_DECLARATIONS:
        declarations.setdefault(path, []).append(commit)
    for path, commits in declarations.items():
        source = _historical_git(chain.repository, "show", f"{chain.final_tree}:{path}")
        require(source.returncode == 0 and source.stderr == b"",
                f"historical Git declaration source is unavailable: {path}")
        for commit in commits:
            require(source.stdout.count(commit.encode("ascii")) == 1,
                    f"historical Git declaration differs: {path}")

    missing: set[str] = set()
    checked_commits: set[str] = set()
    for requirement in GIT_REQUIREMENTS:
        source_type = _historical_git(repository, "cat-file", "-t", requirement.commit)
        require(source_type.returncode == 0 and source_type.stderr == b"" and source_type.stdout == b"commit\n",
                f"historical Git commit is unavailable for {requirement.purpose}")
        source_blob = _historical_git(repository, "rev-parse", f"{requirement.commit}:{requirement.path}")
        require(source_blob.returncode == 0 and source_blob.stderr == b""
                and source_blob.stdout.decode("ascii", "strict").strip() == requirement.blob,
                f"historical Git path differs for {requirement.purpose}")
        if requirement.commit in checked_commits:
            continue
        checked_commits.add(requirement.commit)
        retained = _historical_git(chain.repository, "cat-file", "-t", requirement.commit)
        if retained.returncode != 0:
            require(retained.returncode == 128 and retained.stdout == b""
                    and retained.stderr == b"fatal: git cat-file: could not get object info\n",
                    f"retained historical Git lookup failed for {requirement.purpose}")
            missing.add(requirement.commit)
        else:
            require(retained.stderr == b"" and retained.stdout == b"commit\n",
                    f"retained historical Git type differs for {requirement.purpose}")
    expected_missing = {item.commit for item in GIT_REQUIREMENTS if item.guarded_only}
    require(missing == expected_missing, "retained historical Git dependency set differs")
    anchor_parent = _historical_git(chain.repository, "show", "-s", "--format=%P", BENCHMARK_ANCHOR_COMMIT)
    final_evidence = _historical_git(chain.repository, "rev-parse", f"{chain.final_tree}:{BENCHMARK_EVIDENCE_PATH}")
    require(anchor_parent.returncode == 0 and anchor_parent.stderr == b""
            and anchor_parent.stdout.decode("ascii", "strict").strip() == BENCHMARK_SOURCE_COMMIT
            and final_evidence.returncode == 0 and final_evidence.stderr == b""
            and final_evidence.stdout.decode("ascii", "strict").strip() == BENCHMARK_EVIDENCE_BLOB,
            "renderer benchmark evidence ancestry differs")
    return HistoricalObjects(repository, repository_binding, object_dir, object_dir_binding,
                             GUARDED_SOURCE_HEAD, GUARDED_SOURCE_TREE)


def verify_historical_objects(source: HistoricalObjects) -> None:
    """Reject replacement of either Phase-bound source directory."""
    require(_directory_binding(source.repository, "Phase A guarded repository") == source.repository_identity,
            "Phase A guarded repository changed")
    require(_directory_binding(source.object_dir, "Phase A guarded object directory") == source.object_dir_identity,
            "Phase A guarded object directory changed")


def _workspace_members(chain: Chain) -> tuple[str, ...]:
    """Resolve the closed workspace allowlist from the authenticated final tree."""
    require(digest(json.dumps(list(WORKSPACE_TRACKED_INPUTS), separators=(",", ":")).encode())
            == WORKSPACE_TRACKED_INPUTS_SHA256,
            "workspace tracked-input allowlist differs")
    result = _run_local_git(
        chain.repository, "ls-tree", "-r", "--name-only", "-z",
        chain.final_tree, "--", *WORKSPACE_TRACKED_INPUTS,
    )
    require(result.returncode == 0 and not result.stderr and result.stdout.endswith(b"\0"),
            "workspace tree inventory differs")
    try:
        members = tuple(item.decode("utf-8", "strict") for item in result.stdout[:-1].split(b"\0"))
    except UnicodeDecodeError as error:
        raise Reject("workspace tree inventory is not UTF-8") from error
    require(members == tuple(sorted(set(members))) and all(
        item and not item.startswith("/") and "\x00" not in item
        and all(part not in ("", ".", "..") for part in item.split("/"))
        for item in members
    ), "workspace tree inventory differs")
    require(all(any(item == wanted or item.startswith(wanted + "/") for item in members)
                for wanted in WORKSPACE_TRACKED_INPUTS),
            "workspace tracked input is missing")
    return members


def verify_workspace_archive(archive: WorkspaceArchive) -> None:
    """Require the same private archive inode, bytes, root, tree, and members."""
    root = os.lstat(archive.root)
    require((root.st_dev, root.st_ino, root.st_uid, stat.S_IMODE(root.st_mode)) == archive.root_identity,
            "workspace archive root changed")
    require(stable_read(archive.snapshot.path, "workspace archive", mode=0o600) == archive.snapshot,
            "workspace archive changed")
    require(OID_RE.fullmatch(archive.head) is not None and OID_RE.fullmatch(archive.tree) is not None
            and archive.members,
            "workspace archive binding differs")


@contextlib.contextmanager
def workspace_archive(chain: Chain) -> Iterator[WorkspaceArchive]:
    """Create one private final-tree archive and remove only its exact inode."""
    root = Path(f"/tmp/hermternal-task409-offline-workspace.{os.getpid()}")
    archive_path = root / "workspace.tar"
    try:
        os.mkdir(root, 0o700)
    except FileExistsError as error:
        raise Reject("workspace archive root already exists") from error
    root_metadata = os.lstat(root)
    require(stat.S_ISDIR(root_metadata.st_mode) and root_metadata.st_uid == os.getuid()
            and stat.S_IMODE(root_metadata.st_mode) == 0o700 and root_metadata.st_nlink == 2,
            "workspace archive root metadata differs")
    root_identity = (root_metadata.st_dev, root_metadata.st_ino, root_metadata.st_uid, stat.S_IMODE(root_metadata.st_mode))
    descriptor = -1
    owned_identity: tuple[int, int, int, int, int, int, int, int] | None = None
    try:
        members = _workspace_members(chain)
        descriptor = os.open(
            archive_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        command = local_git_argv(
            chain.repository, "archive", "--format=tar", chain.final_tree,
            "--", *WORKSPACE_TRACKED_INPUTS,
        )
        try:
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=descriptor, stderr=subprocess.PIPE,
                env=dict(LOCAL_GIT_ENV), cwd="/", timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Reject("workspace archive creation is unavailable") from error
        os.fsync(descriptor)
        owned_identity = _identity(os.fstat(descriptor))
        os.close(descriptor); descriptor = -1
        require(result.returncode == 0 and len(result.stderr or b"") <= MAX_OUTPUT,
                "workspace archive creation failed")
        snapshot = stable_read(archive_path, "workspace archive", mode=0o600)
        with tarfile.open(fileobj=io.BytesIO(snapshot.raw), mode="r:") as handle:
            entries = handle.getmembers()
        require(all(item.isdir() or item.isfile() for item in entries),
                "workspace archive contains a non-file entry")
        archived_files = tuple(item.name.rstrip("/") for item in entries if item.isfile())
        require(archived_files == members, "workspace archive members differ")
        archive = WorkspaceArchive(root, root_identity, chain.final_head, chain.final_tree, members, snapshot)
        verify_workspace_archive(archive)
        yield archive
        verify_workspace_archive(archive)
    finally:
        if descriptor >= 0:
            owned_identity = _identity(os.fstat(descriptor))
            os.close(descriptor)
        if archive_path.exists():
            current = os.lstat(archive_path)
            expected_identity = snapshot.identity if 'snapshot' in locals() else owned_identity
            if expected_identity is None or _identity(current) != expected_identity:
                raise Reject("workspace archive residue identity differs")
            os.unlink(archive_path)
            root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(root_descriptor)
            finally:
                os.close(root_descriptor)
        if root.exists():
            final_root = os.lstat(root)
            require((final_root.st_dev, final_root.st_ino, final_root.st_uid, stat.S_IMODE(final_root.st_mode)) == root_identity,
                    "workspace archive root changed")
            os.rmdir(root)


def semantic_evidence(chain: Chain) -> dict[str, Any]:
    """Bind private immutable source files to the approved final Git tree.

    The replay protects physical source files at mode 0600. Git independently
    tracks the reviewed application blobs at mode 100644. Both bindings must
    hold: the private checkout prevents another local account from changing the
    evidence, while the tree mode proves the intended source-file semantics.
    """
    repository = chain.repository.resolve()
    require(repository == chain.repository and repository.is_absolute() and os.path.realpath(repository) == os.fspath(repository), "semantic repository path differs")
    paths = {name: repository / relative for name, relative in SEMANTIC_PATHS.items()}
    for name, path in paths.items():
        metadata = os.lstat(path)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1, f"semantic {name} metadata differs")
    sources = {name: stable_read(path.resolve(), f"semantic {name}", 2 * 1024 * 1024, 0o600) for name, path in paths.items()}
    bindings: dict[str, dict[str, str]] = {}
    for name, source in sources.items():
        relative = SEMANTIC_PATHS[name]
        require(source.path == paths[name] and source.path.is_relative_to(repository) and source.identity[2] == os.getuid(), f"semantic {name} ownership or path differs")
        listing = _local_git(repository, "ls-tree", "--full-tree", chain.final_tree, "--", relative)
        match = re.fullmatch(rb"100644 blob ([0-9a-f]{40})\t" + re.escape(relative.encode("utf-8")) + rb"\n", listing)
        require(match is not None, f"semantic {name} final Git mode or blob differs")
        blob = match.group(1).decode("ascii")
        calculated = _local_git(repository, "hash-object", "--no-filters", "--stdin", stdin=source.raw).decode("ascii", "strict").strip()
        require(calculated == blob, f"semantic {name} working bytes differ from final Git blob")
        bindings[name] = {"git_mode": "100644", "git_blob": blob}
    auth, privacy, screenshots = (sources["auth"].raw.decode("utf-8"), sources["privacy"].raw.decode("utf-8"), sources["screenshots"].raw.decode("utf-8"))
    direct_enter = re.search(
        r"if \(activation === 'click'\) await signIn\.click\(\);\s*"
        r"else \{\s*await signIn\.focus\(\);\s*await signIn\.press\('Enter'\);\s*\}",
        auth,
    ) is not None
    checks = {"click": "activation === 'click'" in auth and ".click()" in auth, "enter": direct_enter, "clearing": auth.count("toHaveValue('')") >= 4 and "outerHTML" in auth, "redaction": "page.screenshot()" in auth and "not.toContain(passwordValue)" in auth and "not.toContain(usernameValue)" in auth, "accessibility": "AxeBuilder" in auth and "axe violations" in auth, "privacy_policy": "LIVE_ARTIFACT_REDACTION" in privacy and "screenshot: 'off'" in privacy, "screenshot_contract": "blockedLiveScreenshotManifest" in screenshots}
    require(all(checks.values()), "semantic privacy, accessibility, or authentication evidence is incomplete")
    return {"checks": checks, "sources": {name: {"path": os.fspath(item.path), "sha256": item.sha256, "identity": list(item.identity), **bindings[name]} for name, item in sources.items()}}


Run = Callable[..., subprocess.CompletedProcess[bytes]]
LocalGit = Callable[..., subprocess.CompletedProcess[bytes]]


def run_gates(chain: Chain, pins: Pins, run: Run = subprocess.run,
              attest: Callable[[Pins], None] = attest_image, *,
              local_git: LocalGit = _run_local_git,
              historical: Callable[[Chain], HistoricalObjects] = historical_objects) -> list[dict[str, Any]]:
    """Run six hermetic host-Git observations, then seven isolated web gates."""
    require(digest(json.dumps([[g.gate_id, g.workdir, list(g.command)] for g in GATES], separators=(",", ":")).encode()) == GATE_LIST_SHA256, "immutable gate list differs")
    require(tuple(gate.gate_id for gate in GATES[:6]) == LOCAL_GIT_GATE_IDS
            and tuple(gate.gate_id for gate in GATES[6:]) == PODMAN_GATE_IDS,
            "gate backend partition differs")
    require(all(gate.workdir == "/workspace" and gate.command[0] == "git" for gate in GATES[:6])
            and all(gate.workdir == "/workspace/apps/web" and gate.command[0] == "bun" for gate in GATES[6:]),
            "gate backend command differs")
    require(_identity(os.lstat(chain.repository)) == chain.repository_identity, "retained repository changed before gates")
    source = historical(chain)
    verify_historical_objects(source)
    attest(pins)
    records: list[dict[str, Any]] = []
    expected = {"git-head": chain.final_head, "git-tree": chain.final_tree, "git-main": chain.protected_main, "git-dev-base": chain.expected_dev_base, "git-clean": ""}
    for gate in GATES[:6]:
        argv = local_git_argv(chain.repository, *gate.command[1:])
        try:
            result = local_git(chain.repository, *gate.command[1:])
        except Reject as error:
            raise Reject(f"{gate.gate_id} failed") from error
        require(tuple(result.args) == argv, f"{gate.gate_id} argv differs")
        stdout, stderr, returncode = bytes(result.stdout or b""), bytes(result.stderr or b""), result.returncode
        require(len(stdout) <= MAX_OUTPUT and len(stderr) <= MAX_OUTPUT and returncode == 0, f"{gate.gate_id} failed")
        if gate.gate_id in expected:
            require(stdout.decode("utf-8", "strict").strip() == expected[gate.gate_id], f"{gate.gate_id} output differs")
        records.append({"id": gate.gate_id, "argv": list(argv), "exit_code": returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)})

    podman_environment = rootless_podman_environment()
    with workspace_archive(chain) as archive:
        for gate in GATES[6:]:
            verify_workspace_archive(archive)
            verify_historical_objects(source)
            argv = podman_argv(chain.repository, archive, source, gate, pins)
            try:
                result = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=podman_environment, cwd="/", timeout=900, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise Reject(f"{gate.gate_id} was unavailable") from error
            stdout, stderr, returncode = bytes(result.stdout or b""), bytes(result.stderr or b""), result.returncode
            require(len(stdout) <= MAX_OUTPUT and len(stderr) <= MAX_OUTPUT and returncode == 0, f"{gate.gate_id} failed")
            records.append({"id": gate.gate_id, "argv": list(argv), "exit_code": returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)})
    verify_historical_objects(source)
    return records


def write_report(path: Path, chain: Chain, gates: list[dict[str, Any]], semantic: dict[str, Any]) -> Snapshot:
    value = {"schema": REPORT_SCHEMA, "status": "passed", "network": "not-used", "credentials": "not-used", "gate_list_sha256": GATE_LIST_SHA256, "repository": os.fspath(chain.repository), "repository_identity": list(chain.repository_identity), "final_head": chain.final_head, "final_tree": chain.final_tree, "protected_main": chain.protected_main, "expected_dev_base": chain.expected_dev_base, "dev_target": chain.final_head, "inputs": {"result": {"path": os.fspath(chain.result.path), "sha256": chain.result.sha256}, "completion": {"path": os.fspath(chain.completion.path), "sha256": chain.completion.sha256}, "phase_a_anchor": {"path": os.fspath(chain.phase_anchor.path), "sha256": chain.phase_anchor.sha256}, "provenance": {"path": os.fspath(chain.provenance.path), "sha256": chain.provenance.sha256}}, "semantic_evidence": semantic, "gates": gates}
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(); path = Path(path).resolve()
    parent = os.lstat(path.parent); require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, "report parent is not private")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, raw); os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(directory); os.close(directory)
    report = stable_read(path, "offline report", mode=0o600); require(report.raw == raw, "offline report changed after create")
    return report


def main(argv: Sequence[str] | None = None, *, run: Run = subprocess.run,
         attest: Callable[[Pins], None] = attest_image, local_git: LocalGit = _run_local_git,
         historical: Callable[[Chain], HistoricalObjects] = historical_objects) -> int:
    """Run the real CLI with only its two process boundaries injectable."""
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--result", type=Path, required=True); parser.add_argument("--completion", type=Path, required=True); parser.add_argument("--report", type=Path, required=True); args = parser.parse_args(argv)
    pins = load_pins(); chain = _load_chain(args.result, args.completion, pins); before_semantic = semantic_evidence(chain); gates = run_gates(chain, pins, run, attest, local_git=local_git, historical=historical); final_chain = _load_chain(args.result, args.completion, pins); final_semantic = semantic_evidence(final_chain)
    require(chain == final_chain and before_semantic == final_semantic, "replay repository or semantic evidence changed during offline gates")
    write_report(args.report, final_chain, gates, final_semantic)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Reject as error:
        print(f"OFFLINE_GATES_REJECT: {error}", file=sys.stderr); raise SystemExit(2)
