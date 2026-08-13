#!/usr/bin/env python3
"""Create a Linux-bound, evidence-only offline-gate report after replay.

The committed pins are deliberately incomplete until the reviewed Linux
authority and #405 successor exist.  This program rejects that state instead
of falling back to the retired macOS authority.  It never pulls, installs, or
contacts a service: a reviewed local Podman image must already contain the
exact Bun, browser, and locked dependency set.
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
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

PINS_PATH = Path(__file__).resolve().with_name("final-linux-pins.json")
REPORT_SCHEMA = "hermternal.issue-397.offline-gates/v3"
PINS_SCHEMA = "hermternal.issue-397.offline-gates/v3-final-linux-pins"
MAX_OUTPUT = 2 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SAFE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "CI": "1", "NO_COLOR": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1", "PLAYWRIGHT_BROWSERS_PATH": "/opt/hermternal/playwright-browsers", "BUN_INSTALL_CACHE_DIR": "/tmp/bun-cache"}
LOCAL_GIT_ENV = {**SAFE_ENV, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"}


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
    expected_dev_base: str
    image: str
    image_digest: str
    dependencies_sha256: str


def _pin_path(value: Any, label: str, pins_path: Path, base: Path) -> Path:
    require(isinstance(value, str) and value and not os.path.isabs(value), f"{label} path differs")
    path = (pins_path.parent / value).resolve()
    require(path.is_relative_to(base), f"{label} escapes handover")
    return path


def load_pins(path: Path | None = None) -> Pins:
    """Load the one finalization file; deferred values are an execution stop."""
    pins_path = Path(path or PINS_PATH).resolve()
    base = pins_path.parents[1]
    raw = stable_read(pins_path, "final Linux pins", 64 * 1024, 0o644)
    value = strict_json(raw.raw, "final Linux pins")
    required = {"schema", "status", "platform_profile", "linux_authority", "replay", "expected_dev_base", "toolchain"}
    require(set(value) == required and value.get("schema") == PINS_SCHEMA, "final Linux pins schema differs")
    require(value.get("status") == "final", "final Linux pins are not finalized")
    profile, authority, replay, toolchain = value["platform_profile"], value["linux_authority"], value["replay"], value["toolchain"]
    require(isinstance(profile, dict) and set(profile) == {"path", "sha256"}, "platform profile pins differ")
    require(isinstance(authority, dict) and set(authority) == {"root", "module_path", "module_sha256"}, "Linux authority pins differ")
    require(isinstance(replay, dict) and set(replay) == {"wrapper_path", "wrapper_sha256", "phase_a_path", "phase_a_sha256"}, "Linux replay pins differ")
    require(isinstance(toolchain, dict) and set(toolchain) == {"image", "repo_digest", "bun", "node", "playwright", "dependencies_sha256"}, "toolchain pins differ")
    strings = [(profile["sha256"], "profile SHA-256"), (authority["module_sha256"], "authority SHA-256"), (replay["wrapper_sha256"], "wrapper SHA-256"), (replay["phase_a_sha256"], "Phase A SHA-256"), (toolchain["repo_digest"], "image digest"), (toolchain["dependencies_sha256"], "dependency SHA-256")]
    require(all(isinstance(item, str) and SHA_RE.fullmatch(item) for item, _ in strings), "final Linux pin digest differs")
    require(isinstance(value["expected_dev_base"], str) and OID_RE.fullmatch(value["expected_dev_base"]), "expected dev base differs")
    require(isinstance(toolchain["image"], str) and "@sha256:" in toolchain["image"] and toolchain["image"].endswith(toolchain["repo_digest"]), "toolchain image differs")
    require(toolchain["bun"] == "1.3.14" and toolchain["node"] == "26.7.0" and toolchain["playwright"] == "1.62.1", "toolchain version pins differ")
    root = _pin_path(authority["root"], "Linux authority root", pins_path, base)
    return Pins(_pin_path(profile["path"], "platform profile", pins_path, base), profile["sha256"], root, _pin_path(authority["module_path"], "Linux authority", pins_path, base), authority["module_sha256"], _pin_path(replay["wrapper_path"], "Linux wrapper", pins_path, base), replay["wrapper_sha256"], _pin_path(replay["phase_a_path"], "Linux Phase A", pins_path, base), replay["phase_a_sha256"], value["expected_dev_base"], toolchain["image"], toolchain["repo_digest"], toolchain["dependencies_sha256"])


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


def _require_oid(value: Any, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value), f"{label} differs")
    return value


def _load_chain(result_path: Path, completion_path: Path, pins: Pins | None = None) -> Chain:
    """Validate only the final Linux #403 → #404 → #405 contract."""
    pins = pins or load_pins()
    profile = verified_module(pins.profile_path, pins.profile_sha256, "issue397_offline_platform_profile")
    loaded_profile = profile.load()
    require(Path(loaded_profile.authority_root) == pins.authority_root, "profile authority root differs")
    authority = verified_module(pins.authority_module, pins.authority_sha256, "issue397_offline_authority")
    wrapper = verified_module(pins.wrapper_module, pins.wrapper_sha256, "issue397_offline_wrapper")
    phase = verified_module(pins.phase_a_module, pins.phase_a_sha256, "issue397_offline_phase_a")
    require(phase.EVIDENCE_SCHEMA.endswith(".v2") or phase.EVIDENCE_SCHEMA.endswith(".v3"), "Linux Phase A schema differs")
    descriptor = stable_read(pins.authority_root / "authority-descriptor.json", "Linux authority descriptor", mode=0o600)
    provenance = stable_read(pins.authority_root / "provenance-manifest.json", "Linux provenance", mode=0o600)
    validated = authority.validate(descriptor.path, pins.authority_root, descriptor.sha256)
    replay_authority = wrapper.load_authority()
    result = stable_read(Path(result_path).resolve(), "#405 result", mode=0o600)
    completion = stable_read(Path(completion_path).resolve(), "#405 completion", mode=0o600)
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
    require(result_value.get("phase_a_manifest_sha256") == evidence.manifest_sha256 and result_value.get("phase_a_approval_digest") == evidence.approval_digest, "Linux/#405 Phase A binding differs")
    return Chain(repository, _identity(repo_meta), final_head, final_tree, result_value["protected_main_commit"], pins.expected_dev_base, result, completion, evidence.snapshot, provenance)


@dataclass(frozen=True)
class Gate:
    gate_id: str
    workdir: str
    command: tuple[str, ...]


GATES = (Gate("git-head", "/workspace", ("git", "rev-parse", "HEAD^{commit}")), Gate("git-tree", "/workspace", ("git", "rev-parse", "HEAD^{tree}")), Gate("git-main", "/workspace", ("git", "rev-parse", "refs/remotes/origin/main^{commit}")), Gate("git-dev-base", "/workspace", ("git", "rev-parse", "refs/remotes/origin/dev^{commit}")), Gate("git-clean", "/workspace", ("git", "status", "--porcelain=v1", "--untracked-files=all")), Gate("git-fsck", "/workspace", ("git", "fsck", "--full", "--strict")), Gate("web-typecheck", "/workspace/apps/web", ("bun", "x", "--no-install", "svelte-check", "--tsconfig", "./tsconfig.json")), Gate("web-unit", "/workspace/apps/web", ("bun", "x", "--no-install", "vitest", "run")), Gate("web-build", "/workspace/apps/web", ("bun", "x", "--no-install", "vite", "build")), Gate("privacy-redaction", "/workspace/apps/web", ("bun", "x", "--no-install", "vitest", "run", "src/lib/live-artifact-policy.test.ts", "src/lib/live-screenshot-contract.test.ts")), Gate("accessibility", "/workspace/apps/web", ("bun", "run", "--no-install", "test:a11y")), Gate("no-network-browser", "/workspace/apps/web", ("bun", "run", "--no-install", "test:no-network")), Gate("auth-click-enter", "/workspace/apps/web", ("bun", "x", "--no-install", "playwright", "test", "tests/e2e/ui-preview.spec.ts", "--grep", "native password activation clears live values")))
GATE_LIST_SHA256 = digest(json.dumps([[g.gate_id, g.workdir, list(g.command)] for g in GATES], separators=(",", ":")).encode())
WRITABLE_WEB_PATHS = ("/workspace/apps/web/node_modules", "/workspace/apps/web/.svelte-kit", "/workspace/apps/web/build", "/workspace/apps/web/test-results", "/workspace/apps/web/playwright-report")


def podman_argv(repository: Path, gate: Gate, pins: Pins) -> tuple[str, ...]:
    """Run a fixed gate with source read-only and all tool output in tmpfs.

    The reviewed image carries immutable dependencies at /opt/hermternal. The
    entry script copies them into the dedicated tmpfs before Bun runs; it never
    installs or downloads packages.
    """
    uid, gid = os.getuid(), os.getgid()
    setup = "mkdir -p /workspace/apps/web/node_modules; cp -a /opt/hermternal/node_modules/. /workspace/apps/web/node_modules/; exec \"$@\""
    tmpfs = sum((("--tmpfs", f"{item}:rw,nosuid,nodev,size=768m") for item in ("/tmp", *WRITABLE_WEB_PATHS)), ())
    return ("/usr/bin/podman", "run", "--rm", "--pull=never", "--network=none", "--userns=keep-id", "--user", f"{uid}:{gid}", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--mount", f"type=bind,src={repository},dst=/workspace,ro=true,relabel=private", *tmpfs, "--workdir", gate.workdir, *sum((("--env", f"{key}={value}") for key, value in sorted(SAFE_ENV.items())), ()), "--entrypoint", "/bin/sh", pins.image, "-eu", "-c", setup, "--", *gate.command)


def attest_image(pins: Pins, run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run) -> None:
    """Inspect a local image only. Exact labels prevent a tag from being trust."""
    try:
        rootless = run(("/usr/bin/podman", "info", "--format", "{{.Host.Security.Rootless}}"), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SAFE_ENV), cwd="/", timeout=30, check=False)
        result = run(("/usr/bin/podman", "image", "inspect", pins.image), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SAFE_ENV), cwd="/", timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Reject("pre-staged Podman image is unavailable") from error
    require(rootless.returncode == 0 and bytes(rootless.stdout or b"").strip() == b"true", "Podman is not rootless")
    require(result.returncode == 0 and len(result.stdout or b"") <= MAX_OUTPUT, "pre-staged Podman image is unavailable")
    value = strict_json(bytes(result.stdout).strip().removeprefix(b"[").removesuffix(b"]"), "Podman image inspection")
    digests = value.get("RepoDigests"); labels = value.get("Labels") or value.get("Config", {}).get("Labels")
    require(isinstance(digests, list) and any(isinstance(item, str) and item.endswith(pins.image_digest) for item in digests), "pre-staged image digest differs")
    require(isinstance(labels, dict) and labels.get("org.hermternal.bun") == "1.3.14" and labels.get("org.hermternal.node") == "26.7.0" and labels.get("org.hermternal.playwright") == "1.62.1" and labels.get("org.hermternal.dependencies-sha256") == pins.dependencies_sha256, "pre-staged image toolchain attestation differs")


SEMANTIC_PATHS = {
    "auth": "apps/web/tests/e2e/ui-preview.spec.ts",
    "privacy": "apps/web/src/lib/live-artifact-policy.test.ts",
    "screenshots": "apps/web/src/lib/live-screenshot-contract.test.ts",
}


def _local_git(repository: Path, *args: str, stdin: bytes = b"") -> bytes:
    """Read only local Git objects with every config and fetch path disabled."""
    command = ("/usr/bin/git", "-C", os.fspath(repository), "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", *args)
    try:
        result = subprocess.run(command, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(LOCAL_GIT_ENV), cwd="/", timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Reject("semantic Git binding is unavailable") from error
    stdout, stderr = bytes(result.stdout or b""), bytes(result.stderr or b"")
    require(result.returncode == 0 and len(stdout) <= MAX_OUTPUT and len(stderr) <= MAX_OUTPUT, "semantic Git binding differs")
    return stdout


def semantic_evidence(chain: Chain) -> dict[str, Any]:
    """Bind normal immutable source files to the approved final Git tree.

    Evidence records stay private at mode 0600. Source is different: Git tracks
    reviewed application files at mode 0644. We accept only that exact owner,
    regular-file, single-link mode, then bind its stable bytes to the final tree
    mode and blob. This rejects an unstaged replacement without making a normal
    retained checkout impossible to read.
    """
    repository = chain.repository.resolve()
    require(repository == chain.repository and repository.is_absolute() and os.path.realpath(repository) == os.fspath(repository), "semantic repository path differs")
    paths = {name: repository / relative for name, relative in SEMANTIC_PATHS.items()}
    for name, path in paths.items():
        metadata = os.lstat(path)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o644 and metadata.st_nlink == 1, f"semantic {name} metadata differs")
    sources = {name: stable_read(path.resolve(), f"semantic {name}", 2 * 1024 * 1024, 0o644) for name, path in paths.items()}
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
    checks = {"click": "activation === 'click'" in auth and ".click()" in auth, "enter": "activation === 'enter'" in auth and ".press('Enter')" in auth, "clearing": auth.count("toHaveValue('')") >= 4 and "outerHTML" in auth, "redaction": "page.screenshot()" in auth and "not.toContain(passwordValue)" in auth and "not.toContain(usernameValue)" in auth, "accessibility": "AxeBuilder" in auth and "axe violations" in auth, "privacy_policy": "LIVE_ARTIFACT_REDACTION" in privacy and "screenshot: 'off'" in privacy, "screenshot_contract": "blockedLiveScreenshotManifest" in screenshots}
    require(all(checks.values()), "semantic privacy, accessibility, or authentication evidence is incomplete")
    return {"checks": checks, "sources": {name: {"path": os.fspath(item.path), "sha256": item.sha256, "identity": list(item.identity), **bindings[name]} for name, item in sources.items()}}


Run = Callable[..., subprocess.CompletedProcess[bytes]]


def run_gates(chain: Chain, pins: Pins, run: Run = subprocess.run, attest: Callable[[Pins], None] = attest_image) -> list[dict[str, Any]]:
    require(digest(json.dumps([[g.gate_id, g.workdir, list(g.command)] for g in GATES], separators=(",", ":")).encode()) == GATE_LIST_SHA256, "immutable gate list differs")
    require(_identity(os.lstat(chain.repository)) == chain.repository_identity, "retained repository changed before gates")
    attest(pins)
    records: list[dict[str, Any]] = []
    expected = {"git-head": chain.final_head, "git-tree": chain.final_tree, "git-main": chain.protected_main, "git-dev-base": chain.expected_dev_base, "git-clean": ""}
    for gate in GATES:
        try:
            result = run(podman_argv(chain.repository, gate, pins), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SAFE_ENV), cwd="/", timeout=900, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Reject(f"{gate.gate_id} was unavailable") from error
        stdout, stderr = bytes(result.stdout or b""), bytes(result.stderr or b"")
        require(len(stdout) <= MAX_OUTPUT and len(stderr) <= MAX_OUTPUT and result.returncode == 0, f"{gate.gate_id} failed")
        if gate.gate_id in expected:
            require(stdout.decode("utf-8", "strict").strip() == expected[gate.gate_id], f"{gate.gate_id} output differs")
        records.append({"id": gate.gate_id, "argv": list(podman_argv(chain.repository, gate, pins)), "exit_code": result.returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)})
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


def main(argv: Sequence[str] | None = None, *, run: Run = subprocess.run, attest: Callable[[Pins], None] = attest_image) -> int:
    """Run the real CLI, with only its container boundary injectable for tests."""
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--result", type=Path, required=True); parser.add_argument("--completion", type=Path, required=True); parser.add_argument("--report", type=Path, required=True); args = parser.parse_args(argv)
    pins = load_pins(); chain = _load_chain(args.result, args.completion, pins); before_semantic = semantic_evidence(chain); gates = run_gates(chain, pins, run, attest); final_chain = _load_chain(args.result, args.completion, pins); final_semantic = semantic_evidence(final_chain)
    require(chain == final_chain and before_semantic == final_semantic, "replay repository or semantic evidence changed during offline gates")
    write_report(args.report, final_chain, gates, final_semantic)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Reject as error:
        print(f"OFFLINE_GATES_REJECT: {error}", file=sys.stderr); raise SystemExit(2)
