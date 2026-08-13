#!/usr/bin/env python3
"""Create an evidence-bound, closed offline-gate report after retained replay.

This tool is intentionally not a replay driver.  It can run only its fixed
offline gate list in a rootless Podman container.  It never pulls an image,
uses a network, mounts a credential location, or changes Git references.
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
from typing import Any, Callable, Mapping, Sequence

BASE = Path(__file__).resolve().parents[1]
FINAL_ROOT = Path("/home/kayg/Developer/hermternal/handover/issue-397/task464-candidate5-final")
AUTHORITY_PATH = BASE / "task464-candidate5-authority-successor" / "candidate5_authority.py"
WRAPPER_PATH = BASE / "task409-replay-result-successor" / "replay_result_successor.py"
PHASE_A_PATH = BASE / "task409-phase-a-anchor-successor" / "phase_a_anchor_runner.py"
PROVENANCE_PATH = FINAL_ROOT / "provenance-manifest.json"
DESCRIPTOR_PATH = FINAL_ROOT / "authority-descriptor.json"
AUTHORITY_SHA256 = "1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8"
WRAPPER_SHA256 = "a8a00bab2d221c5231ddc1f03eba1e0113ed252eecce43df1f8493df0160be60"
PHASE_A_SHA256 = "fb11d84062c05a2054a2f4162908de54ed15a530538fbf671ee54ff999baaf84"
DESCRIPTOR_SHA256 = "cf10f8286eca92d42130c17b9e086b8776dc385fa3a297c90725787415776f34"
PROVENANCE_SHA256 = "363d6f62335a5ff9f92eefabe87dd568032e71871390fa9fc5ae6fd72e3ac320"
REPORT_SCHEMA = "hermternal.issue-397.offline-gates/v2"
IMAGE = "docker.io/library/node@sha256:4f48f5d25f268954f3b9db98a0e12ad639a9ef94a995c933b85f0c4f51b1c6a5"
MAX_OUTPUT = 2 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\\Z")
OID_RE = re.compile(r"[0-9a-f]{40}\\Z")

# This is the complete inherited environment.  Its values are deliberately
# boring: mounts and container flags, not a host credential filter, enforce
# the credential boundary.
SAFE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "CI": "1", "NO_COLOR": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1"}


class Reject(Exception):
    """The input chain or one required offline check is not acceptable."""


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


def stable_read(path: Path, label: str, limit: int = 8 * 1024 * 1024) -> Snapshot:
    """Use three no-follow reads so a same-byte replacement also rejects."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path is not canonical")
    observations: list[Snapshot] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit, f"{label} metadata differs")
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(fd, min(131072, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk); size += len(chunk)
                require(size <= limit, f"{label} exceeds its byte limit")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} changed during read")
        raw = b"".join(chunks)
        observations.append(Snapshot(path, raw, digest(raw), _identity(before)))
    require(observations[0] == observations[1] == observations[2], f"{label} changed across reads")
    return observations[0]


def verified_module(path: Path, expected: str, name: str) -> types.ModuleType:
    source = stable_read(path.resolve(), name, 2 * 1024 * 1024)
    require(source.sha256 == expected, f"{name} SHA-256 differs")
    module = types.ModuleType(name); module.__file__ = os.fspath(path); module.__loader__ = None
    # Dataclass type resolution reads sys.modules while the verified bytes run.
    # Register this byte-only module, never a pathname import loader.
    sys.modules[name] = module
    exec(compile(source.raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


@dataclass(frozen=True)
class Chain:
    repository: Path
    final_head: str
    final_tree: str
    protected_main: str
    result: Snapshot
    completion: Snapshot
    phase_anchor: Snapshot
    provenance: Snapshot


def _require_oid(value: Any, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value), f"{label} differs")
    return value


def _load_chain(result_path: Path, completion_path: Path) -> Chain:
    """Validate the real #403 → #404 → #405 chain before a container exists."""
    authority = verified_module(AUTHORITY_PATH, AUTHORITY_SHA256, "issue397_offline_authority")
    wrapper = verified_module(WRAPPER_PATH, WRAPPER_SHA256, "issue397_offline_wrapper")
    phase = verified_module(PHASE_A_PATH, PHASE_A_SHA256, "issue397_offline_phase_a")
    require(phase.EVIDENCE_SCHEMA == "hermternal.issue-397.phase-a-anchor-evidence.v2", "#404 schema differs")
    validated = authority.validate(DESCRIPTOR_PATH, FINAL_ROOT, DESCRIPTOR_SHA256)
    replay_authority = wrapper.load_authority()
    provenance = stable_read(PROVENANCE_PATH, "#403 provenance")
    require(provenance.sha256 == PROVENANCE_SHA256, "#403 provenance SHA-256 differs")
    provenance_value = strict_json(provenance.raw, "#403 provenance")
    require(provenance_value.get("schema") == "hermternal.issue-397.candidate-five-provenance.v1", "#403 provenance schema differs")
    result = stable_read(Path(result_path).resolve(), "#405 result")
    completion = stable_read(Path(completion_path).resolve(), "#405 completion")
    result_value = strict_json(result.raw, "#405 result")
    completion_value = strict_json(completion.raw, "#405 completion")
    require(set(result_value) == set(wrapper.RESULT_KEYS), "#405 result fields differ")
    require(result_value.get("schema") == wrapper.RESULT_SCHEMA and result_value.get("phase") == wrapper.RESULT_PHASE and result_value.get("lane") == wrapper.RESULT_LANE, "#405 result schema differs")
    require(set(completion_value) == set(wrapper.COMPLETION_KEYS), "#405 completion fields differ")
    require(completion_value.get("schema") == wrapper.COMPLETION_SCHEMA and completion_value.get("completion_marker") == wrapper.SUCCESS_OUTPUT.decode("ascii").strip() and completion_value.get("stderr_policy") == wrapper.STDERR_POLICY and completion_value.get("returncode") == 0, "#405 completion state differs")
    require(completion_value.get("result_path") == os.fspath(result.path) and completion_value.get("result_sha256") == result.sha256, "#405 completion result binding differs")
    require(completion_value.get("result_identity") == {"st_dev": result.identity[0], "st_ino": result.identity[1], "st_uid": result.identity[2], "st_mode": result.identity[3], "st_size": result.identity[4], "st_nlink": result.identity[5]}, "#405 completion result identity differs")
    require(completion_value.get("driver_module_sha256") == wrapper.DRIVER_SHA256 and completion_value.get("driver_source_sha256") == validated.artifacts["shell"].sha256, "#405 driver binding differs")
    require(completion_value.get("markdown_sha256") == validated.artifacts["markdown"].sha256 and completion_value.get("json_sha256") == validated.artifacts["json"].sha256 and completion_value.get("shell_sha256") == validated.artifacts["shell"].sha256 and completion_value.get("provenance_sha256") == provenance.sha256, "#403/#405 authority binding differs")
    for key in ("base_commit", "base_tree", "protected_main_commit", "required_ancestors", "forbidden_ancestors"):
        require(result_value.get(key) == getattr(replay_authority, key), f"#405 {key} differs")
    require(completion_value.get("source_commit") == replay_authority.source_commit, "#405 source commit differs")
    for key in ("final_head", "tree", "parent"):
        _require_oid(result_value.get(key), f"#405 {key}")
    replay_root = Path(result_value.get("replay_root", ""))
    repository = Path(result_value.get("repository", ""))
    require(replay_root.is_absolute() and repository.is_absolute() and replay_root.name == "replay-root" and repository.name == "repository" and replay_root.parent == repository.parent, "#405 retained root layout differs")
    phase_anchor_path = Path(completion_value.get("phase_a_evidence_path", ""))
    phase_anchor_sha = completion_value.get("phase_a_evidence_sha256")
    require(isinstance(phase_anchor_sha, str) and SHA_RE.fullmatch(phase_anchor_sha), "#404 anchor digest differs")
    evidence = wrapper.load_phase_a_evidence(phase_anchor_path, phase_anchor_sha)
    require(result_value.get("phase_a_manifest_sha256") == evidence.manifest_sha256 and result_value.get("phase_a_approval_digest") == evidence.approval_digest, "#404/#405 Phase A binding differs")
    return Chain(repository, result_value["final_head"], result_value["tree"], result_value["protected_main_commit"], result, completion, evidence.anchor, provenance)


@dataclass(frozen=True)
class Gate:
    gate_id: str
    workdir: str
    command: tuple[str, ...]


# Tuple construction and the config digest make a skipped or reordered gate a
# rejection.  Commands execute only inside the locked container below.
GATES = (
    Gate("git-head", "/workspace", ("git", "rev-parse", "HEAD^{commit}")),
    Gate("git-tree", "/workspace", ("git", "rev-parse", "HEAD^{tree}")),
    Gate("git-main", "/workspace", ("git", "rev-parse", "refs/remotes/origin/main^{commit}")),
    Gate("git-dev", "/workspace", ("git", "rev-parse", "refs/remotes/origin/dev^{commit}")),
    Gate("git-clean", "/workspace", ("git", "status", "--porcelain=v1", "--untracked-files=all")),
    Gate("git-fsck", "/workspace", ("git", "fsck", "--full", "--strict")),
    Gate("web-typecheck", "/workspace/apps/web", ("bun", "x", "--no-install", "svelte-check", "--tsconfig", "./tsconfig.json")),
    Gate("web-unit", "/workspace/apps/web", ("bun", "x", "--no-install", "vitest", "run")),
    Gate("web-build", "/workspace/apps/web", ("bun", "x", "--no-install", "vite", "build")),
    Gate("privacy-redaction", "/workspace/apps/web", ("bun", "x", "--no-install", "vitest", "run", "src/lib/live-artifact-policy.test.ts", "src/lib/live-screenshot-contract.test.ts")),
    Gate("accessibility", "/workspace/apps/web", ("bun", "run", "--no-install", "test:a11y")),
    Gate("no-network-browser", "/workspace/apps/web", ("bun", "run", "--no-install", "test:no-network")),
    Gate("auth-click-enter", "/workspace/apps/web", ("bun", "x", "--no-install", "playwright", "test", "tests/e2e/ui-preview.spec.ts", "--grep", "native password activation clears live values")),
)
GATE_LIST_SHA256 = digest(json.dumps([[g.gate_id, g.workdir, list(g.command)] for g in GATES], separators=(",", ":")).encode())


def podman_argv(repository: Path, gate: Gate) -> tuple[str, ...]:
    """Return a rootless, read-only, network-none command with no host secrets."""
    uid, gid = os.getuid(), os.getgid()
    return ("/usr/bin/podman", "run", "--rm", "--pull=never", "--network=none", "--userns=keep-id", "--user", f"{uid}:{gid}", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m", "--mount", f"type=bind,src={repository},dst=/workspace,ro=true,relabel=private", "--workdir", gate.workdir, *sum((("--env", f"{key}={value}") for key, value in sorted(SAFE_ENV.items())), ()), IMAGE, *gate.command)


def image_exists(_: str) -> bool:
    """Discover only a local image; --pull=never makes discovery non-networked."""
    return subprocess.run(("/usr/bin/podman", "image", "exists", IMAGE), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(SAFE_ENV), cwd="/", check=False).returncode == 0


def semantic_evidence(repository: Path) -> dict[str, Any]:
    """Record source facts for privacy, accessibility, and keyboard auth proof."""
    paths = {"auth": repository / "apps/web/tests/e2e/ui-preview.spec.ts", "privacy": repository / "apps/web/src/lib/live-artifact-policy.test.ts", "screenshots": repository / "apps/web/src/lib/live-screenshot-contract.test.ts"}
    raw = {name: stable_read(path.resolve(), f"semantic {name}", 2 * 1024 * 1024).raw.decode("utf-8") for name, path in paths.items()}
    auth = raw["auth"]
    checks = {"click": "activation === 'click'" in auth and ".click()" in auth, "enter": "activation === 'enter'" in auth and ".press('Enter')" in auth, "clearing": auth.count("toHaveValue('')") >= 4 and "outerHTML" in auth, "redaction": "page.screenshot()" in auth and "not.toContain(passwordValue)" in auth and "not.toContain(usernameValue)" in auth, "accessibility": "AxeBuilder" in auth and "axe violations" in auth, "privacy_policy": "LIVE_ARTIFACT_REDACTION" in raw["privacy"] and "screenshot: 'off'" in raw["privacy"], "screenshot_contract": "blockedLiveScreenshotManifest" in raw["screenshots"]}
    require(all(checks.values()), "semantic privacy, accessibility, or authentication evidence is incomplete")
    return {"checks": checks, "sources": {name: {"path": os.fspath(paths[name]), "sha256": digest(raw[name].encode("utf-8"))} for name in paths}}


Run = Callable[..., subprocess.CompletedProcess[bytes]]


def run_gates(chain: Chain, run: Run = subprocess.run, exists: Callable[[str], bool] = image_exists) -> list[dict[str, Any]]:
    require(digest(json.dumps([[g.gate_id, g.workdir, list(g.command)] for g in GATES], separators=(",", ":")).encode()) == GATE_LIST_SHA256, "immutable gate list differs")
    repository_meta = os.lstat(chain.repository)
    require(chain.repository.is_absolute() and os.path.realpath(chain.repository) == os.fspath(chain.repository) and stat.S_ISDIR(repository_meta.st_mode) and repository_meta.st_uid == os.getuid() and stat.S_IMODE(repository_meta.st_mode) == 0o700, "retained repository is not private")
    require(exists(IMAGE), "pinned Podman image is unavailable locally")
    records: list[dict[str, Any]] = []
    for gate in GATES:
        argv = podman_argv(chain.repository, gate)
        try:
            result = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(SAFE_ENV), cwd="/", timeout=900, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Reject(f"{gate.gate_id} was unavailable") from error
        stdout, stderr = bytes(result.stdout or b""), bytes(result.stderr or b"")
        require(len(stdout) <= MAX_OUTPUT and len(stderr) <= MAX_OUTPUT, f"{gate.gate_id} output exceeds its byte limit")
        require(result.returncode == 0, f"{gate.gate_id} failed")
        expected = {"git-head": chain.final_head, "git-tree": chain.final_tree, "git-main": chain.protected_main, "git-dev": chain.final_head, "git-clean": ""}
        if gate.gate_id in expected:
            require(stdout.decode("utf-8", "strict").strip() == expected[gate.gate_id], f"{gate.gate_id} output differs")
        records.append({"id": gate.gate_id, "argv": list(argv), "exit_code": result.returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)})
    records.append({"id": "semantic-evidence", "internal": True, "evidence": semantic_evidence(chain.repository)})
    return records


def write_report(path: Path, chain: Chain, gates: list[dict[str, Any]]) -> Snapshot:
    """Create exactly one fsynced report; existing evidence is never replaced."""
    value = {"schema": REPORT_SCHEMA, "status": "passed", "network": "not-used", "credentials": "not-used", "container": {"runtime": "rootless-podman", "image": IMAGE, "pull": "never", "network": "none", "read_only": True}, "gate_list_sha256": GATE_LIST_SHA256, "repository": os.fspath(chain.repository), "final_head": chain.final_head, "final_tree": chain.final_tree, "protected_main": chain.protected_main, "dev_target": chain.final_head, "inputs": {"result": {"path": os.fspath(chain.result.path), "sha256": chain.result.sha256}, "completion": {"path": os.fspath(chain.completion.path), "sha256": chain.completion.sha256}, "phase_a_anchor": {"path": os.fspath(chain.phase_anchor.path), "sha256": chain.phase_anchor.sha256}, "provenance": {"path": os.fspath(chain.provenance.path), "sha256": chain.provenance.sha256}}, "gates": gates}
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path = Path(path).resolve(); require(path.parent.is_dir(), "report parent is absent")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, "offline report write made no progress")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)); os.fsync(parent); os.close(parent)
    report = stable_read(path, "offline report")
    require(report.raw == raw, "offline report changed after create")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True); parser.add_argument("--completion", type=Path, required=True); parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    chain = _load_chain(args.result, args.completion)
    gates = run_gates(chain)
    # Revalidate every durable input after the last gate but before publication.
    final_chain = _load_chain(args.result, args.completion)
    require(chain == final_chain, "result chain changed during offline gates")
    write_report(args.report, final_chain, gates)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Reject as error:
        print(f"OFFLINE_GATES_REJECT: {error}", file=os.sys.stderr)
        raise SystemExit(2)
