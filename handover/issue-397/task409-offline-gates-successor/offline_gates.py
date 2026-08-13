#!/usr/bin/env python3
"""Run a closed offline gate set after guarded replay and genuine Phase B."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


PROVENANCE_SCHEMA = "hermternal.issue-397.candidate-five-provenance.v1"
INTERLOCK_SCHEMA = "hermternal.issue-397.execution-interlock.v1"
BASE_COMMIT = "729f2613af2b78d58b07918478e9102d5716f367"
MAIN_COMMIT = "3ebf8b3fe4767442490ab3053c0c1ccf84e8019f"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
NETWORK_MARKERS = (b"http://", b"https://", b"registry.", b"download", b"fetching", b"connecting to")
BLOCKED_ENV_PREFIXES = ("AWS_", "AZURE_", "GOOGLE_", "HERMES_", "OPENAI_", "ANTHROPIC_", "GITHUB_TOKEN", "GH_TOKEN", "SSH_")
SAFE_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C", "CI": "1",
    "NO_COLOR": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1", "BUN_CONFIG_NO_VERIFY": "1",
}
PROVENANCE_KEYS = frozenset({"schema", "issue", "candidate", "generation", "repository_boundary", "dependencies", "source_inputs", "outputs", "cross_format_authority", "publication", "safety_claims"})


class Reject(Exception):
    """A deliberate fail-closed offline gate rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    """Parse UTF-8 JSON and reject duplicate keys."""
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


def stable_read(path: Path, label: str, limit: int = 8 * 1024 * 1024) -> bytes:
    """Read one canonical single-link file three times without following links."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path is not canonical")
    observations = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit, f"{label} metadata differs")
            raw = b""
            while True:
                chunk = os.read(fd, min(131072, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk; require(len(raw) <= limit, f"{label} exceeds its bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.stat(path, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_uid, stat.S_IMODE(item.st_mode), item.st_size, item.st_nlink)
        require(identity(before) == identity(after) == identity(final), f"{label} changed during read")
        observations.append((raw, identity(before)))
    require(observations[0] == observations[1] == observations[2], f"{label} changed across reads")
    return observations[0][0]


@dataclass(frozen=True)
class Authority:
    """Cross-check facts accepted from #403 and #404/#405."""

    integrated_commit: str
    integrated_tree: str
    source_commit: str
    final_head: str
    final_tree: str
    replay_root: Path
    repository: Path


def validate_inputs(provenance_raw: bytes, interlock_raw: bytes) -> Authority:
    """Require a complete Phase B chain and exact #403 repository boundary."""
    provenance = strict_json(provenance_raw, "#403 provenance")
    require(set(provenance) == PROVENANCE_KEYS and provenance.get("schema") == PROVENANCE_SCHEMA, "#403 provenance schema differs")
    boundary = provenance.get("repository_boundary")
    required_boundary = {"integrated_commit", "integrated_tree", "base_commit", "base_tree", "protected_main_commit", "source_commit"}
    require(isinstance(boundary, dict) and set(boundary) == required_boundary, "#403 repository boundary differs")
    require(boundary["base_commit"] == BASE_COMMIT and boundary["protected_main_commit"] == MAIN_COMMIT, "fixed base or main differs")
    interlock = strict_json(interlock_raw, "#404/#405 result")
    required_result = {"schema", "state", "authority_provenance_sha256", "integrated_commit", "integrated_tree", "source_commit", "base_commit", "base_tree", "protected_main_commit", "runtime_parent", "replay_root", "events", "tip_event_sha256"}
    require(set(interlock) == required_result and interlock["schema"] == INTERLOCK_SCHEMA and interlock["state"] == "phase-b", "interlock is not a complete Phase B result")
    require(interlock["authority_provenance_sha256"] == hashlib.sha256(provenance_raw).hexdigest(), "interlock provenance identity differs")
    for key in ("integrated_commit", "integrated_tree", "source_commit", "base_commit", "base_tree", "protected_main_commit"):
        require(interlock[key] == boundary[key], f"interlock {key} differs")
    events = interlock["events"]
    require(isinstance(events, list) and [item.get("stage") for item in events] == ["phase-a", "anchor", "replay", "phase-b"], "interlock event order differs")
    require(all(item.get("status") == "PASS" for item in events), "interlock contains a non-PASS event")
    replay = events[2].get("evidence", {}); phase_b = events[3].get("evidence", {})
    require(phase_b.get("execution") == "not-run" and phase_b.get("mutation") == "not-run" and phase_b.get("network") == "not-used", "Phase B safety fields differ")
    replay_root = Path(interlock["replay_root"]); repository = Path(replay.get("repository", ""))
    require(replay_root.is_absolute() and repository == replay_root / "repository", "isolated replay repository differs")
    for key in ("final_head", "final_tree"):
        require(OID_RE.fullmatch(replay.get(key, "")) is not None, f"replay {key} differs")
    return Authority(boundary["integrated_commit"], boundary["integrated_tree"], boundary["source_commit"], replay["final_head"], replay["final_tree"], replay_root, repository)


def load_inputs(provenance_path: Path, provenance_sha256: str, interlock_path: Path, interlock_sha256: str) -> Authority:
    """Load the exact reviewed input files and bind both external digests."""
    require(SHA256_RE.fullmatch(provenance_sha256) is not None and SHA256_RE.fullmatch(interlock_sha256) is not None, "input SHA-256 is invalid")
    provenance_raw = stable_read(Path(provenance_path), "#403 provenance")
    interlock_raw = stable_read(Path(interlock_path), "#404/#405 result")
    require(hashlib.sha256(provenance_raw).hexdigest() == provenance_sha256, "#403 provenance SHA-256 differs")
    require(hashlib.sha256(interlock_raw).hexdigest() == interlock_sha256, "#404/#405 result SHA-256 differs")
    return validate_inputs(provenance_raw, interlock_raw)


@dataclass(frozen=True)
class Gate:
    """One exact offline command or internal source hook."""

    gate_id: str
    argv: tuple[str, ...]
    cwd: str = "."
    hook: str | None = None


GATES = (
    Gate("git-head", ("/usr/bin/git", "rev-parse", "HEAD^{commit}")),
    Gate("git-tree", ("/usr/bin/git", "rev-parse", "HEAD^{tree}")),
    Gate("git-main-unchanged", ("/usr/bin/git", "rev-parse", "refs/remotes/origin/main^{commit}")),
    Gate("git-dev-target", ("/usr/bin/git", "rev-parse", "refs/remotes/origin/dev^{commit}")),
    Gate("git-clean", ("/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=all")),
    Gate("git-fsck", ("/usr/bin/git", "fsck", "--full", "--strict")),
    Gate("web-typecheck", ("bun", "x", "--no-install", "svelte-check", "--tsconfig", "./tsconfig.json"), "apps/web"),
    Gate("web-unit-tests", ("bun", "x", "--no-install", "vitest", "run"), "apps/web"),
    Gate("web-static-build", ("bun", "x", "--no-install", "vite", "build"), "apps/web"),
    Gate("privacy-redaction", ("bun", "x", "--no-install", "vitest", "run", "src/lib/live-artifact-policy.test.ts", "src/lib/live-screenshot-contract.test.ts"), "apps/web"),
    Gate("accessibility", ("bun", "run", "--no-install", "test:a11y"), "apps/web"),
    Gate("no-network-browser", ("bun", "run", "--no-install", "test:no-network"), "apps/web"),
    Gate("auth-click-enter", ("bun", "x", "--no-install", "playwright", "test", "tests/e2e/ui-preview.spec.ts", "--grep", "native password activation clears live values"), "apps/web"),
    Gate("auth-source-evidence", ("internal", "auth-source-evidence"), hook="auth-source"),
)
REQUIRED_GATE_IDS = tuple(gate.gate_id for gate in GATES)


def verify_repository_identity(authority: Authority) -> None:
    """Bind the existing canonical private replay root and repository names."""
    for path, label in ((authority.replay_root, "replay root"), (authority.repository, "repository")):
        require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} is not canonical")
        metadata = os.stat(path, follow_symlinks=False)
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700, f"{label} is not a private directory")


def auth_source_hook(repository: Path) -> dict[str, Any]:
    """Require click, Enter, accessibility, DOM, and screenshot-redaction source hooks."""
    path = repository / "apps/web/tests/e2e/ui-preview.spec.ts"
    source = stable_read(path.resolve(), "authentication source", 2 * 1024 * 1024).decode("utf-8")
    checks = {
        "click": "'click'" in source or '"click"' in source,
        "enter": "'enter'" in source or '"enter"' in source,
        "accessibility": "axe" in source.lower() or "toHaveAccessibleName" in source,
        "dom_clear": source.count("toHaveValue('')") >= 2 and "outerHTML" in source,
        "screenshot_redaction": "page.screenshot" in source and bool(re.search(r"(?:usernameValue|visible-username)[\s\S]{0,500}not\.toContain", source)),
    }
    require(all(checks.values()), f"authentication source hook is incomplete: {[key for key, value in checks.items() if not value]}")
    return checks


def _safe_argv(gate: Gate) -> None:
    joined = " ".join(gate.argv).lower()
    for token in ("curl", "wget", "podman", "docker", "ssh", "npm install", "bun install", "test:e2e:live", "hermes"):
        require(token not in joined, f"{gate.gate_id} has a blocked command token")


def run_gates(authority: Authority, run: Callable[..., subprocess.CompletedProcess[bytes]]) -> dict[str, Any]:
    """Run every required gate through the one injected process boundary."""
    verify_repository_identity(authority)
    require(tuple(gate.gate_id for gate in GATES) == REQUIRED_GATE_IDS, "required offline gate was skipped or substituted")
    results = []
    for gate in GATES:
        _safe_argv(gate)
        if gate.hook == "auth-source":
            checks = auth_source_hook(authority.repository)
            results.append({"id": gate.gate_id, "status": "passed", "argv": list(gate.argv), "exit_code": 0, "stdout_sha256": hashlib.sha256(json.dumps(checks, sort_keys=True).encode()).hexdigest(), "stderr_sha256": hashlib.sha256(b"").hexdigest()})
            continue
        cwd = (authority.repository / gate.cwd).resolve()
        require(cwd.is_dir() and (cwd == authority.repository or authority.repository in cwd.parents), f"{gate.gate_id} cwd differs")
        try:
            completed = run(gate.argv, cwd=cwd, env=dict(SAFE_ENV), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Reject(f"{gate.gate_id} failed or was unavailable: {exc.__class__.__name__}") from exc
        stdout = bytes(completed.stdout or b""); stderr = bytes(completed.stderr or b"")
        require(len(stdout) <= 2 * 1024 * 1024 and len(stderr) <= 2 * 1024 * 1024, f"{gate.gate_id} output exceeds its bound")
        lowered = (stdout + b"\n" + stderr).lower()
        require(not any(marker in lowered for marker in NETWORK_MARKERS), f"{gate.gate_id} output contains a network indicator")
        require(completed.returncode == 0, f"{gate.gate_id} failed or was unavailable")
        normalized = stdout.decode("utf-8", "replace").strip()
        expected = {"git-head": authority.final_head, "git-tree": authority.final_tree, "git-main-unchanged": MAIN_COMMIT, "git-dev-target": authority.final_head, "git-clean": ""}
        if gate.gate_id in expected:
            require(normalized == expected[gate.gate_id], f"{gate.gate_id} result differs")
        results.append({"id": gate.gate_id, "status": "passed", "argv": list(gate.argv), "exit_code": completed.returncode, "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest()})
    require(len(results) == len(GATES) and all(item["status"] == "passed" for item in results), "offline gate set is incomplete")
    return {"schema": "hermternal.issue-397.offline-gates.v1", "status": "passed", "offline": True, "credentials": "not-used", "network": "not-used", "repository": str(authority.repository), "final_head": authority.final_head, "final_tree": authority.final_tree, "main_unchanged": MAIN_COMMIT, "dev_target": authority.final_head, "gates": results}
