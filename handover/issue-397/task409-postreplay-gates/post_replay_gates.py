#!/usr/bin/env python3
"""Run the deterministic, offline gates after a replay checkout is created.

This runner is intentionally outside the repository.  It accepts one absolute,
isolated replay checkout, executes only allowlisted local commands, never stages
or writes the checkout, and writes a JSON evidence report elsewhere.  Command
stdout and stderr are hashed in memory rather than retained, which keeps the
report useful without turning it into a transcript or credential artifact.

The runner does not claim that a skipped, unavailable, or failed gate passed.
The Task #475 authentication handoff is fail-closed: existing click/Enter and
DOM checks may run, but a source-evidence check still requires an explicit
screenshot-content assertion for the entered username.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


SCHEMA = "hermternal.task409-postreplay-gates.v1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 120.0
WEB_TIMEOUT_SECONDS = 180.0
E2E_TIMEOUT_SECONDS = 240.0

# Commands in this runner must remain local and offline.  These tokens are
# rejected before spawn so a future edit cannot accidentally widen the lane.
BLOCKED_COMMAND_TOKENS = (
    "podman",
    "docker",
    "curl",
    "wget",
    "ssh",
    "scp",
    "hermes_agent.py",
    "with_live_credential.py",
    "test:e2e:live",
    "playwright.live.config",
)


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    cwd_rel: str = "."
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    expected_stdout: str | None = None
    artifact_paths: tuple[str, ...] = ()
    label: str = ""


@dataclass(frozen=True)
class GateSpec:
    gate_id: str
    category: str
    description: str
    commands: tuple[CommandSpec, ...] = ()
    required_paths: tuple[str, ...] = ()
    planned_commands: tuple[tuple[str, ...], ...] = ()
    artifact_paths: tuple[str, ...] = ()
    special: str | None = None
    skip_reason: str | None = None
    use_candidate: bool = False


@dataclass
class CommandResult:
    argv: list[str]
    cwd: str
    status: str
    exit_code: int | None
    duration_ms: float | None
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    reason: str | None = None
    label: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "argv": self.argv,
            "cwd": self.cwd,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "artifacts": self.artifacts,
        }
        if self.reason:
            result["reason"] = self.reason
        if self.label:
            result["label"] = self.label
        return result


@dataclass
class GateResult:
    gate: GateSpec
    status: str
    commands: list[CommandResult]
    reason: str | None = None
    evidence: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.gate.gate_id,
            "category": self.gate.category,
            "description": self.gate.description,
            "status": self.status,
            "commands": [command.as_dict() for command in self.commands],
        }
        if self.gate.planned_commands:
            result["planned_commands"] = [list(command) for command in self.gate.planned_commands]
        if self.reason:
            result["reason"] = self.reason
        if self.evidence is not None:
            result["evidence"] = self.evidence
        return result


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    """Hash one regular, non-symlink file without following replacements."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FileNotFoundError(path) from exc
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact is not a regular file: {path}")
    if metadata.st_size < 0 or metadata.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact exceeds bounded size: {path}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError(f"artifact exceeds bounded size: {path}")
            digest.update(chunk)
    try:
        final = path.lstat()
    except OSError as exc:
        raise ValueError(f"artifact changed during hashing: {path}") from exc
    if path.is_symlink() or final.st_size != metadata.st_size:
        raise ValueError(f"artifact changed during hashing: {path}")
    return digest.hexdigest(), total


def normalize_output_path(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        raise ValueError("--output must be an absolute path")
    return path.resolve(strict=False)


def normalize_checkout(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        raise ValueError("--checkout-root must be an absolute path")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("--checkout-root must be a directory")
    return resolved


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def safe_relative_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve(strict=False)
    if not is_within(candidate, root):
        raise ValueError(f"path escapes checkout: {relative}")
    return candidate


def check_required_paths(root: Path, paths: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for relative in paths:
        try:
            path = safe_relative_path(root, relative)
            if not path.exists() or path.is_symlink():
                missing.append(relative)
        except (OSError, ValueError):
            missing.append(relative)
    return missing


def artifact_records(root: Path, paths: Iterable[str]) -> tuple[list[dict[str, Any]], str | None]:
    records: list[dict[str, Any]] = []
    total = 0
    for relative in paths:
        try:
            path = safe_relative_path(root, relative)
            digest, size = sha256_file(path)
        except FileNotFoundError:
            records.append({"path": relative, "status": "missing"})
            return records, f"required artifact missing: {relative}"
        except (OSError, ValueError) as exc:
            records.append({"path": relative, "status": "rejected"})
            return records, str(exc)
        total += size
        if total > MAX_ARTIFACT_TOTAL_BYTES:
            records.append({"path": relative, "status": "rejected"})
            return records, "artifact total exceeds bounded size"
        records.append({"path": relative, "status": "hashed", "size_bytes": size, "sha256": digest})
    return records, None


def command_is_allowed(argv: Sequence[str]) -> bool:
    lowered = " ".join(argv).lower()
    return not any(token in lowered for token in BLOCKED_COMMAND_TOKENS)


def base_environment(report_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "CI": "1",
            "NO_COLOR": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(report_root / "pycache"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
            # Bun commands must never populate a missing dependency tree or
            # consult a registry as a side effect of a post-replay gate.
            "BUN_CONFIG_NO_VERIFY": "1",
        }
    )
    return env


def unavailable_command(spec: CommandSpec, root: Path, reason: str) -> CommandResult:
    return CommandResult(
        argv=list(spec.argv),
        cwd=str(safe_relative_path(root, spec.cwd_rel)),
        status="unavailable",
        exit_code=None,
        duration_ms=None,
        stdout_sha256=EMPTY_SHA256,
        stderr_sha256=EMPTY_SHA256,
        stdout_bytes=0,
        stderr_bytes=0,
        reason=reason,
        label=spec.label or None,
    )


def skipped_command(spec: CommandSpec, root: Path, reason: str) -> CommandResult:
    result = unavailable_command(spec, root, reason)
    result.status = "skipped"
    return result


def run_command(
    spec: CommandSpec,
    root: Path,
    report_root: Path,
    *,
    required_artifacts: Iterable[str] = (),
) -> CommandResult:
    cwd = safe_relative_path(root, spec.cwd_rel)
    if not cwd.is_dir():
        return unavailable_command(spec, root, f"working directory is unavailable: {spec.cwd_rel}")
    if not command_is_allowed(spec.argv):
        return CommandResult(
            argv=list(spec.argv),
            cwd=str(cwd),
            status="failed",
            exit_code=None,
            duration_ms=0.0,
            stdout_sha256=EMPTY_SHA256,
            stderr_sha256=EMPTY_SHA256,
            stdout_bytes=0,
            stderr_bytes=0,
            reason="offline command allowlist rejected this command",
            label=spec.label or None,
        )

    started = time.perf_counter()
    try:
        command_argv = list(spec.argv)
        if spec.argv[:2] == ("python3", "scripts/verify_fixture_registry_authority.py"):
            command_argv.extend(["--repo-root", ".", "--checkout-root", "."])
        completed = subprocess.run(
            command_argv,
            cwd=cwd,
            env=base_environment(report_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=spec.timeout_seconds,
            check=False,
        )
        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
    except subprocess.TimeoutExpired as exc:
        stdout = bytes(exc.stdout or b"")
        stderr = bytes(exc.stderr or b"")
        return CommandResult(
            argv=list(spec.argv),
            cwd=str(cwd),
            status="failed",
            exit_code=None,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            stdout_sha256=sha256_bytes(stdout),
            stderr_sha256=sha256_bytes(stderr),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            reason=f"command timed out after {spec.timeout_seconds:.1f}s",
            label=spec.label or None,
        )
    except OSError as exc:
        return CommandResult(
            argv=list(spec.argv),
            cwd=str(cwd),
            status="unavailable",
            exit_code=None,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            stdout_sha256=EMPTY_SHA256,
            stderr_sha256=EMPTY_SHA256,
            stdout_bytes=0,
            stderr_bytes=0,
            reason=f"command unavailable: {exc.__class__.__name__}",
            label=spec.label or None,
        )

    status = "passed" if completed.returncode == 0 else "failed"
    reason: str | None = None
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        status = "failed"
        reason = "command output exceeded the bounded capture limit"
    if status == "passed" and spec.expected_stdout is not None:
        normalized = stdout.decode("utf-8", "replace").strip()
        if normalized != spec.expected_stdout:
            status = "failed"
            reason = "command output did not match the pinned toolchain value"
    artifacts, artifact_error = artifact_records(root, tuple(required_artifacts) + tuple(spec.artifact_paths))
    if status == "passed" and artifact_error:
        status = "failed"
        reason = artifact_error
    return CommandResult(
        argv=command_argv,
        cwd=str(cwd),
        status=status,
        exit_code=completed.returncode,
        duration_ms=duration_ms,
        stdout_sha256=sha256_bytes(stdout),
        stderr_sha256=sha256_bytes(stderr),
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
        artifacts=artifacts,
        reason=reason,
        label=spec.label or None,
    )


def aggregate_status(commands: Sequence[CommandResult], *, forced_reason: str | None = None) -> tuple[str, str | None]:
    if forced_reason:
        return "failed", forced_reason
    statuses = [command.status for command in commands]
    if any(status == "failed" for status in statuses):
        return "failed", "one or more commands failed"
    if any(status == "unavailable" for status in statuses):
        return "unavailable", "one or more required commands were unavailable"
    if statuses and all(status == "skipped" for status in statuses):
        return "skipped", "gate was intentionally not executed"
    if not statuses:
        return "skipped", "gate has no executable command in this offline lane"
    return "passed", None


def web_artifacts() -> tuple[str, ...]:
    return (
        "apps/web/package.json",
        "apps/web/bun.lock",
    )


def build_plan(root: Path) -> list[GateSpec]:
    py = "python3"
    web = root / "apps" / "web"
    fixture_validator_paths = (
        "contracts/fixtures/index.json",
        "contracts/fixtures/schema.json",
        "contracts/fixtures/validator/validate.py",
        "contracts/fixtures/validator/test_validate.py",
        "contracts/fixtures/validator/validation-baseline.json",
    )
    authority_paths = (
        "scripts/verify_fixture_registry_authority.py",
        "scripts/fixture_registry_authority.v2.json",
        *fixture_validator_paths,
    )
    static_build_artifacts = (
        *web_artifacts(),
        "apps/web/build/index.html",
        "apps/web/build/200.html",
        "apps/web/build/manifest.webmanifest",
        "apps/web/build/service-worker.js",
        "apps/web/.svelte-kit/output/client/.vite/manifest.json",
    )
    web_required = (
        "apps/web/package.json",
        "apps/web/bun.lock",
        "apps/web/node_modules",
    )
    python_script_paths = (
        "scripts/live_run_marker.py",
        "scripts/test_live_run_marker.py",
        "scripts/hermes_agent.py",
        "scripts/test_hermes_agent.py",
        "scripts/with_live_credential.py",
        "scripts/test_with_live_credential.py",
        "scripts/read_launcher_result.py",
        "scripts/test_read_launcher_result.py",
    )
    paper_paths = (
        "contracts/design-tokens/web/validate.py",
        "contracts/design-tokens/web/test_validate.py",
        "contracts/design-tokens/web/artboards.json",
    )
    auth_spec = "apps/web/tests/e2e/ui-preview.spec.ts"

    return [
        GateSpec(
            "candidate-git-integrity",
            "git",
            "Read-only Git object, diff, and clean-worktree review for the supplied candidate.",
            commands=(
                CommandSpec(("git", "rev-parse", "--verify", "HEAD^{commit}"), label="candidate HEAD"),
                CommandSpec(("git", "rev-parse", "--is-inside-work-tree"), expected_stdout="true", label="repository check"),
                CommandSpec(("git", "fsck", "--full", "--strict"), timeout_seconds=WEB_TIMEOUT_SECONDS, label="strict object check"),
                CommandSpec(("git", "diff", "--check"), label="worktree whitespace check"),
                CommandSpec(("git", "diff", "--cached", "--check"), label="index whitespace check"),
                CommandSpec(("git", "status", "--porcelain=v1", "--untracked-files=all"), label="clean worktree check"),
            ),
            required_paths=(".git",),
            artifact_paths=(".git/HEAD",),
        ),
        GateSpec(
            "dependency-toolchain",
            "dependencies",
            "Verify pinned local Bun and Node versions and read-only lockfile metadata without registry access.",
            commands=(
                CommandSpec(("bun", "--version"), expected_stdout="1.3.14", label="Bun version"),
                CommandSpec(("node", "--version"), expected_stdout="v26.7.0", label="Node version"),
                CommandSpec(("bun", "pm", "hash"), cwd_rel="apps/web", artifact_paths=web_artifacts(), label="lockfile hash"),
                CommandSpec(("bun", "pm", "untrusted"), cwd_rel="apps/web", artifact_paths=web_artifacts(), label="untrusted package list"),
            ),
            required_paths=("apps/web/package.json", "apps/web/bun.lock"),
            planned_commands=(("bun", "pm", "scan"),),
            artifact_paths=web_artifacts(),
        ),
        GateSpec(
            "web-typecheck",
            "web",
            "Run the package's local TypeScript and Svelte type checks with Bun auto-install disabled.",
            commands=(
                CommandSpec(("bun", "x", "--no-install", "--package", "@typescript/native", "tsc", "--noEmit", "--pretty", "false", "-p", "tsconfig.json"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=web_artifacts(), label="TypeScript 7 typecheck"),
                CommandSpec(("bun", "x", "--no-install", "svelte-check", "--tsconfig", "./tsconfig.json"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=web_artifacts(), label="Svelte check"),
            ),
            required_paths=web_required,
            artifact_paths=web_artifacts(),
        ),
        GateSpec(
            "web-unit-tests",
            "web",
            "Run the existing Vitest unit suite only; no test logic is duplicated here.",
            commands=(
                CommandSpec(("bun", "x", "--no-install", "vitest", "run"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=web_artifacts(), label="Vitest unit suite"),
            ),
            required_paths=web_required,
            artifact_paths=web_artifacts(),
        ),
        GateSpec(
            "web-build-and-static",
            "web",
            "Build the static web output and run the existing static route, CSS-token, lazy-boundary, and output assertions.",
            commands=(
                CommandSpec(("bun", "x", "--no-install", "vite", "build"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=static_build_artifacts, label="Vite production build"),
                CommandSpec(("node", "--test", "tests/static/terminal-lazy-boundary.test.mjs"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=static_build_artifacts, label="terminal lazy boundary"),
                CommandSpec(("node", "tests/static/assert-static-build.mjs"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=static_build_artifacts, label="static build assertion"),
                CommandSpec(("node", "tests/static/assert-css-tokens.mjs"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=(*static_build_artifacts, "contracts/design-tokens/web/artboards.json"), label="CSS Paper token assertion"),
                CommandSpec(("node", "tests/static/assert-static-routes.mjs"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=static_build_artifacts, label="static route assertion"),
            ),
            required_paths=web_required,
            artifact_paths=static_build_artifacts,
        ),
        GateSpec(
            "python-script-syntax",
            "python",
            "Compile the Task #409 launcher and local test helpers into the report-owned cache prefix.",
            commands=(
                CommandSpec((py, "-m", "py_compile", *python_script_paths), timeout_seconds=DEFAULT_TIMEOUT_SECONDS, label="script py_compile"),
            ),
            required_paths=python_script_paths,
            artifact_paths=python_script_paths,
        ),
        GateSpec(
            "python-script-self-tests",
            "python",
            "Run the documented synthetic launcher, marker, credential-boundary, and result-reader tests.",
            commands=(
                CommandSpec((py, "scripts/test_live_run_marker.py"), label="live run marker tests"),
                CommandSpec((py, "scripts/test_hermes_agent.py"), label="Hermes launcher tests"),
                CommandSpec((py, "scripts/test_with_live_credential.py"), label="credential boundary tests"),
                CommandSpec((py, "scripts/test_read_launcher_result.py"), label="launcher result tests"),
                CommandSpec((py, "-O", "scripts/test_live_run_marker.py"), label="optimized marker tests"),
                CommandSpec((py, "-O", "scripts/test_hermes_agent.py"), label="optimized launcher tests"),
            ),
            required_paths=python_script_paths,
        ),
        GateSpec(
            "python-proof-validators",
            "python",
            "Run the local roadmap and implementation proof-gate validators and their focused tests.",
            commands=(
                CommandSpec((py, "scripts/validate_roadmap_template.py"), label="roadmap validator"),
                CommandSpec((py, "scripts/test_validate_roadmap_template.py"), label="roadmap validator tests"),
                CommandSpec((py, "scripts/validate_proof_gates.py"), label="proof-gate validator"),
                CommandSpec((py, "scripts/test_validate_proof_gates.py"), label="proof-gate validator tests"),
            ),
            required_paths=(
                "scripts/validate_roadmap_template.py",
                "scripts/test_validate_roadmap_template.py",
                "scripts/validate_proof_gates.py",
                "scripts/test_validate_proof_gates.py",
                ".github/ISSUE_TEMPLATE/roadmap.md",
                "docs/product/implementation-proof-gates.md",
            ),
        ),
        GateSpec(
            "aggregate-fixture-registry",
            "fixtures",
            "Validate the aggregate synthetic fixture registry in normal and optimized interpreter modes.",
            commands=(
                CommandSpec((py, "contracts/fixtures/validator/validate.py"), label="fixture registry validator"),
                CommandSpec((py, "-O", "contracts/fixtures/validator/validate.py"), label="optimized fixture registry validator"),
                CommandSpec((py, "contracts/fixtures/validator/test_validate.py"), label="fixture registry tests"),
                CommandSpec((py, "-O", "contracts/fixtures/validator/test_validate.py"), label="optimized fixture registry tests"),
                CommandSpec((py, "-m", "py_compile", "contracts/fixtures/validator/validate.py", "contracts/fixtures/validator/test_validate.py"), label="fixture validator syntax"),
            ),
            required_paths=fixture_validator_paths,
            artifact_paths=fixture_validator_paths,
        ),
        GateSpec(
            "fixture-registry-authority",
            "fixtures",
            "Re-run the immutable v2 fixture-registry authority and its focused tests against the candidate checkout.",
            commands=(
                CommandSpec((py, "scripts/verify_fixture_registry_authority.py"), timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=authority_paths, label="immutable authority verifier"),
                CommandSpec((py, "scripts/test_fixture_registry_authority.py"), timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=authority_paths, label="authority verifier tests"),
            ),
            required_paths=authority_paths,
            artifact_paths=authority_paths,
        ),
        GateSpec(
            "paper-state-comparison",
            "paper",
            "Run the offline Paper artboard/token manifest validator and existing CSS-token comparison.",
            commands=(
                CommandSpec((py, "contracts/design-tokens/web/validate.py"), label="Paper manifest validator"),
                CommandSpec((py, "-O", "contracts/design-tokens/web/validate.py"), label="optimized Paper manifest validator"),
                CommandSpec((py, "contracts/design-tokens/web/test_validate.py"), label="Paper manifest tests"),
                CommandSpec((py, "-O", "contracts/design-tokens/web/test_validate.py"), label="optimized Paper manifest tests"),
                CommandSpec(("node", "tests/static/assert-css-tokens.mjs"), cwd_rel="apps/web", timeout_seconds=WEB_TIMEOUT_SECONDS, artifact_paths=("contracts/design-tokens/web/artboards.json",), label="static Paper CSS comparison"),
            ),
            required_paths=(*paper_paths, "apps/web/tests/static/assert-css-tokens.mjs"),
            artifact_paths=paper_paths,
            planned_commands=(("paper-mcp", "inspect", "01KZ6BB66KCWR2C4J2TSWQGDM7"),),
        ),
        GateSpec(
            "privacy-redaction",
            "privacy",
            "Run the existing live-artifact and screenshot redaction tests; the Task #464 harness is referenced, not reimplemented.",
            commands=(
                CommandSpec(("bun", "x", "--no-install", "vitest", "run", "src/lib/live-artifact-policy.test.ts", "src/lib/live-screenshot-contract.test.ts"), cwd_rel="apps/web", timeout_seconds=E2E_TIMEOUT_SECONDS, artifact_paths=web_artifacts(), label="existing redaction and screenshot tests"),
            ),
            required_paths=(
                *web_required,
                "apps/web/src/lib/live-artifact-policy.test.ts",
                "apps/web/src/lib/live-screenshot-contract.test.ts",
                "apps/web/tests/live/live-artifact-policy.mjs",
                "apps/web/tests/live/live-screenshot-contract.mjs",
            ),
            planned_commands=(("existing", "Task #464", "artifact", "harness", "owned", "outside", "this", "runner"),),
            skip_reason="The production-build artifact harness remains owned by Task #464 and is not duplicated here.",
        ),
        GateSpec(
            "accessibility-no-network",
            "accessibility",
            "Run the existing axe accessibility lane and no-network browser lane with local dependencies only.",
            commands=(
                CommandSpec(("bun", "run", "--no-install", "test:a11y"), cwd_rel="apps/web", timeout_seconds=E2E_TIMEOUT_SECONDS, artifact_paths=web_artifacts(), label="axe accessibility lane"),
                CommandSpec(("bun", "run", "--no-install", "test:no-network"), cwd_rel="apps/web", timeout_seconds=E2E_TIMEOUT_SECONDS, artifact_paths=web_artifacts(), label="no-network lane"),
            ),
            required_paths=web_required,
        ),
        GateSpec(
            "swift-parity",
            "swift",
            "Run the offline Swift parity package only when the candidate contains that package.",
            commands=(
                CommandSpec(("swift", "test"), cwd_rel="contracts/swift-parity", timeout_seconds=E2E_TIMEOUT_SECONDS, label="Swift parity tests"),
                CommandSpec(("swift", "run", "hermternal-swift-parity", "--repo-root", "../.."), cwd_rel="contracts/swift-parity", timeout_seconds=E2E_TIMEOUT_SECONDS, label="Swift parity fixture run"),
            ),
            required_paths=("contracts/swift-parity/Package.swift",),
            artifact_paths=("contracts/swift-parity/Package.swift",),
        ),
        GateSpec(
            "task-475-auth-click-enter",
            "authentication",
            "Run the existing no-JavaScript authentication activation test for native click and Enter paths.",
            commands=(
                CommandSpec(("bun", "x", "--no-install", "playwright", "test", "tests/e2e/ui-preview.spec.ts", "--grep", "native password activation clears live values"), cwd_rel="apps/web", timeout_seconds=E2E_TIMEOUT_SECONDS, artifact_paths=web_artifacts(), label="Task #475 click and Enter browser test"),
            ),
            required_paths=(*web_required, auth_spec),
        ),
        GateSpec(
            "task-475-auth-source-evidence",
            "authentication",
            "Fail-closed source handoff for immediate DOM retention and screenshot exclusion of entered credentials.",
            required_paths=(auth_spec,),
            artifact_paths=(auth_spec,),
            special="task475_source",
            planned_commands=(("manual-or-browser", "Task #475", "native-click-and-enter", "DOM-retention", "screenshot-content", "review"),),
        ),
        GateSpec(
            "graph-impact-review",
            "review",
            "Document graph update and read-only impact commands without mutating the coordinator graph.",
            planned_commands=(
                ("code-review-graph", "update", "--brief", "--repo", str(root), "--data-dir", "<disposable-graph-data>"),
                ("code-review-graph", "detect-changes", "--brief", "--repo", str(root)),
            ),
            skip_reason="Graph update mutates graph data and no disposable graph database was supplied to this offline runner.",
        ),
        GateSpec(
            "task-464-artifact-harness-handoff",
            "handoff",
            "Explicitly hand off production-build artifact evidence to the existing Task #464 harness.",
            planned_commands=(("bun", "x", "--no-install", "vitest", "run", "benchmarks/production-build/evidence.test.ts", "benchmarks/production-build/run.test.ts"),),
            skip_reason="Task #464 owns the artifact test harness; this runner records the handoff and does not duplicate it.",
        ),
        GateSpec(
            "paper-mcp-review-handoff",
            "handoff",
            "Paper MCP review remains a coordinator/user review step because this runner is offline-only.",
            planned_commands=(("paper-mcp", "inspect", "01KZ6BB66KCWR2C4J2TSWQGDM7", "auth-and-runtime-artboards"),),
            skip_reason="Paper MCP is network-backed and is intentionally not invoked in this offline run.",
        ),
    ]


def run_task475_source_gate(gate: GateSpec, root: Path, report_root: Path) -> GateResult:
    relative = gate.required_paths[0]
    path = safe_relative_path(root, relative)
    command = CommandSpec(("internal", "task-475-source-evidence"), label="Task #475 source evidence")
    if not path.is_file() or path.is_symlink():
        return GateResult(gate, "unavailable", [unavailable_command(command, root, "authentication browser spec is unavailable")], "authentication browser spec is unavailable")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return GateResult(gate, "failed", [unavailable_command(command, root, "authentication browser spec could not be read")], "authentication browser spec could not be read")

    checks: dict[str, bool] = {
        "native_click_and_enter": bool(re.search(r"['\"]click['\"].*['\"]enter['\"]", source, re.DOTALL)),
        "script_execution_disabled": "setScriptExecutionDisabled" in source,
        "username_cleared": source.count("toHaveValue('')") >= 1,
        "password_cleared": source.count("toHaveValue('')") >= 2,
        "dom_inaccessibility_scan": "outerHTML" in source and "querySelectorAll" in source and "JSON.stringify(liveDom)" in source,
        "screenshot_capture": "page.screenshot" in source,
        # A screenshot byte-length check alone is not enough.  Require a
        # marker-aware assertion over screenshot output for this handoff.
        "screenshot_content_excludes_username": bool(
            re.search(r"screenshot(?:Bytes|Buffer|Data)?[\\s\\S]{0,500}(?:usernameValue|visible-username)", source)
            and re.search(r"(?:usernameValue|visible-username)[\\s\\S]{0,500}not\\.toContain", source)
        ),
    }
    artifacts, artifact_error = artifact_records(root, gate.artifact_paths)
    missing = [name for name, present in checks.items() if not present]
    result = CommandResult(
        argv=list(command.argv),
        cwd=str(path.parent),
        status="passed" if not missing and not artifact_error else "failed",
        exit_code=0 if not missing and not artifact_error else 1,
        duration_ms=0.0,
        stdout_sha256=EMPTY_SHA256,
        stderr_sha256=EMPTY_SHA256,
        stdout_bytes=0,
        stderr_bytes=0,
        artifacts=artifacts,
        reason=None if not missing and not artifact_error else "required Task #475 source evidence is incomplete",
        label=command.label,
    )
    evidence: dict[str, Any] = {"checks": checks, "source_path": relative}
    if missing:
        evidence["missing_checks"] = missing
    if artifact_error:
        evidence["artifact_error"] = artifact_error
    return GateResult(gate, result.status, [result], result.reason, evidence)


def run_gate(gate: GateSpec, root: Path, report_root: Path) -> GateResult:
    if gate.special == "task475_source":
        return run_task475_source_gate(gate, root, report_root)
    if gate.skip_reason and not gate.commands:
        command = CommandSpec(gate.planned_commands[0] if gate.planned_commands else ("internal", gate.gate_id), label=gate.gate_id)
        return GateResult(gate, "skipped", [skipped_command(command, root, gate.skip_reason)], gate.skip_reason)

    missing = check_required_paths(root, gate.required_paths)
    if missing:
        reason = "required candidate paths unavailable: " + ", ".join(missing)
        commands = [unavailable_command(command, root, reason) for command in gate.commands]
        if not commands:
            commands = [unavailable_command(CommandSpec(("internal", gate.gate_id), label=gate.gate_id), root, reason)]
        return GateResult(gate, "unavailable", commands, reason)

    commands: list[CommandResult] = []
    for spec in gate.commands:
        result = run_command(spec, root, report_root, required_artifacts=gate.artifact_paths)
        # A clean-worktree command exits zero even when it reports untracked
        # files.  Convert that output into a fail-closed gate result without
        # retaining the paths in the report.
        if spec.label == "clean worktree check" and result.status == "passed" and result.stdout_bytes:
            result.status = "failed"
            result.reason = "candidate worktree is not clean; generated caches must not be committed"
        commands.append(result)
    status, reason = aggregate_status(commands)
    if gate.skip_reason and status == "passed":
        # The gate ran its owned focused checks.  The skip reason is retained as
        # a handoff note, not allowed to downgrade an actual pass.
        reason = gate.skip_reason
    return GateResult(gate, status, commands, reason)


def report_summary(gates: Sequence[GateResult]) -> dict[str, int]:
    summary = {"passed": 0, "failed": 0, "skipped": 0, "unavailable": 0}
    for gate in gates:
        summary[gate.status] = summary.get(gate.status, 0) + 1
    return summary


def write_report(root: Path, output: Path, gates: Sequence[GateResult], started_at: str, finished_at: str) -> tuple[Path, Path, str]:
    summary = report_summary(gates)
    overall = "failed" if summary["failed"] else "unavailable" if summary["unavailable"] else "passed"
    if summary["skipped"] and overall == "passed":
        overall = "skipped"
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "offline_only": True,
        "live_operations": False,
        "network_operations": False,
        "checkout_root": str(root),
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "overall_status": overall,
        "summary": summary,
        "mutation_policy": {
            "candidate_checkout_writes": False,
            "candidate_git_staging": False,
            "candidate_git_commits": False,
            "generated_cache_commits": False,
            "command_output_retained": False,
            "report_root": str(output.parent),
        },
        "limitations": [
            "Skipped and unavailable gates are not passes.",
            "Paper MCP review is documented but not run because this lane is offline-only.",
            "code-review-graph update is documented but not run because it mutates graph data; use a disposable graph data directory.",
            "Task #464 production-build artifact harness is referenced and not duplicated.",
            "Task #475 remains fail-closed until screenshot bytes are checked for the entered username in addition to click/Enter DOM clearing.",
        ],
        "gates": [gate.as_dict() for gate in gates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = sha256_file(output)[0]
    sidecar = output.with_name(output.name + ".sha256")
    sidecar.write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    return output, sidecar, digest


def run(checkout_root: Path, output: Path) -> tuple[Path, Path, str, dict[str, int]]:
    root = normalize_checkout(checkout_root)
    output = normalize_output_path(output)
    if is_within(output, root):
        raise ValueError("--output must be outside --checkout-root so the candidate remains unchanged")
    output.parent.mkdir(parents=True, exist_ok=True)
    report_root = output.parent / (output.stem + ".work")
    report_root.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    gates = [run_gate(gate, root, report_root) for gate in build_plan(root)]
    finished_at = utc_now()
    report_path, sidecar, digest = write_report(root, output, gates, started_at, finished_at)
    return report_path, sidecar, digest, report_summary(gates)


def print_plan(root: Path) -> None:
    for gate in build_plan(root):
        print(json.dumps({
            "id": gate.gate_id,
            "category": gate.category,
            "description": gate.description,
            "commands": [list(command.argv) for command in gate.commands],
            "cwd": [command.cwd_rel for command in gate.commands],
            "required_paths": list(gate.required_paths),
            "planned_commands": [list(command) for command in gate.planned_commands],
        }, sort_keys=True))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run offline post-replay gates against an isolated checkout")
    parser.add_argument("--checkout-root", type=Path, required=True, help="absolute isolated replay checkout")
    parser.add_argument("--output", type=Path, required=True, help="absolute JSON report path outside the checkout")
    parser.add_argument("--plan-only", action="store_true", help="print the deterministic gate plan without running commands")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        root = normalize_checkout(args.checkout_root)
        output = normalize_output_path(args.output)
        if args.plan_only:
            print_plan(root)
            return 0
        report, sidecar, digest, summary = run(root, output)
        print(json.dumps({
            "report": str(report),
            "report_sha256": digest,
            "sha256_sidecar": str(sidecar),
            "summary": summary,
        }, sort_keys=True))
        return 0 if summary["failed"] == 0 and summary["unavailable"] == 0 else 2
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema": SCHEMA, "status": "failed", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
