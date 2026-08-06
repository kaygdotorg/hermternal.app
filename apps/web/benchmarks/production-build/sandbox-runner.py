#!/usr/bin/env python3
"""Enter the reviewed OS sandbox, then replace this process with the build.

The parent creates a dedicated process group before invoking this helper.  Both
macOS sandbox-exec and Linux bubblewrap keep every descendant inside the same
no-network boundary even if a child clears environment variables or bypasses
Node module helpers.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
from pathlib import Path


def fail(_message: str) -> "None":
    # The TypeScript parent emits the bounded public error code. Keep sandbox
    # diagnostics silent so paths and host details cannot enter evidence logs.
    raise SystemExit(126)


def contained_path(raw: str, root: Path) -> Path:
    candidate = Path(raw).resolve(strict=True)
    if candidate != root and root not in candidate.parents:
        fail("path outside reviewed root")
    return candidate


def macos_command(workspace: Path, dependency_root: Path, command: list[str]) -> list[str]:
    sandbox = Path("/usr/bin/sandbox-exec")
    if not sandbox.is_file():
        fail("sandbox unavailable")
    writable = [workspace / ".svelte-kit", workspace / ".artifact-output", workspace / ".home", workspace / ".tmp", workspace / "node_modules" / ".vite-temp"]
    rules = ["(version 1)", "(allow default)", "(deny network*)", "(deny file-write*)"]
    for path in writable:
        rules.append(f'(allow file-write* (subpath "{str(path).replace(chr(34), "")}"))')
    rules.append('(allow file-write* (literal "/dev/null"))')
    rules.append(f'(deny file-write* (subpath "{str(dependency_root).replace(chr(34), "")}"))')
    return [str(sandbox), "-p", "".join(rules), *command]


def linux_command(workspace: Path, dependency_root: Path, artifact_bytes: int, command: list[str]) -> list[str]:
    bubblewrap = shutil.which("bwrap")
    if bubblewrap is None:
        fail("bubblewrap unavailable")
    # The host tree is read-only. Only build state, the quota-backed output
    # tmpfs, HOME, and TMPDIR are writable. --unshare-net applies to the entire
    # namespace and --die-with-parent prevents an orphaned namespace monitor.
    return [
        bubblewrap,
        "--die-with-parent",
        "--unshare-net",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(workspace / ".svelte-kit"),
        str(workspace / ".svelte-kit"),
        "--size",
        str(artifact_bytes),
        "--tmpfs",
        str(workspace / ".artifact-output"),
        "--bind",
        str(workspace / ".home"),
        str(workspace / ".home"),
        "--bind",
        str(workspace / ".tmp"),
        str(workspace / ".tmp"),
        "--bind",
        str(workspace / "node_modules" / ".vite-temp"),
        str(workspace / "node_modules" / ".vite-temp"),
        "--ro-bind",
        str(dependency_root),
        str(dependency_root),
        "--",
        *command,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--dependency-root", required=True)
    parser.add_argument("--artifact-bytes", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        fail("command empty")
    workspace = Path(arguments.workspace).resolve(strict=True)
    dependency_root = Path(arguments.dependency_root).resolve(strict=True)
    contained_path(str(workspace / ".svelte-kit"), workspace)
    build_root = workspace / ".artifact-output"
    if build_root.is_symlink() or not build_root.is_dir():
        fail("artifact root invalid")
    contained_path(str(workspace / ".home"), workspace)
    contained_path(str(workspace / ".tmp"), workspace)
    contained_path(str(workspace / "node_modules" / ".vite-temp"), workspace)
    system = platform.system()
    if system == "Darwin":
        sandboxed = macos_command(workspace, dependency_root, command)
    elif system == "Linux":
        sandboxed = linux_command(workspace, dependency_root, arguments.artifact_bytes, command)
    else:
        fail("platform unsupported")
    os.execve(sandboxed[0], sandboxed, os.environ.copy())
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
