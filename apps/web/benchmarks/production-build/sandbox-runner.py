#!/usr/bin/env python3
"""Supervise the complete build lifecycle inside the OS sandbox.

The TypeScript parent starts the fixed sandbox executable first. Only then does
an absolute isolated Python interpreter execute this reviewed helper. Linux runs
this supervisor as PID 1 so orphan adoption is atomic. The outer macOS Seatbelt
profile denies forks when the measured Node executable is the caller, which
removes the polling gap that otherwise exists after a fast spawn-and-exit.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path


TERMINATION_GRACE_SECONDS = 0.5
TRACK_INTERVAL_SECONDS = 0.02
_stop_signal: int | None = None
_timed_out = False


def fail() -> "None":
    raise SystemExit(126)


def _signal_handler(signum: int, _frame: object) -> None:
    global _stop_signal
    _stop_signal = signum


def _linux_parent_pid(stat_line: str) -> int:
    """Extract ppid after Linux's variable-width comm field.

    `/proc/<pid>/stat` permits spaces and right parentheses inside `comm`, so
    positional splitting from the beginning can mistake those bytes for the
    state and parent fields. The final `)` terminates `comm`; the suffix starts
    with state and then ppid.
    """

    closing = stat_line.rfind(")")
    if closing < 0:
        raise ValueError("malformed proc stat")
    suffix = stat_line[closing + 1 :].split()
    if len(suffix) < 2:
        raise ValueError("malformed proc stat")
    return int(suffix[1])


def _children(parent_pid: int) -> set[int]:
    """Read direct children without executing PATH or set-id process tools."""

    if sys.platform == "darwin":
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_children = libproc.proc_listchildpids
        list_children.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        list_children.restype = ctypes.c_int
        required = list_children(parent_pid, None, 0)
        if required <= 0:
            return set()
        capacity = min(max(required, 16), 65536)
        buffer = (ctypes.c_int * capacity)()
        found = list_children(parent_pid, buffer, ctypes.sizeof(buffer))
        if found < 0:
            fail()
        return {pid for pid in buffer[: min(found, capacity)] if pid > 0}
    if sys.platform.startswith("linux"):
        result: set[int] = set()
        try:
            entries = os.listdir("/proc")
        except OSError:
            fail()
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                stat_line = Path(f"/proc/{entry}/stat").read_text(encoding="ascii")
                if _linux_parent_pid(stat_line) == parent_pid:
                    result.add(int(entry))
            except (OSError, ValueError, UnicodeError):
                continue
        return result
    fail()


def _descendants(root_pid: int) -> set[int]:
    result: set[int] = set()
    frontier = {root_pid}
    while frontier:
        children: set[int] = set()
        for parent in frontier:
            children.update(_children(parent))
        children.difference_update(result)
        if not children:
            break
        result.update(children)
        frontier = children
    return result


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_all(pids: set[int], signum: int) -> None:
    for pid in sorted(pids, reverse=True):
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass
        except PermissionError:
            fail()


def _reap_adopted() -> None:
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid <= 0:
            return


def _terminate_tracked(root_pid: int, tracked: set[int]) -> None:
    tracked.update(_descendants(root_pid))
    targets = {pid for pid in tracked if _alive(pid)}
    _signal_all(targets, signal.SIGTERM)
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        tracked.update(_descendants(root_pid))
        targets = {pid for pid in tracked if _alive(pid)}
        if not targets:
            _reap_adopted()
            return
        time.sleep(TRACK_INTERVAL_SECONDS)
    _signal_all({pid for pid in tracked if _alive(pid)}, signal.SIGKILL)
    force_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while time.monotonic() < force_deadline:
        _reap_adopted()
        tracked.update(_descendants(root_pid))
        if not any(_alive(pid) for pid in tracked):
            return
        time.sleep(TRACK_INTERVAL_SECONDS)
    if any(_alive(pid) for pid in tracked):
        fail()


def _scan(arguments: argparse.Namespace) -> dict[str, object]:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            arguments.scanner,
            "--workspace",
            arguments.workspace,
            "--root",
            arguments.artifact_root,
            "--max-files",
            str(arguments.max_files),
            "--max-bytes",
            str(arguments.max_bytes),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > 1024:
        fail()
    try:
        result = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        fail()
    if not isinstance(result, dict) or set(result) != {"files", "bytes", "sha256"}:
        fail()
    return result


def _forward_output(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            fail()
        view = view[written:]


def _write_results(fd: int, payloads: list[dict[str, object]]) -> None:
    encoded = b"".join(
        b"HERMTERNAL_RESULT " + json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        for payload in payloads
    )
    view = memoryview(encoded)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            fail()
        view = view[written:]
    os.close(fd)


def _run_once(arguments: argparse.Namespace, command: list[str]) -> dict[str, object] | None:
    global _timed_out
    started_ns = time.monotonic_ns()
    deadline_ns = started_ns + arguments.timeout_ms * 1_000_000
    child = subprocess.Popen(
        command,
        cwd=arguments.workspace,
        env=os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        pass_fds=(),
    )
    tracked = {child.pid}
    output_selector = selectors.DefaultSelector()
    assert child.stdout is not None and child.stderr is not None
    output_selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    output_selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    output_bytes = {"stdout": 0, "stderr": 0}
    output_limited = False
    exit_code: int | None = None
    try:
        while exit_code is None and _stop_signal is None:
            for key, _events in output_selector.select(TRACK_INTERVAL_SECONDS):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    output_selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                stream = key.data
                output_bytes[stream] += len(chunk)
                try:
                    _forward_output(1 if stream == "stdout" else 2, chunk)
                except BrokenPipeError:
                    fail()
                if output_bytes[stream] > getattr(arguments, f"max_{stream}"):
                    output_limited = True
            tracked.update(_descendants(os.getpid()))
            exit_code = child.poll()
            if exit_code is None and time.monotonic_ns() >= deadline_ns:
                _timed_out = True
                _terminate_tracked(os.getpid(), tracked)
                try:
                    child.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    fail()
                return None
            if output_limited:
                _terminate_tracked(os.getpid(), tracked)
                try:
                    child.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    fail()
                return None
        duration_us = max(1, (time.monotonic_ns() - started_ns) // 1000)
        if _stop_signal is not None:
            _terminate_tracked(os.getpid(), tracked)
            try:
                child.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                fail()
            return None
        assert exit_code is not None
        _terminate_tracked(os.getpid(), tracked)
        while output_selector.get_map():
            for key, _events in output_selector.select(TRACK_INTERVAL_SECONDS):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    output_selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                stream = key.data
                output_bytes[stream] += len(chunk)
                try:
                    _forward_output(1 if stream == "stdout" else 2, chunk)
                except BrokenPipeError:
                    fail()
                if output_bytes[stream] > getattr(arguments, f"max_{stream}"):
                    output_limited = True
        if output_limited or exit_code != 0:
            return None
        if arguments.result_fd < 0:
            # Probe-only callers still need the lifecycle and output limits, but
            # do not request an artifact scan or authenticated result line.
            return {
                "exit_code": exit_code,
                "duration_us": duration_us,
                "stdout_bytes": output_bytes["stdout"],
                "stderr_bytes": output_bytes["stderr"],
                "artifact_files": 0,
                "artifact_bytes": 0,
                "artifact_sha256": "0" * 64,
            }
        artifact = _scan(arguments)
        return {
            "exit_code": exit_code,
            "duration_us": duration_us,
            "stdout_bytes": output_bytes["stdout"],
            "stderr_bytes": output_bytes["stderr"],
            "artifact_files": artifact["files"],
            "artifact_bytes": artifact["bytes"],
            "artifact_sha256": artifact["sha256"],
        }
    finally:
        output_selector.close()
        if child.poll() is None:
            _terminate_tracked(os.getpid(), tracked)
            try:
                child.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
        _reap_adopted()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--result-fd", required=True, type=int)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--max-files", required=True, type=int)
    parser.add_argument("--max-bytes", required=True, type=int)
    parser.add_argument("--max-stdout", required=True, type=int)
    parser.add_argument("--max-stderr", required=True, type=int)
    parser.add_argument("--timeout-ms", required=True, type=int)
    parser.add_argument("--repetitions", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    if not command or not all(isinstance(item, str) and item for item in command):
        fail()
    if (
        arguments.repetitions < 1
        or arguments.repetitions > 100
        or arguments.max_stdout <= 0
        or arguments.max_stderr <= 0
        or arguments.timeout_ms <= 0
    ):
        fail()

    workspace = Path(arguments.workspace).resolve(strict=True)
    scanner = Path(arguments.scanner).resolve(strict=True)
    if not scanner.is_file() or arguments.max_files <= 0 or arguments.max_bytes <= 0:
        fail()
    arguments.workspace = str(workspace)
    arguments.scanner = str(scanner)
    # Linux mounts an empty quota tmpfs over this path after workspace setup.
    # Recreate every writable runtime directory inside the active quota boundary.
    for relative in (".home", ".tmp", ".svelte-kit", ".vite-temp"):
        (workspace / ".artifact-output" / relative).mkdir(parents=True, exist_ok=True)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    results: list[dict[str, object]] = []
    for _ in range(arguments.repetitions):
        result = _run_once(arguments, command)
        if _stop_signal is not None:
            return 128 + _stop_signal
        if result is None:
            return 124 if _timed_out else 125
        results.append(result)
    if arguments.result_fd >= 0:
        _write_results(arguments.result_fd, results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
