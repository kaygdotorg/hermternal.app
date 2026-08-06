#!/usr/bin/env python3
"""Supervise the complete build descendant tree inside the OS sandbox.

The TypeScript parent starts the fixed sandbox executable first. Only then does
an absolute isolated Python interpreter import and execute this reviewed helper.
The helper continuously records descendants, including processes that call
setsid(), and reaps every recorded process before it returns.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


TERMINATION_GRACE_SECONDS = 0.5
TRACK_INTERVAL_SECONDS = 0.02
_stop_signal: int | None = None


def fail() -> "None":
    raise SystemExit(126)


def _signal_handler(signum: int, _frame: object) -> None:
    global _stop_signal
    _stop_signal = signum


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
        # Darwin versions have returned either a PID count or a byte count for
        # the sizing call. Over-allocation is bounded and handles both forms.
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
                fields = Path(f"/proc/{entry}/stat").read_text(encoding="ascii").split()
                if len(fields) > 3 and int(fields[3]) == parent_pid:
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


def _terminate_tracked(root_pid: int, tracked: set[int]) -> None:
    tracked.update(_descendants(root_pid))
    targets = {pid for pid in tracked if _alive(pid)}
    _signal_all(targets, signal.SIGTERM)
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        tracked.update(_descendants(root_pid))
        targets = {pid for pid in tracked if _alive(pid)}
        if not targets:
            return
        time.sleep(TRACK_INTERVAL_SECONDS)
    _signal_all({pid for pid in tracked if _alive(pid)}, signal.SIGKILL)
    force_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    while time.monotonic() < force_deadline and any(_alive(pid) for pid in tracked):
        time.sleep(TRACK_INTERVAL_SECONDS)
    if any(_alive(pid) for pid in tracked):
        fail()


def _write_result(path: Path, exit_code: int, duration_us: int) -> None:
    payload = json.dumps(
        {"exit_code": exit_code, "duration_us": duration_us},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    temporary = path.with_name("result.tmp")
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    if not command or not all(isinstance(item, str) and item for item in command):
        fail()

    workspace = Path(arguments.workspace).resolve(strict=True)
    result = Path(arguments.result)
    result_parent = result.parent.resolve(strict=True)
    if result_parent != (workspace / ".supervisor").resolve(strict=True):
        fail()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    started_ns = time.monotonic_ns()
    child = subprocess.Popen(
        command,
        cwd=workspace,
        env=os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=None,
        start_new_session=True,
        close_fds=True,
    )
    tracked = {child.pid}
    exit_code: int | None = None
    try:
        while exit_code is None and _stop_signal is None:
            tracked.update(_descendants(os.getpid()))
            exit_code = child.poll()
            if exit_code is None:
                time.sleep(TRACK_INTERVAL_SECONDS)
        duration_us = max(1, (time.monotonic_ns() - started_ns) // 1000)
        if _stop_signal is not None:
            _terminate_tracked(os.getpid(), tracked)
            try:
                child.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                fail()
            return 128 + _stop_signal
        assert exit_code is not None
        _terminate_tracked(os.getpid(), tracked)
        _write_result(result, exit_code, duration_us)
        return exit_code if 0 <= exit_code <= 125 else 125
    finally:
        if child.poll() is None:
            _terminate_tracked(os.getpid(), tracked)
            try:
                child.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass


if __name__ == "__main__":
    sys.exit(main())
