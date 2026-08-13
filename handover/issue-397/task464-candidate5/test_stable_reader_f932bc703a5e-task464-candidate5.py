#!/usr/bin/env python3
"""Deterministic bounded-reader regressions for the private candidate5 generator."""

import ast
import hashlib
import importlib.util
import os
import stat
import sys
import tempfile
from pathlib import Path


BASE = Path(__file__).resolve().parent
GENERATOR = BASE / "f932bc703a5e-task464-candidate5-generator.py"
SOURCE_MARKDOWN = Path("/private/tmp/task464-working-input.md")
EXPECTED_GENERATOR_SHA256 = "600f4e9f4b75a5a4ded039fb6ae0e8f5778854147f15ec8190fef87fab1a7102"
HEREDOC_MARKER = "<<'PY'\n"


def load_generator():
    with GENERATOR.open("rb") as handle:
        actual = hashlib.sha256(handle.read()).hexdigest()
    assert actual == EXPECTED_GENERATOR_SHA256, (actual, EXPECTED_GENERATOR_SHA256)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("candidate5_generator_stable_reader", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def emitted_heredocs(shell):
    bodies = []
    position = 0
    while True:
        start = shell.find(HEREDOC_MARKER, position)
        if start < 0:
            return bodies
        body_start = start + len(HEREDOC_MARKER)
        end = shell.find("\nPY", body_start)
        assert end >= 0, "unterminated emitted Python heredoc"
        bodies.append(shell[body_start:end])
        position = end + len("\nPY")


def expect_rejection(reader, path, limit):
    try:
        reader(path, "focused regression", limit=limit)
    except (RuntimeError, SystemExit, OSError) as exc:
        return str(exc)
    raise AssertionError("reader accepted bytes that should have been rejected")


def write_fixture(root, name, data):
    path = root / name
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def same_size_overwrite_rejection(reader, root, name):
    original = b"stable-original-bytes\n"
    replacement = b"same-size-replacement\n"
    assert len(original) == len(replacement)
    path = write_fixture(root, name, original)
    original_read = os.read
    original_fstat = os.fstat
    original_stat = os.stat
    state = {"target": None, "parent": None, "snapshot": None, "mutated": False}

    def hooked_fstat(fd):
        actual = original_fstat(fd)
        if stat.S_ISDIR(actual.st_mode):
            state["parent"] = fd
        elif state["target"] is None and stat.S_ISREG(actual.st_mode):
            state["target"] = fd
            state["snapshot"] = actual
            return actual
        if fd == state["target"]:
            return state["snapshot"]
        return actual

    def hooked_stat(value, *args, **kwargs):
        if (
            state["mutated"]
            and value == path.name
            and kwargs.get("dir_fd") == state["parent"]
        ):
            return state["snapshot"]
        return original_stat(value, *args, **kwargs)

    def hooked_read(fd, size):
        chunk = original_read(fd, size)
        if fd == state["target"] and not state["mutated"] and chunk == b"":
            writer = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
            try:
                assert os.pwrite(writer, replacement, 0) == len(replacement)
                os.fsync(writer)
            finally:
                os.close(writer)
            state["mutated"] = True
        return chunk

    os.fstat = hooked_fstat
    os.stat = hooked_stat
    os.read = hooked_read
    try:
        message = expect_rejection(reader, path, len(original))
    finally:
        os.read = original_read
        os.fstat = original_fstat
        os.stat = original_stat
    assert state["mutated"], "the deterministic overwrite barrier did not run"
    assert "bytes changed" in message, message


def oversized_stat_rejection(reader, root, name):
    path = write_fixture(root, name, b"012345678")
    original_read = os.read
    calls = []

    def forbidden_read(fd, size):
        calls.append(size)
        raise AssertionError("oversized stat must reject before os.read")

    os.read = forbidden_read
    try:
        message = expect_rejection(reader, path, 8)
    finally:
        os.read = original_read
    assert not calls, calls
    assert "bounded read limit" in message, message


def sentinel_rejection(reader, root, name):
    path = write_fixture(root, name, b"12345678")
    original_read = os.read
    calls = []

    def one_byte_over_limit(fd, size):
        calls.append(size)
        return b"X" * (size + 1)

    os.read = one_byte_over_limit
    try:
        message = expect_rejection(reader, path, 8)
    finally:
        os.read = original_read
    assert calls == [9], calls
    assert max(calls) == 9, calls
    assert "bounded read limit" in message, message


def size_mutation_rejection(reader, root, name, kind):
    original = b"size-boundary-original\n"
    path = write_fixture(root, name, original)
    original_read = os.read
    original_fstat = os.fstat
    original_stat = os.stat
    state = {"target": None, "parent": None, "snapshot": None, "mutated": False}

    def hooked_fstat(fd):
        actual = original_fstat(fd)
        if stat.S_ISDIR(actual.st_mode):
            state["parent"] = fd
        elif state["target"] is None and stat.S_ISREG(actual.st_mode):
            state["target"] = fd
            state["snapshot"] = actual
            return actual
        if fd == state["target"]:
            return state["snapshot"]
        return actual

    def hooked_stat(value, *args, **kwargs):
        if (
            state["mutated"]
            and value == path.name
            and kwargs.get("dir_fd") == state["parent"]
        ):
            return state["snapshot"]
        return original_stat(value, *args, **kwargs)

    def hooked_read(fd, size):
        chunk = original_read(fd, size)
        if fd == state["target"] and not state["mutated"] and chunk == b"":
            writer = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
            try:
                if kind == "truncation":
                    os.ftruncate(writer, len(original) // 2)
                elif kind == "append":
                    os.lseek(writer, 0, os.SEEK_END)
                    os.write(writer, b"++")
                else:
                    raise AssertionError(kind)
                os.fsync(writer)
            finally:
                os.close(writer)
            state["mutated"] = True
        return chunk

    os.fstat = hooked_fstat
    os.stat = hooked_stat
    os.read = hooked_read
    try:
        message = expect_rejection(reader, path, 1024)
    finally:
        os.read = original_read
        os.fstat = original_fstat
        os.stat = original_stat
    assert state["mutated"], kind
    assert "changed" in message or "byte count" in message, message


def path_swap_rejection(reader, root, name, kind):
    original = b"bound-before-swap\n"
    replacement = b"replacement-after\n"
    assert len(original) == len(replacement)
    if kind.startswith("child"):
        parent = root
        path = write_fixture(root, name, original)
        binding_name = None
    else:
        parent = root / (name + "-parent")
        parent.mkdir(mode=0o700)
        path = write_fixture(parent, "input", original)
        binding_name = parent.name
    original_stat = os.stat
    original_lstat = os.lstat
    state = {"counts": {}, "swapped": False}

    def swap_once(value, *args, **kwargs):
        dir_fd = kwargs.get("dir_fd")
        follow = kwargs.get("follow_symlinks")
        key = (value, dir_fd, follow)
        state["counts"][key] = state["counts"].get(key, 0) + 1
        is_child_binding = value == path.name and dir_fd is not None and follow is False
        is_parent_binding = value == binding_name and dir_fd is not None and follow is False
        if not state["swapped"] and ((is_child_binding and state["counts"][key] == 2) or (is_parent_binding and state["counts"][key] == 2)):
            state["swapped"] = True
            if kind == "child-rename":
                path.rename(parent / (path.name + "-moved"))
                write_fixture(parent, path.name, replacement)
            elif kind == "child-replacement":
                path.unlink()
                write_fixture(parent, path.name, replacement)
            elif kind == "parent-rename":
                moved = parent.with_name(parent.name + "-moved")
                parent.rename(moved)
                parent.mkdir(mode=0o700)
                write_fixture(parent, path.name, replacement)
            elif kind == "parent-replacement":
                moved = parent.with_name(parent.name + "-replaced")
                parent.rename(moved)
                parent.mkdir(mode=0o700)
                write_fixture(parent, path.name, replacement)
            else:
                raise AssertionError(kind)
        return original_stat(value, *args, **kwargs)

    os.stat = swap_once
    try:
        message = expect_rejection(reader, path, len(original))
    finally:
        os.stat = original_stat
    assert state["swapped"], (kind, state)
    assert message, kind


def special_file_rejection(reader, root, name, kind):
    path = root / name
    if kind == "symlink":
        target = write_fixture(root, name + "-target", b"target\n")
        os.symlink(target, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        raise AssertionError(kind)
    message = expect_rejection(reader, path, 1024)
    assert "regular" in message or "canonical" in message, message


def metadata_mutation_rejection(reader, root, name, kind):
    path = write_fixture(root, name, b"metadata-stable\n")
    original_read = os.read
    original_fstat = os.fstat
    state = {"target": None, "mutated": False}

    def hooked_fstat(fd):
        actual = original_fstat(fd)
        if stat.S_ISREG(actual.st_mode) and state["target"] is None:
            state["target"] = fd
        return actual

    def hooked_read(fd, size):
        chunk = original_read(fd, size)
        if fd == state["target"] and not state["mutated"] and chunk == b"":
            if kind == "chmod":
                os.fchmod(fd, 0o644)
            elif kind == "utime":
                os.utime(path, ns=(1, 2), follow_symlinks=False)
            else:
                raise AssertionError(kind)
            state["mutated"] = True
        return chunk

    os.fstat = hooked_fstat
    os.read = hooked_read
    try:
        message = expect_rejection(reader, path, 1024)
    finally:
        os.read = original_read
        os.fstat = original_fstat
    assert state["mutated"], kind
    assert "changed" in message, message


def hardlink_rejection(reader, root, name):
    path = write_fixture(root, name, b"single-link-policy\n")
    alias = root / (name + "-alias")
    os.link(path, alias)
    message = expect_rejection(reader, path, 1024)
    assert "regular" in message or "single-link" in message, message


def main():
    generator = load_generator()
    namespace = {"os": os, "stat": stat}
    exec(compile(generator.STABLE_READER, "<emitted-STABLE_READER>", "exec"), namespace)
    emitted_reader = namespace["read_stable_file"]

    stable_source = generator.STABLE_READER
    generator_source = generator.read_generator_file.__code__
    assert "read_bytes" not in stable_source
    assert "read_bytes" not in generator.read_generator_file.__code__.co_names
    assert generator_source.co_name == "read_generator_file"

    markdown = SOURCE_MARKDOWN.read_bytes()
    shell = generator.patch_shell(
        generator.extract_fenced(
            markdown,
            "## Canonical machine-readable ordered execution driver\n",
            "```bash\n",
            "stable-reader heredoc regression source",
        ).decode("utf-8")
    )
    bodies = emitted_heredocs(shell)
    assert len(bodies) == 41, len(bodies)
    for index, body in enumerate(bodies, 1):
        tree = ast.parse(body, filename=f"<candidate5-heredoc-{index}>")
        compile(tree, f"<candidate5-heredoc-{index}>", "exec")

    with tempfile.TemporaryDirectory(dir=str(BASE), prefix="stable-reader-regression-") as temporary:
        root = Path(temporary).resolve()
        same_size_overwrite_rejection(emitted_reader, root, "stable-overwrite")
        same_size_overwrite_rejection(generator.read_generator_file, root, "generator-overwrite")
        oversized_stat_rejection(emitted_reader, root, "stable-oversized-stat")
        oversized_stat_rejection(generator.read_generator_file, root, "generator-oversized-stat")
        sentinel_rejection(emitted_reader, root, "stable-sentinel")
        sentinel_rejection(generator.read_generator_file, root, "generator-sentinel")
        for reader, prefix in ((emitted_reader, "stable"), (generator.read_generator_file, "generator")):
            for kind in ("child-rename", "child-replacement", "parent-rename", "parent-replacement"):
                path_swap_rejection(reader, root, f"{prefix}-{kind}", kind)
            for kind in ("truncation", "append"):
                size_mutation_rejection(reader, root, f"{prefix}-{kind}", kind)
            for kind in ("symlink", "fifo"):
                special_file_rejection(reader, root, f"{prefix}-{kind}", kind)
            for kind in ("chmod", "utime"):
                metadata_mutation_rejection(reader, root, f"{prefix}-{kind}", kind)
            hardlink_rejection(reader, root, f"{prefix}-hardlink")

    print("stable-reader regressions passed; heredocs=41; overwrite=2; bounded=4; swaps=8; special=4; metadata=4; hardlink=2")


if __name__ == "__main__":
    main()
