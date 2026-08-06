#!/usr/bin/env python3
"""Measure benchmark artifacts without following attacker-replaceable paths.

Every descendant is opened relative to an already-open directory descriptor with
O_NOFOLLOW. This keeps validation and hashing on one inode chain even if a path
is replaced concurrently, and prevents an external symlink target from being
read before the scanner rejects it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import time
from pathlib import PurePosixPath


def fail() -> "None":
    raise SystemExit(2)


def open_directory(name: str, parent_fd: int | None = None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError:
        fail()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--max-files", required=True, type=int)
    parser.add_argument("--max-bytes", required=True, type=int)
    parser.add_argument("--test-pause-ms", type=int, default=0)
    parser.add_argument("--test-ready-file")
    arguments = parser.parse_args()
    if (arguments.test_pause_ms or arguments.test_ready_file) and (
        os.environ.get("HERMTERNAL_SCANNER_TEST_MODE") != "1"
        or not 1 <= arguments.test_pause_ms <= 1000
        or not arguments.test_ready_file
    ):
        fail()
    root_parts = PurePosixPath(arguments.root).parts
    if not root_parts or arguments.root.startswith("/") or any(part in {"", ".", ".."} for part in root_parts):
        fail()

    descriptors: list[int] = []
    records: list[dict[str, object]] = []
    files = 0
    byte_count = 0
    try:
        current = open_directory(arguments.workspace)
        descriptors.append(current)
        for part in root_parts:
            current = open_directory(part, current)
            descriptors.append(current)
        root_fd = current

        def visit(directory_fd: int, prefix: str) -> None:
            nonlocal files, byte_count
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError:
                fail()
            for name in names:
                if "/" in name or name in {"", ".", ".."}:
                    fail()
                relative = f"{prefix}/{name}" if prefix else name
                try:
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    fail()
                if stat.S_ISLNK(metadata.st_mode):
                    fail()
                if stat.S_ISDIR(metadata.st_mode):
                    child_fd = open_directory(name, directory_fd)
                    descriptors.append(child_fd)
                    visit(child_fd, relative)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    fail()
                try:
                    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    descriptors.append(file_fd)
                    opened = os.fstat(file_fd)
                except OSError:
                    fail()
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    fail()
                if arguments.test_pause_ms:
                    try:
                        ready_fd = os.open(arguments.test_ready_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        os.close(ready_fd)
                    except OSError:
                        fail()
                    time.sleep(arguments.test_pause_ms / 1000)
                files += 1
                remaining_budget = arguments.max_bytes - byte_count
                extent = opened.st_size
                if files > arguments.max_files or extent < 0 or extent > remaining_budget:
                    fail()
                digest = hashlib.sha256()
                hashed_bytes = 0
                while hashed_bytes < extent:
                    # Read only the reviewed stable extent. EOF before the extent
                    # proves shrinkage; one bounded byte after it proves growth.
                    chunk = os.read(file_fd, min(65536, extent - hashed_bytes))
                    if not chunk:
                        fail()
                    hashed_bytes += len(chunk)
                    digest.update(chunk)
                if os.read(file_fd, 1):
                    fail()
                try:
                    final_opened = os.fstat(file_fd)
                    final_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    fail()
                stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(getattr(opened, field) != getattr(final_opened, field) for field in stable_fields):
                    fail()
                if any(getattr(final_opened, field) != getattr(final_path, field) for field in stable_fields):
                    fail()
                if hashed_bytes != extent:
                    fail()
                byte_count += hashed_bytes
                records.append({"path": relative, "bytes": hashed_bytes, "sha256": digest.hexdigest()})

        visit(root_fd, "")
        payload = json.dumps(records, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        result = {
            "files": files,
            "bytes": byte_count,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
