#!/usr/bin/env python3
"""Provision exact fixture-authority objects from the checked-in bundle.

This module is test infrastructure only. A fresh single-head clone can omit
reviewed authority objects that are not reachable from its branch, while a
linked worktree or local alternates can make missing objects appear present.
The repository-versioned bundle is the explicit offline input for the
standalone authority suite.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import zlib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TRUSTED_BUNDLE_PATH = REPO_ROOT / "scripts" / "fixture_registry_authority.objects.bundle"
TRUSTED_BUNDLE_SIZE_BYTES = 5_939_513
TRUSTED_BUNDLE_SHA256 = "da68bbf816f60c3d8c898830231cc7a8b08ed68937e1efda7e6d53306aabba64"

# Keep the historical bootstrap and legacy trust roots separate from the
# active hardened predecessor. The bundle advertises exactly these four refs;
# callers must never infer a replacement from HEAD, a tag, or local alternates.
PROTECTED_OBJECTS = (
    ("bootstrap-authority", "f92f339cf26c1da760e99af6508dfabfb6bfb383"),
    ("bootstrap-source", "abb6754bddd1cf18927b0172ed9fa3456235b035"),
    ("hardened-authority", "8bf435b69c67b49b2a7e9ba503fa237c63a0fbd9"),
    ("hardened-source", "5919c41473cfd6eda9647647c30ff15ab4aa5134"),
)
EXPECTED_BUNDLE_REFS = {
    f"refs/fixture-authority/{name}": commit for name, commit in PROTECTED_OBJECTS
}


def _run_git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def _require_bundle_bytes() -> None:
    metadata = os.lstat(TRUSTED_BUNDLE_PATH)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AssertionError("fixture authority bundle is not a regular file")
    if metadata.st_size != TRUSTED_BUNDLE_SIZE_BYTES:
        raise AssertionError("fixture authority bundle size changed")
    digest = hashlib.sha256(TRUSTED_BUNDLE_PATH.read_bytes()).hexdigest()
    if digest != TRUSTED_BUNDLE_SHA256:
        raise AssertionError("fixture authority bundle digest changed")


def verify_trusted_bundle() -> None:
    """Require a complete bundle with exactly the four pinned commit refs."""

    _require_bundle_bytes()
    verified = _run_git("bundle", "verify", str(TRUSTED_BUNDLE_PATH))
    if verified.returncode != 0:
        raise AssertionError(verified.stderr or verified.stdout)
    listed = _run_git("bundle", "list-heads", str(TRUSTED_BUNDLE_PATH))
    if listed.returncode != 0:
        raise AssertionError(listed.stderr or listed.stdout)
    heads: dict[str, str] = {}
    for line in listed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise AssertionError("fixture authority bundle ref listing changed")
        commit, ref = fields
        if ref in heads or not commit.isascii() or len(commit) != 40:
            raise AssertionError("fixture authority bundle ref listing changed")
        heads[ref] = commit
    if heads != EXPECTED_BUNDLE_REFS:
        raise AssertionError("fixture authority bundle refs changed")


def _git_output(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return completed.stdout


def _reachable_object_rows(repository: Path) -> list[tuple[str, str, int]]:
    """Return the exact object closure reachable from the staged fixture refs."""

    listed = _git_output(repository, "rev-list", "--objects", "--all")
    object_ids: list[str] = []
    for line in listed.splitlines():
        fields = line.split()
        if len(fields) not in {1, 2}:
            raise AssertionError("staged bundle object listing changed")
        object_id = fields[0].decode("ascii", errors="strict")
        if len(object_id) != 40 or any(character not in "0123456789abcdef" for character in object_id):
            raise AssertionError("staged bundle object listing changed")
        object_ids.append(object_id)
    if len(object_ids) != len(set(object_ids)) or not object_ids:
        raise AssertionError("staged bundle object closure changed")

    requests = ("".join(f"{object_id}\n" for object_id in object_ids)).encode("ascii")
    checked = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input=requests,
        check=False,
        capture_output=True,
    )
    if checked.returncode != 0:
        raise AssertionError(checked.stderr or checked.stdout)
    rows: list[tuple[str, str, int]] = []
    checked_lines = checked.stdout.splitlines()
    if len(checked_lines) != len(object_ids):
        raise AssertionError("staged bundle object metadata changed")
    for expected, line in zip(object_ids, checked_lines):
        fields = line.split()
        if len(fields) != 3 or fields[0].decode("ascii", errors="strict") != expected:
            raise AssertionError("staged bundle object metadata changed")
        object_type = fields[1].decode("ascii", errors="strict")
        try:
            object_size = int(fields[2])
        except (TypeError, ValueError) as exc:
            raise AssertionError("staged bundle object metadata changed") from exc
        if object_type not in {"blob", "tree", "commit", "tag"} or object_size < 0:
            raise AssertionError("staged bundle object metadata changed")
        rows.append((expected, object_type, object_size))
    if len(rows) != len(object_ids):
        raise AssertionError("staged bundle object metadata changed")
    return rows


def _materialize_loose_objects(
    repository: Path,
    staging_repository: Path,
    rows: list[tuple[str, str, int]],
) -> None:
    """Copy verified Git payloads into a pack-free loose-object database."""

    requests = ("".join(f"{object_id}\n" for object_id, _, _ in rows)).encode("ascii")
    completed = subprocess.run(
        ["git", "-C", str(staging_repository), "cat-file", "--batch"],
        input=requests,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)

    objects = repository / ".git" / "objects"
    output = completed.stdout
    cursor = 0
    for expected_oid, expected_type, expected_size in rows:
        header_end = output.find(b"\n", cursor)
        if header_end < 0:
            raise AssertionError("staged bundle object payload changed")
        header = output[cursor:header_end].split()
        cursor = header_end + 1
        if len(header) != 3:
            raise AssertionError("staged bundle object payload changed")
        object_id = header[0].decode("ascii", errors="strict")
        object_type = header[1].decode("ascii", errors="strict")
        try:
            object_size = int(header[2])
        except (TypeError, ValueError) as exc:
            raise AssertionError("staged bundle object payload changed") from exc
        if (object_id, object_type, object_size) != (expected_oid, expected_type, expected_size):
            raise AssertionError("staged bundle object payload changed")
        payload_bytes = output[cursor : cursor + object_size]
        cursor += object_size
        if len(payload_bytes) != object_size or output[cursor : cursor + 1] != b"\n":
            raise AssertionError("staged bundle object payload changed")
        cursor += 1
        object_header = f"{object_type} {object_size}\0".encode("ascii")
        object_payload = object_header + payload_bytes
        if hashlib.sha1(object_payload).hexdigest() != expected_oid:
            raise AssertionError("staged bundle object hash changed")

        fanout = objects / expected_oid[:2]
        fanout.mkdir(mode=0o700, exist_ok=True)
        destination = fanout / expected_oid[2:]
        temporary = fanout / f".{expected_oid[2:]}.{os.getpid()}.tmp"
        try:
            temporary.write_bytes(zlib.compress(object_payload))
            temporary.chmod(0o444)
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
    if cursor != len(output):
        raise AssertionError("staged bundle object payload changed")


def _reset_to_plain_loose_repository(repository: Path) -> None:
    """Remove clone packs, refs, and redirects before installing exact fixtures."""

    git_dir = repository / ".git"
    metadata = os.lstat(git_dir)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AssertionError("fixture object repository is not a plain checkout")
    for relative in ("objects", "refs"):
        path = git_dir / relative
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AssertionError("fixture object repository metadata changed")
        shutil.rmtree(path)
        path.mkdir(mode=0o700)
    objects = git_dir / "objects"
    (objects / "info").mkdir(mode=0o700)
    (objects / "pack").mkdir(mode=0o700)
    (git_dir / "refs" / "fixture-authority").mkdir(mode=0o700)

    for relative in ("packed-refs", "shallow", "index", "logs", "gitdir", "commondir", "config.worktree"):
        path = git_dir / relative
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
    (git_dir / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n",
        encoding="ascii",
    )
    # A detached exact authority tip avoids retaining unrelated clone refs while
    # keeping normal Git history commands available to the relationship tests.
    (git_dir / "HEAD").write_text(f"{PROTECTED_OBJECTS[2][1]}\n", encoding="ascii")
    for name, commit in PROTECTED_OBJECTS:
        (git_dir / "refs" / "fixture-authority" / name).write_text(
            f"{commit}\n", encoding="ascii"
        )


def _verify_materialized_repository(
    repository: Path,
    rows: list[tuple[str, str, int]],
) -> None:
    """Recheck refs, object metadata, fsck, and the absence of pack files."""

    pack_directory = repository / ".git" / "objects" / "pack"
    if tuple(pack_directory.iterdir()):
        raise AssertionError("fixture object repository retained pack metadata")
    expected_refs = {
        f"refs/fixture-authority/{name}": commit for name, commit in PROTECTED_OBJECTS
    }
    refs = _git_output(repository, "for-each-ref", "--format=%(refname)\t%(objectname)")
    actual_refs: dict[str, str] = {}
    for line in refs.splitlines():
        fields = line.decode("ascii").split("\t")
        if len(fields) != 2:
            raise AssertionError("fixture object repository refs changed")
        actual_refs[fields[0]] = fields[1]
    if actual_refs != expected_refs:
        raise AssertionError("fixture object repository refs changed")

    checked = _git_output(
        repository,
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
    )
    actual_rows: list[tuple[str, str, int]] = []
    for line in checked.splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise AssertionError("materialized object metadata changed")
        actual_rows.append(
            (
                fields[0].decode("ascii"),
                fields[1].decode("ascii"),
                int(fields[2]),
            )
        )
    if sorted(actual_rows) != sorted(rows):
        raise AssertionError("materialized object closure changed")
    fsck = _run_git(
        "-C",
        str(repository),
        "fsck",
        "--full",
        "--strict",
        "--no-reflogs",
        "--no-progress",
    )
    if fsck.returncode != 0:
        raise AssertionError(fsck.stderr or fsck.stdout)
    for name, commit in PROTECTED_OBJECTS:
        object_type = _run_git("-C", str(repository), "cat-file", "-t", commit)
        if object_type.returncode != 0 or object_type.stdout.strip() != "commit":
            raise AssertionError(f"protected {name} object missing: {commit}")
        ref = f"refs/fixture-authority/{name}"
        resolved = _run_git("-C", str(repository), "rev-parse", ref)
        if resolved.returncode != 0 or resolved.stdout.strip() != commit:
            raise AssertionError(f"protected {name} ref is not pinned: {commit}")


def seed_protected_objects(repository: Path) -> None:
    """Provision only the success fixture as exact loose Git objects.

    Hostile-source tests intentionally retain their packed, missing, alternate,
    and promisor layouts; they must not call this helper as a repair shortcut.
    """

    verify_trusted_bundle()
    with tempfile.TemporaryDirectory(prefix="fixture-authority-staging-") as temporary:
        staging_repository = Path(temporary) / "staging.git"
        initialized = _run_git("init", "--bare", "--quiet", str(staging_repository))
        if initialized.returncode != 0:
            raise AssertionError(initialized.stderr or initialized.stdout)
        refspecs = tuple(
            f"{commit}:refs/fixture-authority/{name}" for name, commit in PROTECTED_OBJECTS
        )
        fetched = _run_git(
            "-C",
            str(staging_repository),
            "fetch",
            "--no-tags",
            "--quiet",
            str(TRUSTED_BUNDLE_PATH),
            *refspecs,
        )
        if fetched.returncode != 0:
            raise AssertionError(fetched.stderr or fetched.stdout)
        fsck = _run_git(
            "-C",
            str(staging_repository),
            "fsck",
            "--full",
            "--strict",
            "--no-reflogs",
            "--no-progress",
        )
        if fsck.returncode != 0:
            raise AssertionError(fsck.stderr or fsck.stdout)
        for name, commit in PROTECTED_OBJECTS:
            resolved = _run_git(
                "-C", str(staging_repository), "rev-parse", f"refs/fixture-authority/{name}"
            )
            if resolved.returncode != 0 or resolved.stdout.strip() != commit:
                raise AssertionError(f"staged {name} ref is not pinned: {commit}")
        rows = _reachable_object_rows(staging_repository)
        _reset_to_plain_loose_repository(repository)
        _materialize_loose_objects(repository, staging_repository, rows)
        _verify_materialized_repository(repository, rows)
