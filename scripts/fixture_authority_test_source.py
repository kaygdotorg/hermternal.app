#!/usr/bin/env python3
"""Provision the pinned fixture-authority objects from the checked-in bundle.

This module is test infrastructure only. The reviewed checkout is deliberately
not an authority source: a fresh single-head clone may omit unreachable history,
and a local developer object database may retain objects that a clean checkout
cannot serve. The repository-versioned bundle is the explicit offline input for
both aggregate and standalone authority suites.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TRUSTED_BUNDLE_PATH = REPO_ROOT / "scripts" / "fixture_registry_authority.objects.bundle"
TRUSTED_BUNDLE_SIZE_BYTES = 49_823_195
TRUSTED_BUNDLE_SHA256 = "b975a7c17e41d9fa3470bdca09752ba74386cc99bcd6d56a465fdd715a7aa782"

# These are the only refs exported by the bundle. The bundle contains the
# reachable trees/blobs needed to read each commit, but its advertised ref set
# is deliberately bounded to these four exact trust roots.
PROTECTED_OBJECTS = (
    ("historical-authority", "285acdcf9c11c049180a7844e689eee0f1490de4"),
    ("historical-source", "263cb75adcf153d6fe252636b064e5fbc3e3f877"),
    ("active-authority", "b01fd589c90ef9e768cc0170c829569783255f00"),
    ("active-source", "dda83ab73191ea696f941bfb18496e4f4a70e748"),
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
    """Require the checked-in bundle to expose exactly the pinned four refs."""

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


def seed_protected_objects(repository: Path) -> None:
    """Fetch all four pinned commits from the trusted bundle into fixture refs."""

    verify_trusted_bundle()
    refspecs = tuple(
        f"{commit}:refs/fixture-authority/{name}" for name, commit in PROTECTED_OBJECTS
    )
    fetched = _run_git(
        "-C",
        str(repository),
        "fetch",
        "--no-tags",
        "--quiet",
        str(TRUSTED_BUNDLE_PATH),
        *refspecs,
    )
    if fetched.returncode != 0:
        raise AssertionError(fetched.stderr or fetched.stdout)
    for name, commit in PROTECTED_OBJECTS:
        object_type = _run_git("-C", str(repository), "cat-file", "-t", commit)
        if object_type.returncode != 0 or object_type.stdout.strip() != "commit":
            raise AssertionError(f"protected {name} object missing: {commit}")
        ref = f"refs/fixture-authority/{name}"
        resolved = _run_git("-C", str(repository), "rev-parse", ref)
        if resolved.returncode != 0 or resolved.stdout.strip() != commit:
            raise AssertionError(f"protected {name} ref is not pinned: {commit}")
