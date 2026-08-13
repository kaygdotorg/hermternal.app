#!/usr/bin/env python3
"""Prove forbidden ancestry when rejected historical objects are unavailable.

The frozen authority can name an unreferenced rejected commit. Absence is a
valid non-ancestry proof only when the local object database and every required
commit closure are complete and no Git indirection can hide an object.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

OID = re.compile(r"[0-9a-f]{40}\Z")
SCHEMA = "hermternal.issue-397.forbidden-object-proof/v1"
SAFE_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
}


class ProofError(RuntimeError):
    """Report a failed forbidden-object proof."""


def canonical_bytes(record: Mapping[str, Any]) -> bytes:
    """Return the only accepted serialized proof form."""
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()


def record_sha256(record: Mapping[str, Any]) -> str:
    """Bind one canonical proof record."""
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def _run(repository: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
         "-C", os.fspath(repository), "-c", "core.hooksPath=/dev/null",
         "-c", "protocol.allow=never", *args],
        input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, env=SAFE_ENV, cwd="/",
    )


def _output(repository: Path, *args: str) -> str:
    process = _run(repository, *args)
    if process.returncode:
        raise ProofError(f"Git proof command failed: {args!r}")
    try:
        return process.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ProofError("Git proof output is not UTF-8") from exc


def _safe_repository(repository: Path) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    if not repository.is_dir() or os.fspath(repository) != os.path.realpath(repository):
        raise ProofError("proof repository is not canonical")
    if _output(repository, "rev-parse", "--show-object-format") != "sha1":
        raise ProofError("proof repository is not SHA-1")
    if _output(repository, "rev-parse", "--is-shallow-repository") != "false":
        raise ProofError("proof repository is shallow")
    git_dir = Path(_output(repository, "rev-parse", "--absolute-git-dir"))
    common = Path(_output(repository, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    objects = Path(_output(repository, "rev-parse", "--path-format=absolute", "--git-path", "objects"))
    for path, label in ((git_dir, "Git directory"), (common, "Git common directory"), (objects, "Git object directory")):
        if not path.is_absolute() or os.path.realpath(path) != os.fspath(path):
            raise ProofError(f"{label} is not canonical")
    forbidden = (
        git_dir / "shallow", common / "shallow", common / "info" / "grafts",
        common / "refs" / "replace", objects / "info" / "alternates",
        objects / "info" / "http-alternates",
    )
    if any(os.path.lexists(path) for path in forbidden):
        raise ProofError("repository has shallow, graft, replacement, or alternate metadata")
    packed = common / "packed-refs"
    if packed.exists() and b"refs/replace/" in packed.read_bytes():
        raise ProofError("repository has packed replacement refs")
    pack_dir = objects / "pack"
    if pack_dir.exists():
        st = os.lstat(pack_dir)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(pack_dir) != os.fspath(pack_dir):
            raise ProofError("repository pack directory is unsafe")
        if any(path.name.endswith(".promisor") for path in pack_dir.iterdir()):
            raise ProofError("repository has promisor pack metadata")
    config = _run(repository, "config", "--local", "--null", "--name-only", "--get-regexp", ".*")
    if config.returncode not in (0, 1):
        raise ProofError("repository configuration inspection failed")
    try:
        config_keys = [value.decode("utf-8", errors="strict").lower()
                       for value in config.stdout.split(b"\0") if value]
    except UnicodeDecodeError as exc:
        raise ProofError("repository configuration is not UTF-8") from exc
    if any(key == "extensions.partialclone"
           or (key.startswith("remote.")
               and key.endswith((".promisor", ".vcs", ".partialclonefilter")))
           for key in config_keys):
        raise ProofError("repository has partial-clone, promisor, or helper configuration")
    fsck = _run(repository, "fsck", "--full", "--strict", "--no-reflogs", "--no-progress")
    if fsck.returncode:
        raise ProofError("strict repository fsck failed")
    closure = _run(repository, "rev-list", "--objects", "--all", "--missing=error")
    if closure.returncode:
        raise ProofError("all-ref object closure is incomplete")
    return {"git_dir": os.fspath(git_dir), "git_common_dir": os.fspath(common), "git_object_dir": os.fspath(objects)}


def classify(repository: Path, final_head: str, forbidden_oids: Sequence[str], closure_roots: Sequence[str]) -> dict[str, Any]:
    """Return a canonical present-or-missing non-ancestry proof."""
    repository = Path(repository).resolve(strict=True)
    forbidden = tuple(forbidden_oids)
    roots = tuple(closure_roots)
    if (not OID.fullmatch(final_head) or not forbidden or len(forbidden) != len(set(forbidden))
            or any(not OID.fullmatch(value) for value in forbidden)
            or not roots or len(roots) != len(set(roots)) or any(not OID.fullmatch(value) for value in roots)):
        raise ProofError("proof OID inventory differs")
    storage = _safe_repository(repository)
    for root in (*roots, final_head):
        if _output(repository, "cat-file", "-t", root) != "commit":
            raise ProofError(f"closure root is not a commit: {root}")
        if _run(repository, "rev-list", "--objects", root, "--missing=error").returncode:
            raise ProofError(f"commit closure is incomplete: {root}")
    rows = []
    for oid in forbidden:
        typed = _run(repository, "cat-file", "-t", oid)
        if typed.returncode == 0:
            if typed.stdout != b"commit\n":
                raise ProofError(f"forbidden object is not a commit: {oid}")
            ancestry = _run(repository, "merge-base", "--is-ancestor", oid, final_head)
            if ancestry.returncode != 1:
                raise ProofError(f"forbidden commit ancestry result is {ancestry.returncode}: {oid}")
            status = "present-non-ancestor"
        else:
            diagnostic = typed.stderr.lower()
            if (typed.stdout or not any(token in diagnostic for token in
                                        (b"missing", b"not a valid object", b"could not get object info"))):
                raise ProofError(f"forbidden object lookup failed unexpectedly: {oid}")
            status = "missing-proved"
        rows.append({"oid": oid, "status": status})
    return {
        "schema": SCHEMA, "repository": os.fspath(repository), "final_head": final_head,
        "closure_roots": list(roots), "forbidden": rows,
        "proof": {"object_format": "sha1", "shallow": False, "strict_fsck": True,
                  "all_ref_closure": True, "root_closures": True, "indirection_absent": True,
                  **storage},
    }


def repair_generated_validator(stdin: bytes, expected_record: Mapping[str, Any], expected_sha256: str) -> bytes:
    """Install the reviewed availability policy at its three exact anchors."""
    if record_sha256(expected_record) != expected_sha256:
        raise ProofError("expected forbidden proof SHA-256 differs")
    rows = expected_record.get("forbidden")
    if not isinstance(rows, list):
        raise ProofError("expected forbidden proof rows differ")
    missing = tuple(row["oid"] for row in rows if row.get("status") == "missing-proved")
    present = tuple(row["oid"] for row in rows if row.get("status") == "present-non-ancestor")
    if set(missing).intersection(present) or len(missing) + len(present) != len(rows):
        raise ProofError("expected forbidden proof statuses differ")
    missing_json = json.dumps(missing, separators=(",", ":"))

    old_static = b"for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']:\n    oid(value, 'commit', 'forbidden.commit')\n"
    new_static = ("missing_proved_forbidden = set(json.loads(" + repr(missing_json) + "))\n"
                  "for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']:\n"
                  "    oid(value, 'commit', 'forbidden.commit', missing=value in missing_proved_forbidden)\n").encode()
    if stdin.count(old_static) != 1:
        raise ProofError("generated static forbidden predicate anchor differs")
    result = stdin.replace(old_static, new_static, 1)

    old_final = b'''  for bad in "${bad_objects[@]}"; do
    set +e
    git_replay merge-base --is-ancestor "$bad" "$CURRENT_HEAD"
    rc=$?
    set -e
    test "$rc" -eq 1 || fail "forbidden ancestry $bad returned $rc, expected exact rc=1"
  done
'''
    case_items = "|".join(missing)
    new_final = f'''  for bad in "${{bad_objects[@]}}"; do
    case "$bad" in
      {case_items})
        test "$(git_replay cat-file -t "$bad" 2>/dev/null || printf missing)" = missing || fail "missing-proved forbidden object became available: $bad"
        ;;
      *)
        set +e
        git_replay merge-base --is-ancestor "$bad" "$CURRENT_HEAD"
        rc=$?
        set -e
        test "$rc" -eq 1 || fail "forbidden ancestry $bad returned $rc, expected exact rc=1"
        ;;
    esac
  done
'''.encode()
    if result.count(old_final) != 1:
        raise ProofError("generated final forbidden predicate anchor differs")
    result = result.replace(old_final, new_final, 1)

    # The retained pack must not require historical objects that the approved
    # proof classified as absent. It still copies every available proof root.
    old_roots = b"ROOTS = validate_pack_roots(\n    tuple(sorted(set(AUTHORITY_ROOTS).union([final_head]))),\n    AUTHORITY_ROOTS,\n    final_head,\n    observed_head,\n)\n"
    new_roots = ("MISSING_PROVED = frozenset(json.loads(" + repr(missing_json) + "))\n"
                 "PRESENT_AUTHORITY_ROOTS = tuple(root for root in AUTHORITY_ROOTS if root not in MISSING_PROVED)\n"
                 "ROOTS = validate_pack_roots(\n    tuple(sorted(set(PRESENT_AUTHORITY_ROOTS).union([final_head]))),\n    PRESENT_AUTHORITY_ROOTS,\n    final_head,\n    observed_head,\n)\n").encode()
    if result.count(old_roots) != 1:
        raise ProofError("generated retained-root predicate anchor differs")
    return result.replace(old_roots, new_roots, 1)
