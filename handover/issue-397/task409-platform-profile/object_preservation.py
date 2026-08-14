#!/usr/bin/env python3
"""Preserve the exact replay authority object closure in a local clone."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

import forbidden_proof

SCHEMA = "hermternal.issue-397.object-preservation/v1"
OID = re.compile(r"[0-9a-f]{40}\Z")
ROOTS = (
    "027806c8596f8b9a4ce200b2fe1344e013f46685",
    "80fe3b68fb676a3b6589fce9aed79140bf37b667",
    "83c709bf9a22672362662f7c369b2c235f5859e9",
    "8be4f513286813a7a1cbe7bbc997f53b7d557209",
    "94b0dd97247093f5ca3eb5dee4f1e3c6926e6439",
    "a2a8a0b03f515409a02e6668d2600e5ebb6e5152",
    "b1741699ca93262306b039771fe96282cb4142fd",
    "befb8c7e673157932f5f13242d863e64806cffac",
    "e3a2d2e662f2e606f318d35f4fccc63ba9738f7c",
    "e664505c7ad9779855a394c62f72823fad7eba76",
    "f054bfe71d98129b81c10367ca27540da6243496",
)
MISSING_PROVED = (
    "7271e7bac836a519c3df66a93ceb3b2c5a0d8921",
    "03e2b0c828276044d1229c0200a5ac969140a344",
    "ad9bc22b7cc86e0c007a0347e2dec78fa49132a4",
    "48b58c19e4e4991d1d15321a8e39b8261937b59b",
    "c7ab4f9b0fec97b4e4de20bada6f43e57bd7d5e3",
)
TYPE_COUNTS = {"blob": 315, "commit": 128, "tree": 120}
SAFE_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
}


class PreservationError(RuntimeError):
    """Report an object preservation policy failure."""


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def record_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _run(repository: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
         "-C", os.fspath(repository), "-c", "core.hooksPath=/dev/null",
         "-c", "protocol.allow=never", *args], input=input_bytes,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env=SAFE_ENV, cwd="/",
    )


def _output(repository: Path, *args: str) -> bytes:
    process = _run(repository, *args)
    if process.returncode or process.stderr:
        raise PreservationError(f"Git object preservation command failed: {args!r}")
    return process.stdout


def typed_inventory(authority: Mapping[str, Any]) -> dict[str, str]:
    """Extract the complete typed OID set used by the frozen validator."""
    expected_by_key = {
        "commit": "commit", "parent": "commit", "parents": "commit",
        "child": "commit", "tree": "tree", "blob": "blob",
    }
    inventory: dict[str, str] = {}

    def collect(node: Any, key: str | None = None) -> None:
        if isinstance(node, dict):
            for child_key, child in node.items():
                collect(child, child_key)
        elif isinstance(node, list):
            for child in node:
                collect(child, key)
        elif isinstance(node, str) and OID.fullmatch(node) and key in expected_by_key:
            expected = expected_by_key[key]
            if node in inventory and inventory[node] != expected:
                raise PreservationError(f"authority assigns two types to {node}")
            inventory[node] = expected

    collect(authority)
    counts = {kind: sum(value == kind for value in inventory.values()) for kind in TYPE_COUNTS}
    if len(inventory) != 563 or counts != TYPE_COUNTS:
        raise PreservationError("authority typed OID inventory differs")
    return dict(sorted(inventory.items()))


def _types(repository: Path, oids: Sequence[str]) -> dict[str, str]:
    process = _run(repository, "cat-file", "--batch-check", input_bytes=("\n".join(oids) + "\n").encode())
    if process.returncode or process.stderr:
        raise PreservationError("batch object type inspection failed")
    result: dict[str, str] = {}
    for line in process.stdout.decode("ascii", errors="strict").splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] not in oids:
            raise PreservationError("batch object type output differs")
        result[fields[0]] = fields[1]
    if len(result) != len(oids):
        raise PreservationError("batch object type output is incomplete")
    return result


def build_record(authority: Mapping[str, Any], proof: Mapping[str, Any]) -> dict[str, Any]:
    """Bind the exact source inventory, statuses, and independent roots."""
    inventory = typed_inventory(authority)
    rows = proof.get("forbidden")
    if not isinstance(rows, list) or len(rows) != 22:
        raise PreservationError("forbidden proof inventory differs")
    missing = tuple(row.get("oid") for row in rows if row.get("status") == "missing-proved")
    present = tuple(row.get("oid") for row in rows if row.get("status") == "present-non-ancestor")
    if missing != MISSING_PROVED or len(present) != 17 or any(not OID.fullmatch(value or "") for value in present):
        raise PreservationError("forbidden proof classification differs")
    entries = [f"{oid} {kind}" for oid, kind in inventory.items()]
    return {
        "schema": SCHEMA,
        "typed_count": len(inventory),
        "typed_counts": TYPE_COUNTS,
        "typed_inventory_sha256": hashlib.sha256(("\n".join(entries) + "\n").encode()).hexdigest(),
        "independent_roots": list(ROOTS),
        "independent_roots_sha256": hashlib.sha256(("\n".join(ROOTS) + "\n").encode()).hexdigest(),
        "present_forbidden": list(present),
        "missing_proved": list(missing),
        "final_head": proof.get("final_head"),
    }


def _validate_repository(repository: Path, authority: Mapping[str, Any], record: Mapping[str, Any]) -> None:
    inventory = typed_inventory(authority)
    observed = _types(repository, list(inventory))
    wrong = [oid for oid, kind in inventory.items() if observed.get(oid) != kind]
    if wrong:
        raise PreservationError(f"typed object preservation differs: {wrong[0]}")
    forbidden = [*record["present_forbidden"], *record["missing_proved"]]
    forbidden_types = _types(repository, forbidden)
    if any(forbidden_types[oid] != "commit" for oid in record["present_forbidden"]):
        raise PreservationError("present forbidden commit preservation differs")
    if any(forbidden_types[oid] != "missing" for oid in record["missing_proved"]):
        raise PreservationError("missing-proved object became available")
    independent = _output(repository, "merge-base", "--independent", *sorted(
        {oid for oid, kind in inventory.items() if kind == "commit"}.union(record["present_forbidden"])
    )).decode().splitlines()
    if tuple(sorted(independent)) != ROOTS:
        raise PreservationError("independent authority roots differ")
    if _run(repository, "fsck", "--full", "--strict", "--no-reflogs", "--no-progress").returncode:
        raise PreservationError("strict repository fsck failed")
    if _run(repository, "rev-list", "--objects", "--all", "--missing=error").returncode:
        raise PreservationError("all-ref object closure is incomplete")
    for root in ROOTS:
        if _run(repository, "rev-list", "--objects", root, "--missing=error").returncode:
            raise PreservationError(f"authority root closure is incomplete: {root}")


def _stable_file(path: Path) -> tuple[tuple[int, ...], str, int]:
    values = []
    for _pass in range(2):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o400:
                raise PreservationError("transfer pack identity is unsafe")
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block); total += len(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = os.lstat(path)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                                  value.st_mode, value.st_size, value.st_nlink,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(before) != identity(current) or total != before.st_size:
            raise PreservationError("transfer pack changed during stable read")
        values.append((identity(before), digest.hexdigest(), total))
    if values[0] != values[1]:
        raise PreservationError("transfer pack changed across stable reads")
    return values[0]


def import_pack(clean: Path, pack_path: Path) -> str:
    """Index one stable complete pack and reject corrupt or thin input."""
    identity, digest, size = _stable_file(pack_path)
    with pack_path.open("rb") as source_pack:
        imported = subprocess.run(
            ["/usr/bin/git", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
             "-C", os.fspath(clean), "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never",
             "index-pack", "--stdin"], stdin=source_pack, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, env=SAFE_ENV, cwd="/",
        )
    match = re.fullmatch(rb"(?:pack\t)?([0-9a-f]{40})\n", imported.stdout)
    if imported.returncode or imported.stderr or match is None:
        raise PreservationError("authority pack import failed or pack is thin")
    if _stable_file(pack_path) != (identity, digest, size):
        raise PreservationError("authority pack changed during import")
    return match.group(1).decode()


def preserve(source: Path, clean: Path, transfer_root: Path, authority_path: Path,
             expected_record: Mapping[str, Any], expected_sha256: str) -> dict[str, Any]:
    """Import one verified non-thin source pack into a disposable clone."""
    source = Path(source).resolve(strict=True); clean = Path(clean).resolve(strict=True)
    transfer_root = Path(transfer_root).resolve(strict=True); authority_path = Path(authority_path).resolve(strict=True)
    if clean.parent != transfer_root or record_sha256(expected_record) != expected_sha256:
        raise PreservationError("object preservation binding differs")
    authority = json.loads(authority_path.read_bytes())
    proof = forbidden_proof.classify(
        source, expected_record["final_head"],
        [*expected_record["present_forbidden"], *expected_record["missing_proved"]],
        [authority["base"]["commit"], authority["base"]["protected_main_commit"], expected_record["final_head"]],
    )
    if build_record(authority, proof) != expected_record:
        raise PreservationError("runtime preservation record differs")
    _validate_repository(source, authority, expected_record)
    pack_path = transfer_root / "authority-transfer.pack"
    descriptor = os.open(pack_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        process = subprocess.run(
            ["/usr/bin/git", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
             "-C", os.fspath(source), "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never",
             "pack-objects", "--stdout", "--revs"],
            input=("\n".join(ROOTS) + "\n").encode(), stdout=descriptor,
            stderr=subprocess.PIPE, check=False, env=SAFE_ENV, cwd="/",
        )
        if process.returncode or process.stderr:
            raise PreservationError("non-thin authority pack export failed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(pack_path, 0o400)
    identity, digest, size = _stable_file(pack_path)
    try:
        pack_object_id = import_pack(clean, pack_path)
        clean_proof = forbidden_proof.classify(
            clean, expected_record["final_head"],
            [*expected_record["present_forbidden"], *expected_record["missing_proved"]],
            [authority["base"]["commit"], authority["base"]["protected_main_commit"],
             expected_record["final_head"]],
        )
        if build_record(authority, clean_proof) != expected_record:
            raise PreservationError("clean-primary preservation record differs")
        _validate_repository(clean, authority, expected_record)
        return {"schema": SCHEMA, "pack_sha256": digest, "pack_bytes": size,
                "pack_object_id": pack_object_id, "typed_count": 563,
                "present_forbidden_count": 17, "missing_proved_count": 5}
    finally:
        os.unlink(pack_path)
        parent = os.open(transfer_root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(parent)
        finally: os.close(parent)


def repair_generated_validator(stdin: bytes, expected_record: Mapping[str, Any],
                                expected_sha256: str, policy_path: Path,
                                policy_sha256: str, proof_path: Path,
                                proof_sha256: str) -> bytes:
    """Insert preservation after the exact clone and before identity binding."""
    if record_sha256(expected_record) != expected_sha256:
        raise PreservationError("expected preservation record SHA-256 differs")
    if hashlib.sha256(Path(policy_path).read_bytes()).hexdigest() != policy_sha256:
        raise PreservationError("object preservation policy SHA-256 differs")
    if hashlib.sha256(Path(proof_path).read_bytes()).hexdigest() != proof_sha256:
        raise PreservationError("forbidden proof policy SHA-256 differs")
    old = b'''  git_hermetic -c protocol.file.allow=always clone --no-local --no-hardlinks --no-checkout --no-tags "$SOURCE" "$CLEAN_PRIMARY" >/dev/null
  bind_clean_primary_identity
'''
    payload = json.dumps(expected_record, sort_keys=True, separators=(",", ":"))
    new = f'''  git_hermetic -c protocol.file.allow=always clone --no-local --no-hardlinks --no-checkout --no-tags "$SOURCE" "$CLEAN_PRIMARY" >/dev/null
  "$PYTHON" - "$SOURCE" "$CLEAN_PRIMARY" "$CLEAN_PRIMARY_ROOT" "$MATRIX" {json.dumps(os.fspath(Path(policy_path).resolve()))} {json.dumps(policy_sha256)} {json.dumps(os.fspath(Path(proof_path).resolve()))} {json.dumps(proof_sha256)} {json.dumps(expected_sha256)} {json.dumps(payload)} <<'PY'
import hashlib, json, os, stat, sys, types
source, clean, root, matrix, policy_path, policy_sha256, proof_path, proof_sha256, record_sha256, payload = sys.argv[1:]
def verified_bytes(path, expected_sha256, label):
    reads = []
    for _pass in range(2):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            before = os.fstat(descriptor); blocks = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block: break
                blocks.append(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = os.lstat(path); raw = b''.join(blocks)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode, value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
        if (identity(before) != identity(after) or identity(before) != identity(current)
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or len(raw) != before.st_size):
            raise SystemExit(label + ' identity differs')
        reads.append((identity(before), raw, hashlib.sha256(raw).hexdigest()))
    if reads[0] != reads[1] or reads[0][2] != expected_sha256:
        raise SystemExit(label + ' stable bytes or SHA-256 differs')
    return reads[0][1]
proof_raw = verified_bytes(proof_path, proof_sha256, 'forbidden proof policy')
policy_raw = verified_bytes(policy_path, policy_sha256, 'object preservation policy')
proof_module = types.ModuleType('forbidden_proof'); proof_module.__file__ = proof_path
exec(compile(proof_raw, proof_path, 'exec', dont_inherit=True), proof_module.__dict__)
module = types.ModuleType('issue397_object_preservation_runtime'); module.__file__ = policy_path
previous = sys.modules.get('forbidden_proof'); sys.modules['forbidden_proof'] = proof_module
try:
    exec(compile(policy_raw, policy_path, 'exec', dont_inherit=True), module.__dict__)
finally:
    if previous is None: sys.modules.pop('forbidden_proof', None)
    else: sys.modules['forbidden_proof'] = previous
record = json.loads(payload)
if module.record_sha256(record) != record_sha256:
    raise SystemExit('object preservation record SHA-256 differs')
module.preserve(module.Path(source), module.Path(clean), module.Path(root), module.Path(matrix), record, record_sha256)
PY
  bind_clean_primary_identity
'''.encode()
    if stdin.count(old) != 1:
        raise PreservationError("clean-primary clone preservation anchor differs")
    return stdin.replace(old, new, 1)
