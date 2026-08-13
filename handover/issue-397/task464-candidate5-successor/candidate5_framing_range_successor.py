#!/usr/bin/env python3
"""Run the frozen candidate-five generator with corrected range validation.

This successor does not change the frozen checkpoint. It loads that checkpoint
only after an exact SHA-256 check, then replaces the range projection in memory.
All publication behavior stays in the pinned generator.
"""

import hashlib
import importlib.util
import os
import re
import stat
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
FROZEN_GENERATOR = (
    BASE / "task464-candidate5" / "f932bc703a5e-task464-candidate5-generator.py"
)
FROZEN_GENERATOR_SHA256 = (
    "cc73c1743c4059cc995be4a9e097cd16007c8095bc87a7c572418134c4d434dc"
)
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
PARENT_ENDPOINT_RE = re.compile(r"[0-9a-f]{40}\^\Z")
INCLUSIVE_RANGE_RE = re.compile(r"[0-9a-f]{40}\^\.\.[0-9a-f]{40}\Z")
COMMIT_RANGE_RE = re.compile(r"[0-9a-f]{40}\.\.[0-9a-f]{40}\Z")


def _reject(message, error_type=ValueError):
    raise error_type(message)


def parse_commit(value, label="Git commit", error_type=ValueError):
    """Accept one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        _reject(f"{label} is not lowercase 40hex", error_type)
    return value


def parse_parent_endpoint(value, label="Git parent endpoint", error_type=ValueError):
    """Accept one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or PARENT_ENDPOINT_RE.fullmatch(value) is None:
        _reject(f"{label} is not lowercase 40hex^", error_type)
    return value


def parse_git_range(value, label="Git range", error_type=ValueError):
    """Accept the complete inclusive ``40hex^..40hex`` notation."""
    if not isinstance(value, str) or INCLUSIVE_RANGE_RE.fullmatch(value) is None:
        _reject(f"{label} is not lowercase 40hex^..40hex", error_type)
    return value


def parse_inclusive_git_range(record, label="Git range", error_type=ValueError):
    """Bind notation to separately validated inclusive range endpoints.

    Git must receive only the values returned here. This rule prevents a valid
    notation from hiding substituted ``left`` or ``right`` metadata.
    """
    if not isinstance(record, dict):
        _reject(f"{label} is not an object", error_type)
    left = parse_parent_endpoint(record.get("left"), f"{label}.left", error_type)
    right = parse_commit(record.get("right"), f"{label}.right", error_type)
    notation = parse_git_range(
        record.get("notation"), f"{label}.notation", error_type
    )
    if notation != f"{left}..{right}":
        _reject(f"{label}.notation does not match its validated endpoints", error_type)
    return left, right, notation


def parse_commit_range(value, label="Git commit range", error_type=ValueError):
    """Validate a non-inclusive two-commit range and return both endpoints."""
    if not isinstance(value, str) or COMMIT_RANGE_RE.fullmatch(value) is None:
        _reject(f"{label} is not lowercase 40hex..40hex", error_type)
    left, right = value.split("..")
    return (
        parse_commit(left, f"{label}.left", error_type),
        parse_commit(right, f"{label}.right", error_type),
    )


STRICT_RECORD_HELPERS = r'''
def strict_single_record_lf(raw, label='record'):
    """Parse one non-empty record with exactly one terminal LF."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must contain exactly one LF-framed record')
    record = raw[:-1]
    if not record or b'\n' in record:
        raise SystemExit(f'{label} must contain exactly one non-empty record')
    return record


def restore_command_substitution_lf(value, label='record'):
    """Put back the LF Bash command substitution removes before parsing."""
    if not isinstance(value, str) or not value or '\r' in value or '\n' in value:
        raise SystemExit(f'{label} command-substitution value is not one record')
    return strict_single_record_lf(value.encode('utf-8') + b'\n', label)


def strict_record_lines(raw, label='records'):
    """Parse a non-empty LF-framed stream without CR or blank rows."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\r' in raw or not raw.endswith(b'\n')
            or raw.endswith(b'\n\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows


def strict_git_commit(value, label='Git commit'):
    """Require one complete lowercase SHA-1 commit token."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex')
    return value


def strict_git_parent_endpoint(value, label='Git parent endpoint'):
    """Require one complete lowercase SHA-1 token with one parent suffix."""
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}\^', value) is None:
        raise SystemExit(f'{label} is not lowercase 40hex^')
    return value


def strict_inclusive_git_range(record, label='Git range'):
    """Bind an inclusive notation to its separately validated endpoints."""
    if not isinstance(record, dict):
        raise SystemExit(f'{label} is not an object')
    left = strict_git_parent_endpoint(record.get('left'), f'{label}.left')
    right = strict_git_commit(record.get('right'), f'{label}.right')
    notation = record.get('notation')
    if (not isinstance(notation, str)
            or re.fullmatch(r'[0-9a-f]{40}\^\.\.[0-9a-f]{40}', notation) is None):
        raise SystemExit(f'{label}.notation is not lowercase 40hex^..40hex')
    if notation != f'{left}..{right}':
        raise SystemExit(f'{label}.notation does not match its validated endpoints')
    return left, right, notation


def strict_git_commit_range(value, label='Git commit range'):
    """Validate a two-commit range before either endpoint is used."""
    if (not isinstance(value, str)
            or re.fullmatch(r'[0-9a-f]{40}\.\.[0-9a-f]{40}', value) is None):
        raise SystemExit(f'{label} is not lowercase 40hex..40hex')
    left, right = value.split('..')
    return strict_git_commit(left, f'{label}.left'), strict_git_commit(right, f'{label}.right')
'''


def strict_record_validator(code):
    """Install record helpers and bind every durable range before Git use."""
    if "def strict_single_record_lf(" not in code:
        future = re.match(r"((?:from __future__ import [^\n]+\n)*)", code)
        prefix = "import re\n" + STRICT_RECORD_HELPERS + "\n"
        code = code[: future.end()] + prefix + code[future.end() :]

    code = code.replace(
        "    r = lane.get('range')\n    if r:\n",
        "    r = lane.get('range')\n    if r:\n"
        "        range_left, range_right, notation = strict_inclusive_git_range(\n"
        "            r, f'{name}.range')\n",
    )
    code = code.replace(
        "out('rev-list', '--reverse', r['notation'])",
        "out('rev-list', '--reverse', notation)",
    )
    code = code.replace(
        "out('rev-list', '--merges', '--count', r['notation'])",
        "out('rev-list', '--merges', '--count', notation)",
    )
    code = code.replace(
        "patch_id(r['left'], r['right'], r['path_allowlist'])",
        "patch_id(range_left, range_right, r['path_allowlist'])",
    )

    code = code.replace(
        "    audit = lane.get('source_ancestry_audit')\n    if audit:\n",
        "    audit = lane.get('source_ancestry_audit')\n    if audit:\n"
        "        audit_left, audit_right, notation = strict_inclusive_git_range(\n"
        "            audit, f'{name}.ancestry')\n",
    )
    code = code.replace(
        "out('rev-list', '--reverse', audit['notation'])",
        "out('rev-list', '--reverse', notation)",
    )
    code = code.replace(
        "out('rev-list', '--merges', '--count', audit['notation'])",
        "out('rev-list', '--merges', '--count', notation)",
    )
    code = code.replace(
        "patch_id(audit['left'], audit['right'], audit['path_allowlist'])",
        "patch_id(audit_left, audit_right, audit['path_allowlist'])",
    )

    code = code.replace(
        "for endpoint in data['forbidden_ancestry']['authentication_range'].split('..'):\n",
        "authentication_left, authentication_right = strict_git_commit_range(\n"
        "    data['forbidden_ancestry']['authentication_range'], 'rejected-auth.range')\n"
        "for endpoint in (authentication_left, authentication_right):\n",
    )

    unsafe_range_uses = (
        "out('rev-list', '--reverse', r['notation'])",
        "out('rev-list', '--merges', '--count', r['notation'])",
        "patch_id(r['left'], r['right']",
        "out('rev-list', '--reverse', audit['notation'])",
        "out('rev-list', '--merges', '--count', audit['notation'])",
        "patch_id(audit['left'], audit['right']",
        "authentication_range'].split('..')",
    )
    if any(token in code for token in unsafe_range_uses):
        raise RuntimeError("a generated validator still uses an unvalidated Git range")
    return code


def _read_frozen_generator():
    """Read the pinned generator through one no-follow descriptor."""
    descriptor = os.open(os.fspath(FROZEN_GENERATOR), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("frozen generator is not a single-link regular file")
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_uid,
        stat.S_IMODE(item.st_mode),
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_nlink,
    )
    raw = b"".join(chunks)
    if identity(before) != identity(after):
        raise RuntimeError("frozen generator identity changed during read")
    if hashlib.sha256(raw).hexdigest() != FROZEN_GENERATOR_SHA256:
        raise RuntimeError("frozen generator SHA-256 mismatch")
    return raw


def install_successor():
    """Load the pinned checkpoint and install this reviewed range projection."""
    _read_frozen_generator()
    spec = importlib.util.spec_from_file_location(
        "candidate5_frozen_generator_for_successor", FROZEN_GENERATOR
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the frozen candidate-five generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.GIT_RANGE_RE = INCLUSIVE_RANGE_RE
    module.parse_git_range = parse_git_range
    module.STRICT_RECORD_HELPERS = STRICT_RECORD_HELPERS
    module.strict_record_validator = strict_record_validator
    return module


def main(argv=None):
    """Run the pinned generator with the successor validation installed."""
    return install_successor().main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
