#!/usr/bin/env python3
"""Reproduce the failure-v11 object-preservation ordering failure."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_replay_failure_v11 as FAILURE  # noqa: E402
import linux_retained_driver_v7 as DRIVER_V7  # noqa: E402

FAILURE_PATH = Path(
    "/home/kayg/Developer/hermternal-issue397-replay-failure-v11/replay-failure.json"
)
FAILURE_SHA256 = "e80411452d17c6129fc2d67eb242af50ed569e330c5b87181433d4feb2d34480"
MISSING_OID = "003194b17a9670b83a9f5a2f9f5cc0742d545361"
PRESERVE_CALL = b"module.preserve(module.Path(source), module.Path(clean),"
TYPED_OBJECT_CALL = b"actual = out('cat-file', '-t', object_id)"
CLEAN_VALIDATION_CALL = b'static_validate_matrix "$CLEAN_PRIMARY"'


def stable_bytes(path: Path, expected_sha256: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("failure-v11 evidence identity differs")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            if not block:
                raise RuntimeError("failure-v11 evidence read ended early")
            raw += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise RuntimeError("failure-v11 evidence changed during read")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("failure-v11 evidence SHA-256 differs")
    return raw


class FailureV11OrderingReproduction(unittest.TestCase):
    def test_preservation_precedes_clean_primary_typed_object_validation(self) -> None:
        evidence = json.loads(stable_bytes(FAILURE_PATH, FAILURE_SHA256))
        anchor_sha256 = evidence["approval"]["anchor_evidence_sha256"]
        # Authority renderers print diagnostics while they build the exact
        # public-loader value. Suppress that unrelated output so red stays sharp.
        with redirect_stdout(io.StringIO()):
            _wrapper, authority = FAILURE.load_approved_wrapper(anchor_sha256)
            expected = DRIVER_V7.derive_contract().stdin
        derived = authority.stdin
        derived_sha256 = hashlib.sha256(derived).hexdigest()

        self.assertEqual(
            evidence["process"]["stdin_sha256"],
            "740204d456c4890d1821ef9898338935b0ffe0f246b8cd6ae4c9641de97682ff",
        )
        self.assertEqual(evidence["authority"]["derived_stdin_sha256"], evidence["process"]["stdin_sha256"])
        self.assertIn(f"('cat-file', '-t', '{MISSING_OID}')", evidence["process"]["stderr"]["excerpt"])
        self.assertIn(TYPED_OBJECT_CALL, derived)
        self.assertIn(CLEAN_VALIDATION_CALL, derived)
        self.assertEqual(
            derived,
            expected,
            "final public stdin must be the exact retained-driver v7 derivation",
        )

        self.assertEqual(derived.count(PRESERVE_CALL), 1)
        self.assertLess(
            derived.index(PRESERVE_CALL),
            derived.rindex(CLEAN_VALIDATION_CALL),
            "object preservation must run before clean-primary typed-object validation",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
