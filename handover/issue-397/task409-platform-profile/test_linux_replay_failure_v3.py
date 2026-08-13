#!/usr/bin/env python3
"""Offline authority checks for failure-v3 without replay or publication."""
from __future__ import annotations

import hashlib
import os
import sys
import unittest

from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_replay_failure_v3 as V3  # noqa: E402
import linux_phase_a_v5 as V5  # noqa: E402


class FailureV3Tests(unittest.TestCase):
    def test_frozen_v2_and_v5_are_authenticated(self) -> None:
        self.assertEqual(hashlib.sha256(V3.V2_PATH.read_bytes()).hexdigest(), V3.V2_SHA256)
        self.assertEqual(hashlib.sha256(V3.PHASE_A_V5_PATH.read_bytes()).hexdigest(), V3.PHASE_A_V5_SHA256)
        base = V3._load_v2()
        self.assertEqual(base.SCHEMA, V3.SCHEMA)
        self.assertEqual(base.DIRECTORY_NAME, V3.DIRECTORY_NAME)

    def test_wrong_anchor_does_not_create_failure_v3_root(self) -> None:
        root = Path(V5.platform_profile.load().source_repository).parent / V3.DIRECTORY_NAME
        self.assertFalse(root.exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V3.load_approved_wrapper("0" * 64)
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
