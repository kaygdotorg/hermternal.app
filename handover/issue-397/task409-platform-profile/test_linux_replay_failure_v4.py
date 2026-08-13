#!/usr/bin/env python3
"""Offline authority checks for proof-bound failure-v4 publication."""
from __future__ import annotations

import hashlib
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_phase_a_v6 as V6  # noqa: E402
import linux_replay_failure_v4 as V4  # noqa: E402
import linux_retained_driver_v3 as DRIVER  # noqa: E402


class FailureV4Tests(unittest.TestCase):
    def test_predecessor_and_phase_v6_are_authenticated(self) -> None:
        self.assertEqual(hashlib.sha256(V4.V3_PATH.read_bytes()).hexdigest(), V4.V3_SHA256)
        self.assertEqual(hashlib.sha256(V4.PHASE_A_V6_PATH.read_bytes()).hexdigest(), V4.PHASE_A_V6_SHA256)
        base = V4._load_v3()
        self.assertEqual(base.SCHEMA, V4.SCHEMA)
        self.assertEqual(base.DIRECTORY_NAME, V4.DIRECTORY_NAME)

    def test_all_nested_publication_mechanisms_use_phase_v6(self) -> None:
        base = V4._load_v3()
        self.assertEqual(base.PHASE_A_V5_PATH, V4.PHASE_A_V6_PATH)
        mechanism = base._load_v2()
        self.assertEqual(mechanism.PHASE_A_V4_PATH, V4.PHASE_A_V6_PATH)
        inner = mechanism._load_v1()
        self.assertEqual(inner.PHASE_A_ADAPTER_PATH, V4.PHASE_A_V6_PATH)
        self.assertIs(inner.load_phase_a_adapter(), V6)

    def test_wrong_anchor_does_not_create_failure_v4_root(self) -> None:
        root = Path(DRIVER.platform_profile.load().source_repository).parent / V4.DIRECTORY_NAME
        self.assertFalse(root.exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V4.load_approved_wrapper("0" * 64)
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
