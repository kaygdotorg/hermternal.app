#!/usr/bin/env python3
"""Confirm the v9 failure interface remains absent before a v9 anchor."""
from __future__ import annotations

import hashlib
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_replay_failure_v7 as V7  # noqa: E402
import linux_retained_driver_v5 as DRIVER  # noqa: E402


class FailureV7Tests(unittest.TestCase):
    def test_successor_pins_v9_and_wrong_anchor_creates_nothing(self):
        self.assertEqual(hashlib.sha256(V7.V6_PATH.read_bytes()).hexdigest(), V7.V6_SHA256)
        self.assertEqual(hashlib.sha256(V7.PHASE_A_V9_PATH.read_bytes()).hexdigest(), V7.PHASE_A_V9_SHA256)
        self.assertEqual(V7._load_v6().SCHEMA, V7.SCHEMA)
        root = Path(DRIVER.AUTHORITY_ROOT).parent / V7.DIRECTORY_NAME
        self.assertFalse(root.exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V7.load_approved_wrapper("0" * 64)
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
