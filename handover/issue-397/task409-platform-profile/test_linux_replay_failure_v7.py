#!/usr/bin/env python3
"""Confirm the v9 failure interface remains absent before a v9 anchor."""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_replay_failure_v7 as V7  # noqa: E402
import linux_retained_driver_v5 as DRIVER  # noqa: E402


class FailureV7Tests(unittest.TestCase):
    def test_successor_pins_v9_and_wrong_anchor_creates_nothing(self):
        self.assertEqual(hashlib.sha256(V7._stable_bytes(V7.V6_PATH, V7.V6_SHA256, "v6")).hexdigest(), V7.V6_SHA256)
        self.assertEqual(hashlib.sha256(V7._stable_bytes(V7.PHASE_A_V9_PATH, V7.PHASE_A_V9_SHA256, "v9")).hexdigest(), V7.PHASE_A_V9_SHA256)
        self.assertEqual(V7._load_v6().SCHEMA, V7.SCHEMA)
        root = Path(DRIVER.AUTHORITY_ROOT).parent / V7.DIRECTORY_NAME
        self.assertFalse(root.exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V7.load_approved_wrapper("0" * 64)
        self.assertFalse(root.exists())

    def test_verified_v9_buffer_rejects_after_read_replacement_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "phase.py"; source.write_bytes(b"marker = 'trusted'\n")
            replacement = root / "replacement.py"; replacement.write_bytes(b"raise RuntimeError('replacement executed')\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            original = V7._stable_bytes
            def replace_after_read(path, expected, label, after_read=None):
                if label == "Phase A v9 adapter":
                    return original(path, expected, label, lambda: os.replace(replacement, source))
                return original(path, expected, label, after_read)
            with mock.patch.object(V7, "PHASE_A_V9_PATH", source), mock.patch.object(V7, "PHASE_A_V9_SHA256", digest), mock.patch.object(V7, "_stable_bytes", replace_after_read):
                with self.assertRaisesRegex(RuntimeError, "changed during read"):
                    V7._load_v9()
            self.assertIn(b"replacement executed", source.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
