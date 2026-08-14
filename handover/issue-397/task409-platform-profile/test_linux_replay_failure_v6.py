#!/usr/bin/env python3
"""Confirm v6 failure publication remains absent without an approved v8 anchor."""
from __future__ import annotations
import hashlib, os, sys, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent; sys.path.insert(0,os.fspath(HERE))
import linux_replay_failure_v6 as V6  # noqa:E402
import linux_retained_driver_v5 as DRIVER  # noqa:E402
class FailureV6Tests(unittest.TestCase):
 def test_successor_authenticates_and_wrong_anchor_creates_nothing(self):
  self.assertEqual(hashlib.sha256(V6.V5_PATH.read_bytes()).hexdigest(),V6.V5_SHA256); self.assertEqual(hashlib.sha256(V6.PHASE_A_V8_PATH.read_bytes()).hexdigest(),V6.PHASE_A_V8_SHA256)
  self.assertEqual(V6._load_v5().SCHEMA,V6.SCHEMA)
  root=Path(DRIVER.AUTHORITY_ROOT).parent/V6.DIRECTORY_NAME; self.assertFalse(root.exists())
  with self.assertRaises((RuntimeError,FileNotFoundError)): V6.load_approved_wrapper("0"*64)
  self.assertFalse(root.exists())
if __name__=="__main__": unittest.main(verbosity=2)
