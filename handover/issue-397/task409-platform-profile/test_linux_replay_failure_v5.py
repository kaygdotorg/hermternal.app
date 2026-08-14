#!/usr/bin/env python3
"""Failure successor remains absent until an approved v7 anchor exists."""
from __future__ import annotations
import hashlib, os, sys, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent; sys.path.insert(0,os.fspath(HERE))
import linux_replay_failure_v5 as V5  # noqa:E402
import linux_retained_driver_v4 as DRIVER  # noqa:E402
class FailureV5Tests(unittest.TestCase):
 def test_successor_authenticates_and_wrong_anchor_creates_nothing(self):
  self.assertEqual(hashlib.sha256(V5.V4_PATH.read_bytes()).hexdigest(),V5.V4_SHA256); self.assertEqual(hashlib.sha256(V5.PHASE_A_V7_PATH.read_bytes()).hexdigest(),V5.PHASE_A_V7_SHA256)
  self.assertEqual(V5._load_v4().SCHEMA,V5.SCHEMA)
  root=Path(DRIVER.platform_profile.load().source_repository).parent/V5.DIRECTORY_NAME; self.assertFalse(root.exists())
  with self.assertRaises((RuntimeError,FileNotFoundError)): V5.load_approved_wrapper("0"*64)
  self.assertFalse(root.exists())
if __name__=="__main__": unittest.main(verbosity=2)
