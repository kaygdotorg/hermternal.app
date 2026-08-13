#!/usr/bin/env python3
"""Offline authority tests; no replay or Git mutation is run."""
from __future__ import annotations
import hashlib, importlib.util, os, sys, unittest
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent; SPEC=importlib.util.spec_from_file_location("replay",HERE/"replay_result_successor.py"); assert SPEC and SPEC.loader
MOD=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=MOD; SPEC.loader.exec_module(MOD)
class Tests(unittest.TestCase):
 def test_real_integrated_authority_and_prepare(self):
  authority=MOD.prepare_authority_only(); self.assertNotEqual(authority.root,MOD.FINAL_ROOT); self.assertEqual(authority.argv[-1],"-s"); self.assertTrue(authority.stdin.endswith(b"\n")); self.assertEqual(authority.base,"729f2613af2b78d58b07918478e9102d5716f367")
 def test_wrong_root_and_synthetic_provenance_reject(self):
  with mock.patch.object(MOD,"FINAL_ROOT",MOD.BASE/"wrong"):
   with self.assertRaises(MOD.Reject): MOD.load_approved_authority()
  provenance=MOD.FINAL_ROOT/"provenance-manifest.json"; raw=provenance.read_bytes()
  with mock.patch.object(MOD,"stable_read",side_effect=lambda path,label,*_mode: b"{}" if Path(path)==provenance else raw):
   with self.assertRaises(MOD.Reject): MOD.load_approved_authority()
 def test_mutable_reviewer_and_semantic_drift_reject(self):
  with mock.patch.object(MOD,"GIT_AUTHORITY_SHA","0"*64):
   with self.assertRaises(MOD.Reject): MOD.load_approved_authority()
  candidate=MOD.FINAL_ROOT/"candidate-five.json"; original=MOD.stable_read
  def changed(path,label,*mode):
   raw=original(path,label,*mode)
   return raw.replace(b'"protected_main_commit": "3eb',b'"protected_main_commit": "4eb') if Path(path)==candidate else raw
  with mock.patch.object(MOD,"stable_read",side_effect=changed):
   with self.assertRaises(MOD.Reject): MOD.load_approved_authority()
 def test_execution_is_blocked(self):
  with self.assertRaisesRegex(MOD.Reject,"blocked"): MOD.retained_replay_is_not_ready()
if __name__=="__main__": unittest.main(verbosity=2)
