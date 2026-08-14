#!/usr/bin/env python3
"""Run a disposable v10 Phase A-to-anchor and load the outer failure chain."""
from __future__ import annotations
import hashlib, os, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent; sys.path.insert(0,os.fspath(HERE))
import linux_phase_a_v10 as V10  # noqa:E402
import linux_replay_failure_v9 as FAILURE  # noqa:E402
import linux_replay_wrapper_v6 as WRAPPER  # noqa:E402
class PhaseAV10Tests(unittest.TestCase):
 def guarded(self,r):
  i={"st_dev":1,"st_ino":2,"st_uid":os.getuid(),"st_gid":os.getgid(),"st_mode":0o700,"st_size":4096,"st_nlink":2,"st_mtime_ns":3,"st_ctime_ns":4}; b=r._binding_record(i)
  return {"path":str(r.REPOSITORY_ROOT),"binding":b,"parent_binding":{**b,"st_ino":5},"head":r.FROZEN_COMMIT,"tree":r.FROZEN_TREE,"detached":True,"source_repository":{"path":str(r.SOURCE_REPOSITORY_ROOT),"binding":{**b,"st_ino":6}},"git_common_dir":{"path":str(r.GIT_COMMON_DIR),"binding":{**b,"st_ino":7}},"git_object_dir":{"path":str(r.GIT_OBJECT_DIR),"binding":{**b,"st_ino":8}},"git_worktree_dir":{"path":str(r.GIT_WORKTREE_DIR),"binding":{**b,"st_ino":9}}}
 def test_disposable_phase_anchor_and_outer_failure_load(self):
  self.assertEqual(hashlib.sha256(V10._stable_bytes(V10.V9_PATH,V10.V9_SHA256,"v9")).hexdigest(),V10.V9_SHA256); self.assertFalse(WRAPPER.preflight()["execution_enabled"])
  base=V10._load_v9(); r=base.load_runner()
  with tempfile.TemporaryDirectory(prefix=".phase-a-v10-test-",dir=Path(r.REPOSITORY_ROOT).parent) as parent:
   r.EXTERNAL_ROOT=Path(parent)/"external"; modules=r.load_modules(); verifier=lambda:self.guarded(r)
   phase=r.phase_a(modules,repository_root=r.REPOSITORY_ROOT,external_root=r.EXTERNAL_ROOT,worktree_verifier=verifier); phase_snapshot=r.stable_read(r.EXTERNAL_ROOT/"evidence"/r.PHASE_A_RECORD,"phase")
   anchor=r.anchor(modules,repository_root=r.REPOSITORY_ROOT,external_root=r.EXTERNAL_ROOT,expected_phase_a_sha256=phase_snapshot.sha256,worktree_verifier=verifier); anchor_snapshot=r.stable_read(r.EXTERNAL_ROOT/"evidence"/r.ANCHOR_RECORD,"anchor")
   v8=base._load_v8(); v7=v8._load_v7(); v3=v7._load_v3(); v3.load_runner=lambda:r; v7._load_v3=lambda:v3; v8._load_v7=lambda:v7; base._load_v8=lambda:v8
   with mock.patch.object(V10,"_load_v9",return_value=base): wrapper,authority=V10.load_approved_wrapper(anchor_snapshot.sha256,V10._adapter_sha256())
   with self.assertRaises((RuntimeError,FileNotFoundError)): FAILURE.load_approved_wrapper("0"*64)
  self.assertEqual(phase["schema"],V10.V10_EVIDENCE_SCHEMA); self.assertEqual(anchor["prior_sha256"],phase_snapshot.sha256); self.assertTrue(callable(wrapper.execute_and_publish)); self.assertEqual(wrapper.PHASE_A_RUNNER_PATH,Path(V10.__file__))
if __name__=="__main__": unittest.main(verbosity=2)
