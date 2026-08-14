#!/usr/bin/env python3
"""Exercise the disposable v8 Phase A-to-anchor lifecycle only."""
from __future__ import annotations
import hashlib, os, sys, tempfile, unittest
from pathlib import Path
HERE = Path(__file__).resolve().parent; sys.path.insert(0, os.fspath(HERE))
import linux_phase_a_v8 as V8  # noqa: E402
import linux_replay_wrapper_v5 as WRAPPER  # noqa: E402

class PhaseAV8Tests(unittest.TestCase):
 def guarded(self, r):
  i={"st_dev":1,"st_ino":2,"st_uid":os.getuid(),"st_gid":os.getgid(),"st_mode":0o700,"st_size":4096,"st_nlink":2,"st_mtime_ns":3,"st_ctime_ns":4}; b=r._binding_record(i)
  return {"path":str(r.REPOSITORY_ROOT),"binding":b,"parent_binding":{**b,"st_ino":5},"head":r.FROZEN_COMMIT,"tree":r.FROZEN_TREE,"detached":True,"source_repository":{"path":str(r.SOURCE_REPOSITORY_ROOT),"binding":{**b,"st_ino":6}},"git_common_dir":{"path":str(r.GIT_COMMON_DIR),"binding":{**b,"st_ino":7}},"git_object_dir":{"path":str(r.GIT_OBJECT_DIR),"binding":{**b,"st_ino":8}},"git_worktree_dir":{"path":str(r.GIT_WORKTREE_DIR),"binding":{**b,"st_ino":9}}}
 def test_disposable_lifecycle_and_disabled_preflight(self):
  self.assertEqual(hashlib.sha256(V8.V7_PATH.read_bytes()).hexdigest(),V8.V7_SHA256)
  result=WRAPPER.preflight(); self.assertTrue(result["phase_a_v8_required"]); self.assertFalse(result["execution_enabled"]); self.assertNotIn("phase_a_v3_required",result)
  base=V8._load_v7(); r=base.load_runner()
  with tempfile.TemporaryDirectory(prefix=".phase-a-v8-test-",dir=Path(r.REPOSITORY_ROOT).parent) as parent:
   r.EXTERNAL_ROOT=Path(parent)/"external"; modules=r.load_modules(); verifier=lambda:self.guarded(r)
   phase=r.phase_a(modules,repository_root=r.REPOSITORY_ROOT,external_root=r.EXTERNAL_ROOT,worktree_verifier=verifier); snap=r.stable_read(r.EXTERNAL_ROOT/"evidence"/r.PHASE_A_RECORD,"phase")
   anchor=r.anchor(modules,repository_root=r.REPOSITORY_ROOT,external_root=r.EXTERNAL_ROOT,expected_phase_a_sha256=snap.sha256,worktree_verifier=verifier)
   self.assertEqual(phase["schema"],V8.V8_EVIDENCE_SCHEMA); self.assertEqual(anchor["prior_sha256"],snap.sha256)
if __name__ == "__main__": unittest.main(verbosity=2)
