#!/usr/bin/env python3
"""Execute the shared root-shape parser against both complete ledger calls."""
from __future__ import annotations
import hashlib, os, re, shutil, stat, subprocess, sys, tempfile, time, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent; sys.path.insert(0,os.fspath(HERE))
import linux_root_shape_authority_v4 as AUTHORITY  # noqa:E402
import linux_retained_driver_v6 as DRIVER  # noqa:E402
class RootShapeAuthorityV4Tests(unittest.TestCase):
 def setUp(self): self.shell=AUTHORITY.generate()["shell"]
 def _function(self):
  match=re.search(rb"assert_root_shape\(\) \{\n(.*?)\n\}\n",self.shell,re.S); self.assertIsNotNone(match); return b"assert_root_shape() {\n"+match.group(1)+b"\n}\n"
 def _identity(self,path,lower_nlink=True):
  value=os.lstat(path); return [str(value.st_dev),str(value.st_ino),str(value.st_uid),format(stat.S_IMODE(value.st_mode),'04o'),str(max(1,value.st_nlink-1) if lower_nlink else value.st_nlink)]
 def _environment(self):
  source=tempfile.mkdtemp(prefix="issue397-root-shape-source-")
  clean=f"/tmp/hermternal-task409-final-clean-primary.{time.time_ns()}"; replay=f"/tmp/hermternal-task409-final-replay.{time.time_ns()+1}"; Path(clean).mkdir(mode=0o700); Path(replay).mkdir(mode=0o700)
  for path in (source,clean,replay): self.addCleanup(shutil.rmtree,path,ignore_errors=True)
  clean_child=Path(clean)/"repository"; replay_child=Path(replay)/"replay"; clean_child.mkdir(mode=0o700); replay_child.mkdir(mode=0o700)
  values={"PYTHON":sys.executable,"SOURCE":source,"CLEAN_PRIMARY_ROOT":clean,"CLEAN_PRIMARY":os.fspath(clean_child),"REPLAY_ROOT":replay,"REPLAY":os.fspath(replay_child),"CLEAN_PRIMARY_ROOT_BOUND":"1","CLEAN_PRIMARY_REPOSITORY_BOUND":"1","CLEAN_PRIMARY_BOUND":"1","REPLAY_ROOT_BOUND":"1","REPLAY_CHECKOUT_BOUND":"1","REPLAY_CHECKOUT_PRESENT":"1","REPLAY_GIT_BOUND":"1"}
  for prefix,root,child in (("CLEAN_PRIMARY",clean,clean_child),("REPLAY",replay,replay_child)):
   for key,data in (("PARENT",self._identity(Path(root).parent)),("ROOT",self._identity(root)),("REPOSITORY" if prefix=="CLEAN_PRIMARY" else "CHECKOUT",self._identity(child))):
    for field,value in zip(("DEVICE","INODE","UID","MODE","NLINK"),data): values[f"{prefix}_{key}_{field}"]=value
   values[f"{prefix}_ROOT_REALPATH"]=root
  return values
 def _run(self,values): return subprocess.run(["/bin/bash","-c",b"fail(){ echo \"$*\" >&2; exit 99; }\n"+self._function()+b"assert_root_shape"],env={**os.environ,**values},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 def test_deterministic_parity_manifest_and_both_calls_accept_nlink_growth(self):
  first=AUTHORITY.generate(); self.assertEqual(first,AUTHORITY.generate()); self.assertEqual(first["shell"],(AUTHORITY.AUTHORITY_ROOT/"candidate-five.sh").read_bytes()); result=self._run(self._environment()); self.assertEqual(result.returncode,0,result.stderr.decode())
  self.assertEqual(DRIVER.load_driver().load_frozen_authority().shell.raw,first["shell"])
 def test_root_realpath_substitution_and_each_child_identity_field_reject(self):
  values=self._environment(); wrong=dict(values); wrong["CLEAN_PRIMARY_ROOT_REALPATH"]=values["REPLAY_ROOT"]; self.assertNotEqual(self._run(wrong).returncode,0)
  for field in ("DEVICE","INODE","UID","MODE"):
   wrong=dict(values); key=f"CLEAN_PRIMARY_REPOSITORY_{field}"; wrong[key]="999999" if field!="MODE" else "0755"; self.assertNotEqual(self._run(wrong).returncode,0)
 def test_exact_one_shared_parser_transform(self):
  self.assertEqual(self.shell.count(AUTHORITY.NEW_PARSER),1); self.assertNotIn(AUTHORITY.OLD_PARSER,self.shell); self.assertEqual(self.shell.count(b"verify_root_real("),3)
if __name__=="__main__": unittest.main(verbosity=2)
