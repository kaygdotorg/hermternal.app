#!/usr/bin/env python3
"""Tests for the normal non-force dev-update verifier."""
from __future__ import annotations
import importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent; SPEC=importlib.util.spec_from_file_location("dev_update", HERE/"dev_update.py"); assert SPEC and SPEC.loader
MOD=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=MOD; SPEC.loader.exec_module(MOD)

class Tests(unittest.TestCase):
    def setUp(self):
        gates=[{"id":f"g{i}","status":"passed"} for i in range(14)]
        value={"schema":MOD.OFFLINE_SCHEMA,"status":"passed","offline":True,"credentials":"not-used","network":"not-used","repository":"/private/tmp/repo","final_head":"4"*40,"final_tree":"5"*40,"main_unchanged":MOD.PROTECTED_MAIN,"dev_target":"4"*40,"gates":gates}
        self.raw=(json.dumps(value)+"\n").encode(); self.candidate=MOD.validate_offline_evidence(self.raw); self.temp=tempfile.TemporaryDirectory(); self.repo=Path(self.temp.name)
    def tearDown(self): self.temp.cleanup()
    def runner(self, argv, **kwargs):
        args=tuple(argv)[3:]; values={("rev-parse","refs/remotes/origin/dev^{commit}"):MOD.BASE_DEV,("rev-parse","refs/remotes/origin/main^{commit}"):MOD.PROTECTED_MAIN,("rev-parse",f"{self.candidate.commit}^{{commit}}"):self.candidate.commit,("rev-parse",f"{self.candidate.commit}^{{tree}}"):self.candidate.tree,("status","--porcelain=v1","--untracked-files=all"):"",("merge-base","--is-ancestor",MOD.BASE_DEV,self.candidate.commit):"",("ls-remote","--refs","origin","refs/heads/dev"):f"{self.candidate.commit}\trefs/heads/dev",("ls-remote","--refs","origin","refs/heads/main"):f"{MOD.PROTECTED_MAIN}\trefs/heads/main"}
        return subprocess.CompletedProcess(argv,0,(values[args]+"\n").encode(),b"")
    def test_preflight_returns_only_normal_push_after_every_gate(self):
        calls=[]
        def run(argv,**kwargs): calls.append(tuple(argv)); return self.runner(argv,**kwargs)
        plan=MOD.preflight(self.candidate,self.repo,run); self.assertEqual(len(calls),6); self.assertEqual(plan["push_argv"],["/usr/bin/git","push","--porcelain","origin",f"{self.candidate.commit}:refs/heads/dev"]); self.assertFalse(plan["push_executed"])
        evidence=MOD.verify_post_push(plan,self.repo,run); self.assertEqual(evidence["push_mode"],"normal-non-force")
    def test_rejects_force_lease_wildcard_deletion_and_other_refs(self):
        attacks=(f"+{self.candidate.commit}:refs/heads/dev",f"{self.candidate.commit}:refs/heads/*",f":refs/heads/dev",f"{self.candidate.commit}:refs/heads/main",f"{self.candidate.commit}:refs/tags/x",f"{self.candidate.commit}:refs/heads/dev --force-with-lease")
        for value in attacks:
            with self.subTest(value=value), self.assertRaises(MOD.Reject): MOD.validate_refspec(value,self.candidate)
    def test_no_push_argv_on_any_failed_preflight_gate(self):
        for fail_at in range(6):
            calls=[]
            def run(argv,**kwargs):
                calls.append(tuple(argv)); result=self.runner(argv,**kwargs)
                if len(calls)-1==fail_at: result.returncode=1
                return result
            with self.subTest(fail_at=fail_at), self.assertRaises(MOD.Reject): MOD.preflight(self.candidate,self.repo,run)
            self.assertFalse(any("push" in call for call in calls))
    def test_rejects_bad_offline_evidence_and_remote_readback(self):
        value=json.loads(self.raw); value["gates"][0]["status"]="skipped"
        with self.assertRaises(MOD.Reject): MOD.validate_offline_evidence(json.dumps(value).encode())
        plan=MOD.preflight(self.candidate,self.repo,self.runner)
        def wrong(argv,**kwargs):
            result=self.runner(argv,**kwargs)
            if "refs/heads/main" in argv: result.stdout=("f"*40+"\trefs/heads/main\n").encode()
            return result
        with self.assertRaisesRegex(MOD.Reject,"main changed"): MOD.verify_post_push(plan,self.repo,wrong)
if __name__=="__main__": unittest.main(verbosity=2)
