"""Regression tests for the offline synthetic C-16 resolver proof."""
from __future__ import annotations
import copy, json, os, py_compile, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
FIXTURE_DIR=Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path: sys.path.insert(0,str(FIXTURE_DIR))
import validate  # noqa: E402

class DeepLinkResolutionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls)->None:
  cls.store=validate.ArtifactStore(); cls.document=validate.parse_json_bytes(cls.store.read(FIXTURE_DIR/'cases.json').data); cls.lineage=validate.pinned_lineage(cls.store)
 def cli(self,optimized:bool=False,*args:str)->subprocess.CompletedProcess[str]:
  command=[sys.executable]+(['-O'] if optimized else[])+[str(FIXTURE_DIR/'validate.py'),*args]
  return subprocess.run(command,capture_output=True,text=True,check=False)
 def test_checked_in_cli_normal_and_optimized(self)->None:
  for optimized in (False,True):
   result=self.cli(optimized); self.assertEqual(result.returncode,0,result.stdout+result.stderr); self.assertEqual(result.stderr,''); self.assertEqual(result.stdout,'deep_link_resolution_validation=ok cases=18 mutations=20\n')
 def test_unknown_cli_args_are_fixed_and_redacted(self)->None:
  secret=f'https://synthetic.hermternal.test/v1/c/{validate.ROOT_ID}'
  expected=json.dumps(validate.ERROR_PAYLOAD,separators=(',',':'),sort_keys=True)+'\n'
  for optimized in (False,True):
   result=self.cli(optimized,'--unknown',secret); self.assertEqual(result.returncode,1); self.assertEqual(result.stdout,expected); self.assertEqual(result.stderr,''); self.assertNotIn(secret,result.stdout+result.stderr); self.assertNotIn(validate.ROOT_ID,result.stdout+result.stderr)
 def test_all_traces_are_deterministic_and_offline(self)->None:
  self.assertEqual(tuple(case['id'] for case in self.document['cases']),validate.CASE_IDS)
  for case in self.document['cases']:
   actual=validate.reduce_case(case,self.lineage); self.assertTrue(validate.strict_equal(actual,case['expected']),case['id']); self.assertEqual(actual['session_creations'],0); self.assertEqual(actual['shares'],0); self.assertFalse(actual['transcript_mirror']); self.assertFalse(actual['network'])
 def test_latest_descendant_uses_ordering_not_constant(self)->None:
  cases={case['id']:case for case in self.document['cases']}; ordered=copy.deepcopy(cases['latest-descendant-ordered-branching']); self.assertEqual(ordered['expected']['opened_session_id'],validate.BRANCH_ID)
  for item in ordered['lineage_ordering']:
   if item['session_id']==validate.SIBLING_ID: item['sequence']=4
  changed=validate.reduce_case(ordered,self.lineage); self.assertEqual(changed['opened_session_id'],validate.SIBLING_ID); self.assertNotEqual(changed['opened_session_id'],validate.BRANCH_ID)
  self.assertEqual(cases['latest-descendant-order-tie-fails-closed']['expected']['decision'],'lineage_unavailable'); self.assertEqual(cases['latest-descendant-malformed-order-fails-closed']['expected']['decision'],'lineage_unavailable')
 def test_authorization_safe_results_match(self)->None:
  cases={case['id']:case for case in self.document['cases']}; self.assertTrue(validate.strict_equal(cases['unknown-session-safe-not-found']['expected'],cases['unauthorized-session-safe-not-found']['expected']))
 def test_cleanup_erases_all_target_data(self)->None:
  terminal={'opened','failed','expired','signed_out'}
  for case in self.document['cases']:
   result=case['expected']
   if result['final_state'] in terminal:
    for key in ('pending_link','pending_session_id','pending_message_id','deadline_seconds'): self.assertIsNone(result[key],f"{case['id']}:{key}")
 def test_reload_reparses_and_reauthenticates(self)->None:
  case=next(c for c in self.document['cases'] if c['id']=='direct-reload-reparses-and-reauthenticates'); result=case['expected']; self.assertEqual(result['parse_attempts'],2); self.assertEqual(result['authentication_checks'],2); self.assertEqual(result['lookup_attempts'],2); self.assertEqual(result['effects'].count('grammar_validated'),2); self.assertEqual(result['effects'].count('authentication_confirmed'),2)
 def test_deadline_is_explicit_and_inclusive(self)->None:
  cases={case['id']:case for case in self.document['cases']}; expired=cases['pending-target-expires-at-deadline']['expected']; early=cases['pending-target-before-deadline-stays-pending']['expected']; self.assertEqual(expired['decision'],'target_expired'); self.assertIsNone(expired['deadline_seconds']); self.assertEqual(early['final_state'],'auth_pending'); self.assertEqual(early['deadline_seconds'],1300); self.assertIn('deadline_not_reached',early['effects'])
 def test_r7_p95_matches_repository_method(self)->None:
  evidence=validate.parse_json_bytes(validate.read_artifact_once(FIXTURE_DIR/'baseline-evidence.json').data); validate.validate_evidence(evidence); self.assertEqual(evidence['normal']['distribution']['p95'],559.644058); self.assertEqual(evidence['optimized']['distribution']['p95'],222.135383)
 def test_streaming_limit_stops_before_full_allocation(self)->None:
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'large.json'; path.write_bytes(b'x'*10_000)
   with self.assertRaises(validate.ContractError): validate.read_artifact_once(path,4096)
 def test_symlink_and_path_replacement_are_rejected(self)->None:
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory); real=root/'real'; real.write_text('{}'); link=root/'link'; link.symlink_to(real)
   with self.assertRaises(validate.ContractError): validate.read_artifact_once(link)
   path=root/'race'; replacement=root/'replacement'; path.write_bytes(b'a'*70_000); replacement.write_bytes(b'b'*70_000)
   original_read=os.read; changed=False
   def racing_read(fd:int,size:int)->bytes:
    nonlocal changed
    chunk=original_read(fd,size)
    if chunk and not changed: changed=True; os.replace(replacement,path)
    return chunk
   with mock.patch('validate.os.read',side_effect=racing_read):
    with self.assertRaises(validate.ContractError): validate.read_artifact_once(path)
 def test_store_reads_each_path_once(self)->None:
  store=validate.ArtifactStore(); path=FIXTURE_DIR/'cases.json'
  with mock.patch('validate.read_artifact_once',wraps=validate.read_artifact_once) as reader:
   first=store.read(path); second=store.read(path); self.assertIs(first,second); self.assertEqual(reader.call_count,1)
 def test_duplicate_nonfinite_exact_type_and_depth_rejected(self)->None:
  with self.assertRaises(validate.ContractError): validate.parse_json_bytes(b'{"a":1,"a":2}')
  with self.assertRaises(validate.ContractError): validate.parse_json_bytes(b'{"a":NaN}')
  changed=copy.deepcopy(self.document); changed['pending_ttl_seconds']=True
  with self.assertRaises(validate.ContractError): validate.validate_document(changed,validate.ArtifactStore())
  deep=None
  for _ in range(validate.MAX_DEPTH+1): deep=[deep]
  with self.assertRaises(validate.ContractError): validate.validate_tree(deep)
 def test_external_review_root_blocks_coordinated_rebinding(self)->None:
  changed=copy.deepcopy(self.document); changed['cases'][0]['notes']='coordinated drift'
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory); cases=root/'cases.json'; evidence=root/'evidence.json'; baseline=root/'baseline.json'; cases.write_text(json.dumps(changed)); evidence.write_bytes((FIXTURE_DIR/'baseline-evidence.json').read_bytes()); baseline.write_bytes((FIXTURE_DIR/'validation-baseline.json').read_bytes())
   with mock.patch.object(validate,'REVIEW_ROOT_DIGEST_PARTS',('0'*16,)*4):
    with self.assertRaises(validate.ContractError): validate.validate_all(cases,baseline,evidence)
 def test_review_root_binds_validator_and_all_evidence(self)->None:
  count,mutations=validate.validate_all(FIXTURE_DIR/'cases.json',FIXTURE_DIR/'validation-baseline.json',FIXTURE_DIR/'baseline-evidence.json'); self.assertEqual((count,mutations),(18,20))
 def test_mutations_and_compile(self)->None:
  self.assertEqual(validate.validate_mutations(self.document),20); py_compile.compile(str(FIXTURE_DIR/'validate.py'),doraise=True); py_compile.compile(str(FIXTURE_DIR/'test_validate.py'),doraise=True)

if __name__=='__main__': unittest.main()
