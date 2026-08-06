"""Regression tests for the offline synthetic C-16 resolver proof."""
from __future__ import annotations
import copy, hashlib, importlib.util, json, os, py_compile, subprocess, sys, tempfile, time, unittest
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
   result=self.cli(optimized); self.assertEqual(result.returncode,0,result.stdout+result.stderr); self.assertEqual(result.stderr,''); self.assertEqual(result.stdout,'deep_link_resolution_validation=ok cases=26 mutations=20\n')
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
  malformed=(
   'latest-descendant-order-tie-fails-closed','latest-descendant-malformed-order-fails-closed',
   'latest-descendant-decreasing-order-fails-closed','latest-descendant-cycle-fails-closed',
   'latest-descendant-missing-parent-fails-closed','latest-descendant-wrong-root-fails-closed',
   'latest-descendant-duplicate-node-fails-closed',
  )
  for case_id in malformed: self.assertEqual(cases[case_id]['expected']['decision'],'lineage_unavailable')
  root_high=copy.deepcopy(cases['latest-descendant-ordered-branching']); root_high['events']=root_high['events'][:2]
  for item in root_high['lineage_ordering']:
   if item['session_id']==validate.ROOT_ID: item['sequence']=9
  self.assertEqual(validate.reduce_case(root_high,self.lineage)['decision'],'lineage_unavailable')
 def test_latest_descendant_requires_pinned_nodes_and_edges(self)->None:
  cases={case['id']:case for case in self.document['cases']}; base=copy.deepcopy(cases['latest-descendant-ordered-branching']); base['events']=base['events'][:2]
  mutations=[]
  parentless=copy.deepcopy(base)
  for item in parentless['lineage_ordering']:
   if item['session_id']==validate.BRANCH_ID: item['parent_id']=None
  mutations.append(parentless)
  self_rooted=copy.deepcopy(base)
  for item in self_rooted['lineage_ordering']:
   if item['session_id']==validate.BRANCH_ID: item['root_id']=validate.BRANCH_ID
  mutations.append(self_rooted)
  fabricated=copy.deepcopy(base); fabricated['lineage_ordering'][-1]['session_id']='session-fabricated-0000000000000000000000000000000000000004'; mutations.append(fabricated)
  for changed in mutations: self.assertEqual(validate.reduce_case(changed,self.lineage)['decision'],'lineage_unavailable')
 def test_authorization_safe_results_match(self)->None:
  cases={case['id']:case for case in self.document['cases']}; self.assertTrue(validate.strict_equal(cases['unknown-session-safe-not-found']['expected'],cases['unauthorized-session-safe-not-found']['expected']))
 def test_aggregate_credential_scanner_accepts_cases(self)->None:
  path=validate.REPO_ROOT/'contracts/fixtures/validator/validate.py'; spec=importlib.util.spec_from_file_location('aggregate_fixture_validator',path); self.assertIsNotNone(spec); self.assertIsNotNone(spec.loader); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module._validate_redaction_tree(self.document)
 def test_cleanup_erases_all_target_data(self)->None:
  terminal={'opened','failed','expired','signed_out','cancelled'}
  for case in self.document['cases']:
   result=case['expected']
   if result['final_state'] in terminal:
    for key in ('link_input','pending_link','pending_session_id','pending_message_id','deadline_seconds'): self.assertIsNone(result[key],f"{case['id']}:{key}")
  cancelled=next(c for c in self.document['cases'] if c['id']=='cancel-clears-pending-target')['expected']; self.assertEqual(cancelled['decision'],'cancelled')
 def test_reload_reparses_and_reauthenticates(self)->None:
  case=next(c for c in self.document['cases'] if c['id']=='direct-reload-reparses-and-reauthenticates'); result=case['expected']; self.assertEqual(result['parse_attempts'],2); self.assertEqual(result['authentication_checks'],2); self.assertEqual(result['lookup_attempts'],2); self.assertEqual(result['effects'].count('grammar_validated'),2); self.assertEqual(result['effects'].count('authentication_confirmed'),2)
 def test_reload_clears_prior_success_before_new_outcome(self)->None:
  cases={case['id']:case['expected'] for case in self.document['cases']}
  success=cases['reload-success-clears-prior-presentation']; self.assertEqual(success['decision'],'session_opened'); self.assertEqual(success['opened_session_id'],validate.ROOT_ID); self.assertIsNone(success['focused_message_id']); self.assertEqual(success['focus'],'session'); self.assertIn('prior_presentation_erased',success['effects'])
  failure=cases['reload-failure-clears-prior-presentation']; self.assertEqual(failure['decision'],'invalid_link'); self.assertEqual(failure['final_state'],'failed'); self.assertIn('prior_presentation_erased',failure['effects'])
  for key in ('opened_session_id','root_id','parent_id','focused_message_id'): self.assertIsNone(failure[key])
  self.assertEqual(failure['focus'],'none')
 def test_deadline_is_explicit_and_inclusive(self)->None:
  cases={case['id']:case for case in self.document['cases']}; expired=cases['pending-target-expires-at-deadline']['expected']; early=cases['pending-target-before-deadline-stays-pending']['expected']; self.assertEqual(expired['decision'],'target_expired'); self.assertIsNone(expired['deadline_seconds']); self.assertEqual(early['final_state'],'auth_pending'); self.assertEqual(early['deadline_seconds'],1300); self.assertIn('deadline_not_reached',early['effects'])
 def test_exact_message_id_is_focused(self)->None:
  focused=[c['expected'] for c in self.document['cases'] if c['expected']['decision']=='message_focused']
  self.assertTrue(focused)
  for result in focused: self.assertEqual(result['focused_message_id'],validate.MESSAGE_ID)
 def test_every_pending_path_expires_at_second_300(self)->None:
  link=f'https://synthetic.hermternal.test/v1/c/{validate.ROOT_ID}'
  message=f'{link}/m/{validate.MESSAGE_ID}'
  paths={
   'authenticated':(False,link,[('receive',1000),('authenticated',1300)]),
   'lookup_present':(True,link,[('receive',1000),('lookup_present',1300)]),
   'lookup_missing':(True,link,[('receive',1000),('lookup_missing',1300)]),
   'lookup_denied':(True,link,[('receive',1000),('lookup_denied',1300)]),
   'message_present':(True,message,[('receive',1000),('lookup_present',1001),('message_present',1300)]),
   'message_missing':(True,message,[('receive',1000),('lookup_present',1001),('message_missing',1300)]),
   'complete':(True,link,[('receive',1000),('lookup_present',1001),('complete',1300)]),
   'interrupt':(True,link,[('receive',1000),('interrupt',1300)]),
   'recover':(True,link,[('receive',1000),('interrupt',1001),('recover',1300)]),
   'logout':(False,link,[('receive',1000),('logout',1300)]),
   'cancel':(False,link,[('receive',1000),('cancel',1300)]),
  }
  for name,(authenticated,target,events) in paths.items():
   resolver=validate.Resolver(target,authenticated,'exact',[])
   for kind,at in events: resolver.apply({'type':kind,'at_seconds':at},self.lineage)
   result=resolver.result(); self.assertEqual(result['decision'],'target_expired',name); self.assertEqual(result['final_state'],'expired',name)
   for key in ('link_input','pending_link','pending_session_id','pending_message_id','deadline_seconds'): self.assertIsNone(result[key],f'{name}:{key}')
 def test_receive_time_cannot_overflow_deadline(self)->None:
  link=f'https://synthetic.hermternal.test/v1/c/{validate.ROOT_ID}'
  for now in (validate.MAX_INTEGER,validate.MAX_INTEGER-validate.PENDING_TTL_SECONDS+1):
   resolver=validate.Resolver(link,True,'exact',[])
   with self.assertRaises(validate.ContractError): resolver.apply({'type':'receive','at_seconds':now},self.lineage)
  resolver=validate.Resolver(link,False,'exact',[]); resolver.apply({'type':'receive','at_seconds':validate.MAX_INTEGER-validate.PENDING_TTL_SECONDS},self.lineage); self.assertEqual(resolver.deadline_seconds,validate.MAX_INTEGER)
 def test_r7_p95_matches_repository_method(self)->None:
  evidence=validate.parse_json_bytes(validate.read_artifact_once(FIXTURE_DIR/'baseline-evidence.json').data); validate.validate_evidence(evidence); self.assertEqual(evidence['normal']['distribution']['p95'],559.644058); self.assertEqual(evidence['optimized']['distribution']['p95'],222.135383)
 def test_streaming_limit_stops_before_full_allocation(self)->None:
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'large.json'; path.write_bytes(b'x'*10_000)
   with self.assertRaises(validate.ContractError): validate.read_artifact_once(path,4096)
 def test_symlink_special_file_and_path_replacement_are_rejected(self)->None:
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory); real=root/'real'; real.write_text('{}'); link=root/'link'; link.symlink_to(real)
   with self.assertRaises(validate.ContractError): validate.read_artifact_once(link)
   fifo=root/'fifo'; os.mkfifo(fifo); started=time.monotonic()
   with self.assertRaises(validate.ContractError): validate.read_artifact_once(fifo)
   self.assertLess(time.monotonic()-started,0.5)
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
 def test_external_review_anchor_blocks_full_local_rebinding(self)->None:
  self.assertNotEqual(validate.REVIEW_ANCHOR_PATH.parent,FIXTURE_DIR)
  changed=copy.deepcopy(self.document); changed['cases'][0]['notes']='coordinated drift'
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory); cases=root/'cases.json'; evidence=root/'evidence.json'; baseline=root/'baseline.json'; local_digest=root/'review-root-sha256.txt'
   cases.write_text(json.dumps(changed)); evidence.write_bytes((FIXTURE_DIR/'baseline-evidence.json').read_bytes()); baseline.write_bytes((FIXTURE_DIR/'validation-baseline.json').read_bytes())
   modified_source=(FIXTURE_DIR/'validate.py').read_bytes()+b'\n# coordinated source replacement\n'
   forged=json.loads((FIXTURE_DIR/'review-root.json').read_text()); forged['artifact_sha256']['cases.json']=hashlib.sha256(cases.read_bytes()).hexdigest(); forged['artifact_sha256']['validate.py']=hashlib.sha256(modified_source).hexdigest(); forged_bytes=(json.dumps(forged,indent=2)+'\n').encode(); local_digest.write_text(hashlib.sha256(forged_bytes).hexdigest()+'\n')
   original=validate.ArtifactStore.read
   def forged_read(store,path):
    path=Path(path)
    if path==FIXTURE_DIR/'review-root.json': return validate.Artifact(path,forged_bytes,hashlib.sha256(forged_bytes).hexdigest())
    if path==FIXTURE_DIR/'validate.py': return validate.Artifact(path,modified_source,hashlib.sha256(modified_source).hexdigest())
    return original(store,path)
   with mock.patch.object(validate.ArtifactStore,'read',forged_read), mock.patch.object(validate,'REVIEW_ROOT_DIGEST_PARTS',('f'*16,)*4,create=True):
    with self.assertRaises(validate.ContractError): validate.validate_all(cases,baseline,evidence)
 def test_review_root_binds_validator_and_all_evidence(self)->None:
  count,mutations=validate.validate_all(FIXTURE_DIR/'cases.json',FIXTURE_DIR/'validation-baseline.json',FIXTURE_DIR/'baseline-evidence.json'); self.assertEqual((count,mutations),(26,20))
 def test_mutations_and_compile(self)->None:
  self.assertEqual(validate.validate_mutations(self.document),20); py_compile.compile(str(FIXTURE_DIR/'validate.py'),doraise=True); py_compile.compile(str(FIXTURE_DIR/'test_validate.py'),doraise=True)

if __name__=='__main__': unittest.main()
