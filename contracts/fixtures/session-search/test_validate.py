#!/usr/bin/env python3
"""Security and semantic regressions for the offline C-07A fixture."""
from __future__ import annotations
import copy, hashlib, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import validate  # noqa: E402

class SessionSearchTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.cases_raw=validate._read_immutable_bytes(validate.CASES_PATH);cls.baseline_raw=validate._read_immutable_bytes(validate.BASELINE_PATH)
  cls.document=validate._parse_json_bytes(cls.cases_raw);cls.baseline=validate._parse_json_bytes(cls.baseline_raw);cls.cases={case["id"]:case for case in cls.document["cases"]}
 def run_cli(self,optimized=False,*extra,cwd=None):
  command=[sys.executable]+(["-O"] if optimized else[])+[str(ROOT/"validate.py"),*extra]
  return subprocess.run(command,check=False,capture_output=True,text=True,cwd=cwd)
 def test_checked_in_contract_and_baseline_validate(self):
  count,size=validate.validate_all(self.document,self.baseline,self.cases_raw,self.baseline_raw);self.assertEqual(count,48);self.assertGreater(size,0);self.assertEqual(self.baseline["repetitions"],30);self.assertIsNone(self.baseline["threshold"])
 def test_normal_and_optimized_cli_have_exact_parity(self):
  normal=self.run_cli();optimized=self.run_cli(True);self.assertEqual((normal.returncode,normal.stdout,normal.stderr),(0,optimized.stdout,""));self.assertEqual(optimized.stderr,"");self.assertIn("cases=48",normal.stdout)
 def test_missing_empty_and_source_backed_normalization(self):
  for case_id in("missing-query","empty-query","whitespace-only-query"):self.assertEqual(self.cases[case_id]["expected"]["decision"],"empty")
  for case_id in("non-whitespace-control-u001c","non-whitespace-control-u001f"):self.assertEqual(self.cases[case_id]["expected"]["error"]["code"],"invalid_query")
  for scalar in range(0x1c,0x20):
   self.assertFalse(validate._is_empty_query(chr(scalar)));result=validate._execute(validate._request(chr(scalar)),validate._standard_catalog(),validate._fixture_server(f"control-{scalar}"));self.assertEqual(result["error"]["code"],"invalid_query")
  self.assertEqual(self.cases["literal-case-sensitive"]["expected"]["results"],[{"session_id":validate.SESSION_C}]);self.assertEqual(self.cases["unicode-literal-language-neutral"]["expected"]["results"],[{"session_id":validate.SESSION_D}])
 def test_exact_identity_and_unicode_scalar_subsequence(self):
  self.assertEqual(self.cases["exact-opaque-id"]["expected"]["results"],[{"session_id":validate.SESSION_A}])
  for case_id in("exact-id-prefix-rejected","exact-id-case-sensitive","exact-id-leading-space-not-trimmed"):self.assertEqual(self.cases[case_id]["expected"]["decision"],"no_results")
  self.assertEqual(self.cases["literal-subsequence-distinguishes-substring"]["expected"]["results"],[{"session_id":validate.SESSION_A},{"session_id":validate.SESSION_B}])
 def test_order_tie_break_and_real_input_permutations_are_stable(self):
  self.assertEqual(self.cases["newest-first-order"]["expected"]["results"],[{"session_id":validate.SESSION_A},{"session_id":validate.SESSION_B}]);self.assertEqual(self.cases["session-id-tie-break"]["expected"]["results"],[{"session_id":validate.SESSION_B},{"session_id":validate.SESSION_C}])
  request=self.cases["stable-repeatability"]["request"];catalog=self.cases["stable-repeatability"]["catalog"];expected=json.dumps(validate._execute(request,catalog,validate._fixture_server("repeat")),sort_keys=True,separators=(",",":"))
  for permutation in (list(reversed(catalog)),catalog[1:]+catalog[:1],[catalog[i] for i in(2,0,3,1)]):self.assertEqual(json.dumps(validate._execute(copy.deepcopy(request),permutation,validate._fixture_server("repeat")),sort_keys=True,separators=(",",":")),expected)
 def test_cursor_is_nonsemantic_integrity_bound_and_catalog_bound(self):
  cursor=self.cases["first-page-with-cursor"]["expected"]["next_cursor"];self.assertRegex(cursor,r"^c1\.[A-Za-z0-9_-]{43}$");self.assertNotIn(validate.SESSION_A,cursor);self.assertNotIn("300",cursor)
  self.assertEqual(self.cases["second-page-from-cursor"]["expected"]["results"],[{"session_id":validate.SESSION_B}])
  for case_id in("cursor-query-mismatch","cursor-mode-mismatch","cursor-visible-catalog-drift","cursor-forgery","malformed-cursor","lone-surrogate-cursor"):self.assertEqual(self.cases[case_id]["expected"]["error"]["code"],"invalid_cursor")
  self.assertEqual(self.cases["cursor-hidden-catalog-drift"]["expected"]["results"],[{"session_id":validate.SESSION_B}])
 def test_malformed_surrogate_oversized_and_duplicate_inputs_are_controlled(self):
  expected={"zero-page-size":"invalid_page_size","oversized-page-size":"invalid_page_size","boolean-page-size":"invalid_page_size","malformed-query-control":"invalid_query","lone-surrogate-query":"invalid_query","oversized-query":"invalid_query","invalid-mode":"invalid_query","duplicate-session-id":"malformed_catalog"}
  for case_id,code in expected.items():self.assertEqual(self.cases[case_id]["expected"]["error"]["code"],code)
 def test_hidden_absent_and_redacted_rows_do_not_disclose(self):
  shapes={json.dumps(self.cases[c]["expected"],sort_keys=True,separators=(",",":")) for c in("no-result","deleted-session-nondisclosure","unauthorized-session-nondisclosure","unavailable-session-nondisclosure")};self.assertEqual(len(shapes),1)
  self.assertEqual(self.cases["mixed-hidden-visible"]["expected"]["results"],[{"session_id":validate.SESSION_A}]);self.assertEqual(self.cases["redacted-metadata-not-searchable"]["expected"]["decision"],"no_results");self.assertEqual(self.cases["redacted-exact-id-only"]["expected"]["results"],[{"session_id":validate.SESSION_HIDDEN}])
 def test_retry_requires_bound_prior_and_reconciliation_evidence(self):
  self.assertIsNotNone(self.cases["interrupted-before-response"]["expected"]["recovery_proof"]);self.assertIsNotNone(self.cases["unknown-response"]["expected"]["recovery_proof"])
  self.assertEqual(self.cases["interrupted-forged-proof"]["expected"]["error"]["code"],"retry_blocked");self.assertIsNone(self.cases["unknown-response-prior-only-blocked"]["request"]["reconciliation_proof"]);self.assertEqual(self.cases["unknown-response-prior-only-blocked"]["expected"]["error"]["code"],"retry_blocked");self.assertEqual(self.cases["reconciliation-visible-catalog-drift"]["expected"]["error"]["code"],"retry_blocked")
  self.assertEqual(self.cases["unknown-response-reconciled-retry"]["expected"],self.cases["interrupted-safe-retry"]["expected"])
 def test_server_state_is_authorization_scoped_and_read_replay_is_explicit(self):
  request=validate._request("project",limit=1);catalog=validate._standard_catalog();issuing=validate._fixture_server("scope-a");issued=validate._execute(request,catalog,issuing)["next_cursor"]
  continuation=copy.deepcopy(request);continuation["cursor"]=issued
  self.assertEqual(validate._execute(continuation,catalog,issuing)["results"],[{"session_id":validate.SESSION_B}])
  other_secret=validate._fixture_server("scope-b");self.assertEqual(validate._execute(continuation,catalog,other_secret)["error"]["code"],"invalid_cursor")
  other_principal=validate._ServerState(hashlib.sha256(b"scope-a-secret-material").digest(),"other-principal/session-search");self.assertEqual(validate._execute(continuation,catalog,other_principal)["error"]["code"],"invalid_cursor")
  server,material=validate._scenario_material("reconciled");retry=validate._request("project",prior_request_proof=material["prior"],reconciliation_proof=material["reconciliation"]);first=validate._execute(retry,catalog,server);second=validate._execute(retry,catalog,server);self.assertEqual(first,second)
  changed_generation=copy.deepcopy(retry);changed_generation["generation"]=2;self.assertEqual(validate._execute(changed_generation,catalog,server)["error"]["code"],"retry_blocked")
  changed_request=copy.deepcopy(retry);changed_request["request_id"]="request-search-0002";self.assertEqual(validate._execute(changed_request,catalog,server)["error"]["code"],"retry_blocked")
  self.assertEqual(self.document["rules"]["recovery"]["operation_class"],"side_effect_free_read_with_no_outward_submission")
 def test_strict_json_rejects_duplicate_nonfinite_overflow_utf8_and_bounds(self):
  payloads={"duplicate":b'{"x":1,"x":2}',"nan":b'{"x":NaN}',"infinity":b'{"x":Infinity}',"overflow":b'{"x":1e9999}',"integer":b'{"x":'+b"9"*(validate.MAX_INTEGER_DIGITS+1)+b"}","utf8":b'{"x":"\xff"}',"depth":b"["*(validate.MAX_DEPTH+2)+b"0"+b"]"*(validate.MAX_DEPTH+2),"string":b'{"x":"'+b"a"*(validate.MAX_STRING_CHARS+1)+b'"}',"object":("{"+",".join(f'\"k{i}\":0' for i in range(validate.MAX_OBJECT_KEYS+1))+"}").encode(),"array":("["+",".join("0" for _ in range(validate.MAX_ARRAY_ITEMS+1))+"]").encode()}
  for name,payload in payloads.items():
   with self.subTest(name=name),self.assertRaises(validate.ContractError):validate._parse_json_bytes(payload)
 def test_immutable_reader_rejects_symlink_special_oversize_and_replacement(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);regular=root/"regular.json";regular.write_bytes(b"{}")
   link=root/"link.json";link.symlink_to(regular)
   with self.assertRaises(validate.ContractError):validate._read_immutable_bytes(link)
   fifo=root/"fifo";os.mkfifo(fifo)
   with self.assertRaises(validate.ContractError):validate._read_immutable_bytes(fifo)
   oversized=root/"oversized";oversized.touch();os.truncate(oversized,validate.MAX_FILE_BYTES+1)
   with self.assertRaises(validate.ContractError):validate._read_immutable_bytes(oversized)
   replacement=root/"replacement";replacement.write_bytes(b'{"old":1}')
   def replace():
    moved=root/"moved";replacement.rename(moved);replacement.write_bytes(b'{"new":2}')
   with self.assertRaises(validate.ContractError):validate._read_immutable_bytes(replacement,replace)
   inplace=root/"inplace";inplace.write_bytes(b'{"old":1}');original=inplace.stat()
   def mutate_in_place():
    with inplace.open("r+b") as stream:stream.write(b'{"new":2}');stream.flush();os.fsync(stream.fileno())
    os.utime(inplace,ns=(original.st_atime_ns,original.st_mtime_ns))
   with self.assertRaises(validate.ContractError):validate._read_immutable_bytes(inplace,mutate_in_place)
 def test_selected_bytes_are_same_parse_hash_and_size_identity(self):
  compact=json.dumps(self.document,ensure_ascii=True,separators=(",",":")).encode();self.assertNotEqual(hashlib.sha256(compact).hexdigest(),validate.REVIEWED_ARTIFACT_SHA256["cases.json"])
  parsed=validate._parse_json_bytes(compact)
  with self.assertRaises(validate.ContractError):validate.validate_all(parsed,self.baseline,compact,self.baseline_raw)
  compact_baseline=json.dumps(self.baseline,separators=(",",":")).encode();parsed_baseline=validate._parse_json_bytes(compact_baseline)
  with self.assertRaises(validate.ContractError):validate.validate_all(self.document,parsed_baseline,self.cases_raw,compact_baseline)
  with tempfile.TemporaryDirectory() as directory:
   cases_path=Path(directory)/"cases.json";baseline_path=Path(directory)/"baseline.json";cases_path.write_bytes(compact);baseline_path.write_bytes(compact_baseline)
   for optimized in(False,True):
    for arguments in(("--cases",str(cases_path)),("--baseline",str(baseline_path))):
     result=self.run_cli(optimized,*arguments);self.assertEqual(result.returncode,1);self.assertEqual(result.stderr,"");self.assertEqual(json.loads(result.stdout),{"error":{"code":"contract","message":validate.ERROR_MESSAGE}})
 def test_unknown_argparse_and_surrogates_are_fixed_redacted_in_both_modes(self):
  marker="--Bearer-synthetic-sensitive-value"
  for optimized in(False,True):
   result=self.run_cli(optimized,marker);self.assertEqual(result.returncode,1);self.assertEqual(result.stderr,"");self.assertEqual(len(result.stdout.splitlines()),1);self.assertNotIn(marker,result.stdout);self.assertEqual(json.loads(result.stdout),{"error":{"code":"contract","message":validate.ERROR_MESSAGE}})
  for case_id in("lone-surrogate-query","lone-surrogate-cursor"):
   request=self.cases[case_id]["request"];expected=self.cases[case_id]["expected"]
   for optimized in(False,True):
    code="import json,sys;sys.path.insert(0,"+repr(str(ROOT))+');import validate;print(json.dumps(validate._execute('+repr(request)+","+repr(self.cases[case_id]["catalog"])+",validate._scenario_material("+repr(self.cases[case_id]["server_scenario"])+")[0]),ensure_ascii=True,sort_keys=True))"
    result=subprocess.run([sys.executable]+(["-O"] if optimized else[])+["-c",code],capture_output=True,text=True,check=False);self.assertEqual(json.loads(result.stdout),expected)
 def test_exact_numeric_types_and_b01_r7_half_even_percentiles(self):
  samples=[float(i) for i in range(1,31)];distribution=validate._distribution(samples);self.assertEqual(distribution,{"min":1.0,"p50":15.5,"p95":28.55,"p99":29.71,"max":30.0,"mean":15.5})
  self.assertEqual(self.baseline["normal"]["distribution"],{"min":67.322,"p50":148.22,"p95":322.802,"p99":360.436,"max":370.648,"mean":171.57})
  self.assertEqual(self.baseline["optimized"]["distribution"],{"min":84.218,"p50":97.877,"p95":122.888,"p99":129.596,"max":132.262,"mean":101.809})
  for field in("artifact_bytes","repetitions"):
   forged=copy.deepcopy(self.baseline);forged[field]=float(forged[field])
   with self.assertRaises(validate.ContractError):validate.validate_baseline(forged,self.cases_raw)
 def test_baseline_evidence_and_distribution_are_immutable(self):
  for mutation in("samples","distribution","command","threshold"):
   forged=copy.deepcopy(self.baseline)
   if mutation=="samples":forged["normal"]["samples_ms"]=[1.0]*30;forged["normal"]["distribution"]=validate._distribution(forged["normal"]["samples_ms"])
   elif mutation=="distribution":forged["optimized"]["distribution"]["mean"]+=1.0
   elif mutation=="command":forged["normal"]["command"]="python3 fabricated.py"
   else:forged["threshold"]=1.0
   with self.assertRaises(validate.ContractError):validate.validate_baseline(forged,self.cases_raw)
 def test_coordinated_artifact_and_manifest_rebinding_hits_reviewed_anchor(self):
  with tempfile.TemporaryDirectory() as directory:
   copied=Path(directory)/"session-search";shutil.copytree(ROOT,copied);cases_path=copied/"cases.json";document=json.loads(cases_path.read_text());document["cases"][0]["notes"]="coordinated mutation";cases_path.write_text(json.dumps(document,indent=2)+"\n")
   baseline_path=copied/"validation-baseline.json";baseline=json.loads(baseline_path.read_text());raw=cases_path.read_bytes()
   for artifact in baseline["artifact_files"]:
    if artifact["path"]=="cases.json":artifact["sha256"]=hashlib.sha256(raw).hexdigest();artifact["size_bytes"]=len(raw)
   baseline["artifact_bytes"]=sum(item["size_bytes"] for item in baseline["artifact_files"]);baseline_path.write_text(json.dumps(baseline,indent=2)+"\n")
   for optimized in(False,True):
    command=[sys.executable]+(["-O"] if optimized else[])+[str(copied/"validate.py")];result=subprocess.run(command,capture_output=True,text=True,check=False);self.assertEqual(result.returncode,1);self.assertEqual(json.loads(result.stdout),{"error":{"code":"contract","message":validate.ERROR_MESSAGE}})
 def test_dependencies_source_pin_and_redaction_are_canonical(self):
  self.assertEqual(self.document["hermes_source_sha"],validate.SOURCE_SHA);self.assertEqual(self.document["dependencies"],validate.DEPENDENCIES);self.assertEqual(self.document["source_blobs"],validate.SOURCE_BLOBS);self.assertEqual(self.document["source_observations"],validate.SOURCE_OBSERVATIONS);validate._validate_dependencies()
  dependencies={item["path"]:item["sha256"] for item in validate.DEPENDENCIES};self.assertEqual(dependencies["contracts/fixtures/connection-restoration/cases.json"],"91b43223a17ebaf309f0f57b32f804dc9bab28af4d6860cae33dae9a7bb03935")
  helper=next(item for item in validate.SOURCE_OBSERVATIONS if item["id"]=="upstream-id-ranking");self.assertEqual(helper["git_blob_sha"],"756884b3f29f16ca38c065b802b397803a6bc0e0");self.assertEqual(helper["sha256"],"6f23d6194826f29e6f521e59db68060e83e29c47121707caeab198a69099c2c9")
  for value in("Bearer synthetic","https://synthetic.invalid","127.0.0.1:8080","/Users/alice/private","password=synthetic","prompt: synthetic","transcript: synthetic"):
   with self.assertRaises(validate.ContractError):validate._validate_redaction({"value":value})
if __name__=="__main__":unittest.main()
