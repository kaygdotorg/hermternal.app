#!/usr/bin/env python3
"""Validate the synthetic, offline C-07A session-search contract."""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, math, os, re, stat, sys
from decimal import Decimal, ROUND_FLOOR, ROUND_HALF_EVEN, localcontext
from pathlib import Path
from typing import Any, Callable

ROOT=Path(__file__).resolve().parent; REPOSITORY_ROOT=ROOT.parents[2]
CASES_PATH=ROOT/"cases.json"; BASELINE_PATH=ROOT/"validation-baseline.json"; EVIDENCE_PATH=ROOT/"baseline-evidence.json"
SCHEMA="hermternal.session-search.v1"; BASELINE_SCHEMA="hermternal.session-search-baseline.v1"; EVIDENCE_SCHEMA="hermternal.session-search-baseline-evidence.v1"
OPERATION="C-07A"; CONTRACT="dashboard-v0.0.1"; SOURCE_SHA="f5be9236e00ddf2f2a412697f267078fc4ee068e"
# Tokens are minted and authorized by injected server state. No integrity secret is
# accepted from a request or exposed as contract configuration.
FIXTURE_PRINCIPAL_SCOPE="synthetic-principal/session-search"
# BEGIN REVIEWED TRUST ANCHORS
REVIEWED_ARTIFACT_SHA256={"README.md":"c1fa9d6665a8112d5e1f3c81487dfd8b3971f363174f90033734fd2e33beafcd","cases.json":"bc9dc83c18c9eb2055ef54b789f781822b6836b51427225f47fd00d88b912a2d","test_validate.py":"1456e0436244c56016ec04fe101cde717db1596caf27e2a5e9a8ce2037822671","baseline-evidence.json":"4cd4384cc43f577dde75cfc58fab688bdfee07a261c8c0aacf53e79190fb3243"}
REVIEWED_BASELINE_SHA256="11745b08de0c5d4093c5e3550aadda57aa37f14d49d48c5ced4d34b358ede6f9"
REVIEWED_VALIDATOR_CANONICAL_SHA256="06aea1097ced3a57786e4e95c60bd43ad0837b96f5ba0c5e7a24a0c8455bee3f"
# END REVIEWED TRUST ANCHORS
MAX_FILE_BYTES=1024*1024; READ_CHUNK_BYTES=64*1024; MAX_DEPTH=64; MAX_NODES=8192; MAX_OBJECT_KEYS=64; MAX_ARRAY_ITEMS=512; MAX_STRING_CHARS=16*1024; MAX_INTEGER_DIGITS=256
MAX_QUERY_BYTES=256; MAX_CURSOR_BYTES=96; MAX_PAGE_SIZE=50; BASELINE_REPETITIONS=30
ERROR_MESSAGE="session search fixture rejected"; SUCCESS_PREFIX="session-search fixture valid"
APPROVED_COMMANDS={"normal":"python3 contracts/fixtures/session-search/validate.py","optimized":"python3 -O contracts/fixtures/session-search/validate.py"}
BASELINE_ARTIFACTS=("README.md","cases.json","validate.py","test_validate.py","baseline-evidence.json")
OPAQUE_ID=re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$"); TOKEN_RE=re.compile(r"^[cr]1\.[A-Za-z0-9_-]{43}$"); CONTROL_RE=re.compile(r"[\x00-\x1f\x7f]")
# Unicode White_Space, pinned explicitly instead of inheriting Python strip rules.
UNICODE_WHITE_SPACE=frozenset(chr(value) for value in (9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288))
SENSITIVE_KEY_RE=re.compile(r"(?:authorization|cookie|password|secret|token|ticket|prompt|transcript|content|tool_output|host|url)",re.I)
SENSITIVE_VALUE_RE=re.compile(r"(?:bearer\s+|basic\s+|https?://|(?:password|secret|token|ticket|prompt|transcript|message|content|host)\s*[:=]|(?:^|\s)(?:/Users/|/home/|~/|[A-Za-z]:[\\/]|\\\\)|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)",re.I)
DEPENDENCIES=[
 {"path":"contracts/fixtures/session-persistence/cases.json","sha256":"59aec1f5b6eb83904f355df850b61379b737b64c6c214b47a909d0976acca6da","use":"exact opaque identity and no transcript mirror boundary"},
 {"path":"contracts/fixtures/connection-restoration/cases.json","sha256":"91b43223a17ebaf309f0f57b32f804dc9bab28af4d6860cae33dae9a7bb03935","use":"C-05 restore barrier, idempotent read retry, and delivery uncertainty boundary"},
 {"path":"contracts/fixtures/route-allowlist/route_allowlist.json","sha256":"0d0e9b3d54eefd15abea8fd6869e4e7a95908c9bf057441979e980490bad4e69","use":"approved authenticated GET /api/sessions/search surface"},
 {"path":"contracts/fixtures/route-allowlist/source_audit.json","sha256":"65a26cdea086d28ee90cc7e22d81c3e48715ea28a89f1bedb9f70c4a050aa78d","use":"pinned source path and search route anchor"}]
SOURCE_BLOBS=[
 {"path":"hermes_cli/web_routers/sessions.py","git_blob_sha":"c692d7b21e1ace3d5a9828c67caf2ee4aa561c4d","sha256":"f8debdab79430829245352ebdb7f50603c3a42c11d4609eb3287c35b9a2bf0ba"},
 {"path":"hermes_state_search.py","git_blob_sha":"756884b3f29f16ca38c065b802b397803a6bc0e0","sha256":"6f23d6194826f29e6f521e59db68060e83e29c47121707caeab198a69099c2c9"}]
SOURCE_OBSERVATIONS=[
 {"id":"search-route-present","path":"hermes_cli/web_routers/sessions.py","anchor":"@search_router.get(\"/api/sessions/search\")","observation":"The pinned Dashboard exposes the authenticated session search route recorded by C-01.","contract_relevance":"This fixture models that approved route offline and does not widen the route allowlist."},
 {"id":"missing-or-empty-query","path":"hermes_cli/web_routers/sessions.py","anchor":"if not q or not q.strip():","observation":"The pinned route treats a missing or Unicode-whitespace-only query as an empty result.","contract_relevance":"Whitespace stripping is used only to classify an empty query; nonempty query text is otherwise preserved by Hermternal policy."},
 {"id":"upstream-id-ranking","path":"hermes_state_search.py","anchor":"def search_sessions_by_id(","git_blob_sha":"756884b3f29f16ca38c065b802b397803a6bc0e0","sha256":"6f23d6194826f29e6f521e59db68060e83e29c47121707caeab198a69099c2c9","observation":"The pinned helper strips and lowercases its query, then ranks exact, prefix, and substring session-id matches.","contract_relevance":"Hermternal intentionally narrows exact_id to complete case-sensitive equality; this is client policy, not an upstream claim."},
 {"id":"bounded-source-limit","path":"hermes_cli/web_routers/sessions.py","anchor":"safe_limit = max(1, min(int(limit or 20), 100))","git_blob_sha":"c692d7b21e1ace3d5a9828c67caf2ee4aa561c4d","sha256":"f8debdab79430829245352ebdb7f50603c3a42c11d4609eb3287c35b9a2bf0ba","observation":"The pinned route bounds its helper limit but defines no cursor.","contract_relevance":"Hermternal accepts explicit integer page sizes and defines a narrower integrity-bound cursor."},
 {"id":"no-source-total-order","path":"hermes_cli/web_routers/sessions.py","anchor":"return {\"results\": list(seen.values())}","git_blob_sha":"c692d7b21e1ace3d5a9828c67caf2ee4aa561c4d","sha256":"f8debdab79430829245352ebdb7f50603c3a42c11d4609eb3287c35b9a2bf0ba","observation":"The pinned route returns combined helper insertion order without an explicit total ordering or tie-breaker.","contract_relevance":"Hermternal applies deterministic ordering before pagination as client policy."}]
RULES={
 "query":{"modes":["exact_id","literal_text"],"empty":"missing_or_only_unicode_white_space_returns_empty","white_space_scalars":"Unicode_White_Space_25_code_points","normalization":"none_after_empty_classification","literal_matching":"case_sensitive_unicode_scalar_subsequence","maximum_utf8_bytes":256,"controls":"all_other_c0_and_del_rejected"},
 "identity":{"session_id":"full_opaque_ascii_segment","exact_lookup":"exact_code_unit_equality_only","duplicates":"malformed_catalog","upstream_broader_matching":"not_adopted"},
 "ordering":{"primary":"updated_ms_descending","tie_breaker":"session_id_ascii_ascending","input_order_independent":True},
 "pagination":{"page_size":"integer_1_through_50","cursor":"server_issued_nonsemantic_token_bound_to_principal_query_mode_visible_projection_and_last_row","total_count":"not_exposed","visible_catalog_change":"invalid_cursor","hidden_catalog_change":"no_effect"},
 "privacy":{"unavailable_deleted_unauthorized":"same_absent_result_without_disclosure","result_fields":["session_id"],"redacted_metadata":"never_exposed","local_transcript_mirror":False},
 "recovery":{"operation_class":"side_effect_free_read_with_no_outward_submission","request_binding":["principal_scope","request_id","generation","query","mode","limit","cursor","visible_projection"],"interrupted_before_response":"server_issued_prior_request_proof_required","unknown_response":"server_issued_prior_and_reconciliation_proofs_required","proof_replay":"allowed_only_for_same_side_effect_free_read_binding","automatic_retry":False,"repeatability":"same_visible_projection_request_and_server_scope_same_bytes"},
 "boundary":{"synthetic_only":True,"live_calls":False,"database_reads":False,"transcript_storage":False}}
REDACTION={"synthetic_only":True,"contains_credentials":False,"contains_cookies":False,"contains_tickets":False,"contains_prompts":False,"contains_transcripts":False,"contains_message_content":False,"contains_hosts":False,"contains_user_data":False,"diagnostic_policy":"fixed controlled codes; no raw values, paths, payloads, counts, or existence details"}
SESSION_A="session-alpha-0000000000000001"; SESSION_B="session-beta-0000000000000002"; SESSION_C="session-gamma-0000000000000003"; SESSION_D="session-delta-0000000000000004"; SESSION_HIDDEN="session-hidden-0000000000000005"

class ContractError(ValueError): pass
class RedactedArgumentParser(argparse.ArgumentParser):
 def error(self,_message:str)->None: raise ContractError(ERROR_MESSAGE)
 def exit(self,_status:int=0,_message:str|None=None)->None: raise ContractError(ERROR_MESSAGE)
def _require(condition:bool)->None:
 if not condition: raise ContractError(ERROR_MESSAGE)
def _utf8(value:str)->bytes|None:
 try:return value.encode("utf-8")
 except UnicodeEncodeError:return None

def _read_immutable_bytes(path:Path,after_open:Callable[[],None]|None=None)->bytes:
 # O_NONBLOCK prevents a hostile FIFO path from hanging before fstat can reject it.
 flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0)
 try:fd=os.open(path,flags)
 except OSError as exc:raise ContractError(ERROR_MESSAGE) from exc
 try:
  before=os.fstat(fd); _require(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=MAX_FILE_BYTES)
  if after_open:after_open()
  chunks=[]; total=0
  while True:
   chunk=os.read(fd,min(READ_CHUNK_BYTES,MAX_FILE_BYTES+1-total))
   if not chunk:break
   total+=len(chunk); _require(total<=MAX_FILE_BYTES); chunks.append(chunk)
  after=os.fstat(fd); _require((before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
  current=os.stat(path,follow_symlinks=False); _require(stat.S_ISREG(current.st_mode) and (current.st_dev,current.st_ino)==(before.st_dev,before.st_ino))
  raw=b"".join(chunks); _require(len(raw)==before.st_size); return raw
 except OSError as exc:raise ContractError(ERROR_MESSAGE) from exc
 finally:os.close(fd)
def _reject_duplicate_keys(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ContractError(ERROR_MESSAGE)
  result[key]=value
 return result
def _parse_int(raw):_require(len(raw.lstrip("-+"))<=MAX_INTEGER_DIGITS);return int(raw)
def _parse_float(raw):
 value=float(raw);_require(math.isfinite(value));return value
def _reject_constant(_raw):raise ContractError(ERROR_MESSAGE)
def _check_bounds(root):
 stack=[(root,0)];nodes=0
 while stack:
  value,depth=stack.pop();nodes+=1;_require(nodes<=MAX_NODES and depth<=MAX_DEPTH)
  if type(value)is str:_require(len(value)<=MAX_STRING_CHARS)
  elif type(value)is list:_require(len(value)<=MAX_ARRAY_ITEMS);stack.extend((item,depth+1) for item in value)
  elif type(value)is dict:
   _require(len(value)<=MAX_OBJECT_KEYS)
   for key,item in value.items():_require(type(key)is str and len(key)<=MAX_STRING_CHARS);stack.append((item,depth+1))
  else:_require(value is None or type(value)in(bool,int,float));_require(type(value)is not float or math.isfinite(value))
def _parse_json_bytes(raw):
 _require(len(raw)<=MAX_FILE_BYTES)
 try:value=json.loads(raw.decode("utf-8"),object_pairs_hook=_reject_duplicate_keys,parse_int=_parse_int,parse_float=_parse_float,parse_constant=_reject_constant)
 except ContractError:raise
 except (UnicodeDecodeError,json.JSONDecodeError,RecursionError,OverflowError,TypeError,ValueError) as exc:raise ContractError(ERROR_MESSAGE) from exc
 _check_bounds(value);return value
def _load_json(path):return _parse_json_bytes(_read_immutable_bytes(path))
def _sha256_bytes(raw):return hashlib.sha256(raw).hexdigest()
def _canonical_validator_sha256(path=None):
 source=_read_immutable_bytes(path or Path(__file__)).decode("utf-8");begin=source.index("# BEGIN REVIEWED TRUST ANCHORS");end=source.index("# END REVIEWED TRUST ANCHORS");block=source[begin:end];block=re.sub(r'"[0-9a-f]{64}"','"'+"0"*64+'"',block);return hashlib.sha256((source[:begin]+block+source[end:]).encode()).hexdigest()
def _validate_dependencies():
 repository=REPOSITORY_ROOT.resolve()
 for dependency in DEPENDENCIES:
  relative=Path(dependency["path"]);_require(not relative.is_absolute() and ".." not in relative.parts);candidate=(repository/relative).resolve(strict=False)
  try:candidate.relative_to(repository)
  except ValueError as exc:raise ContractError(ERROR_MESSAGE) from exc
  _require(_sha256_bytes(_read_immutable_bytes(candidate))==dependency["sha256"])
def _opaque_id(value):return type(value)is str and 16<=len(value)<=128 and OPAQUE_ID.fullmatch(value)is not None
def _canonical_json_bytes(value):
 try:return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
 except (UnicodeEncodeError,ValueError,TypeError):return None
def _catalog_error(catalog):
 if type(catalog)is not list:return "malformed_catalog"
 seen=set();keys=("session_id","title_key","updated_ms","available","deleted","authorized","redacted")
 for row in catalog:
  if type(row)is not dict or tuple(row.keys())!=keys:return "malformed_catalog"
  sid=row["session_id"]
  if not _opaque_id(sid) or sid in seen:return "malformed_catalog"
  seen.add(sid)
  if type(row["title_key"])is not str or _utf8(row["title_key"])is None:return "malformed_catalog"
  if type(row["updated_ms"])is not int or type(row["updated_ms"])is bool or row["updated_ms"]<0:return "malformed_catalog"
  if not all(type(row[k])is bool for k in("available","deleted","authorized","redacted")):return "malformed_catalog"
 return None
def _visible_projection(catalog):
 projection=[]
 for row in catalog:
  if not row["available"] or row["deleted"] or not row["authorized"]:continue
  item={"session_id":row["session_id"],"updated_ms":row["updated_ms"],"redacted":row["redacted"]}
  if not row["redacted"]:item["title_key"]=row["title_key"]
  projection.append(item)
 return sorted(projection,key=lambda row:row["session_id"].encode("ascii"))
def _catalog_digest(catalog):
 raw=_canonical_json_bytes(_visible_projection(catalog));_require(raw is not None);return hashlib.sha256(raw).hexdigest()
class _ServerState:
 """Authorization-scoped server state; requests can present but cannot mint evidence."""
 def __init__(self,secret,principal_scope):
  _require(type(secret)is bytes and len(secret)>=32 and type(principal_scope)is str and principal_scope)
  self.__secret=secret;self.principal_scope=principal_scope;self.__issued={}
 def issue(self,prefix,kind,payload):
  bound=[self.principal_scope,kind,*payload];raw=_canonical_json_bytes(bound);_require(raw is not None)
  token=prefix+"."+base64.urlsafe_b64encode(hmac.new(self.__secret,raw,hashlib.sha256).digest()).decode().rstrip("=")
  self.__issued[token]=(kind,tuple(payload));return token
 def evidence(self,token,kind,payload):return type(token)is str and self.__issued.get(token)==(kind,tuple(payload))
 def reconcile(self,prior,payload):
  if not self.evidence(prior,"unknown",payload):raise ContractError(ERROR_MESSAGE)
  return self.issue("r1","reconciled",[prior,*payload])
def _fixture_server(label):
 # Deterministic fixture injection models a separately held server secret and
 # issuance registry. It is never accepted from caller JSON.
 return _ServerState(hashlib.sha256(("test-only-server:"+label).encode()).digest(),FIXTURE_PRINCIPAL_SCOPE)
def _request_binding(query,mode,limit,cursor,request_id,generation,digest):return [request_id,generation,"side_effect_free_read/no_outward_submission",query,mode,limit,cursor,digest]
def _subsequence(needle,haystack):
 iterator=iter(haystack);return all(any(candidate==scalar for candidate in iterator) for scalar in needle)
def _row(sid,title,updated,*,available=True,deleted=False,authorized=True,redacted=False):return {"session_id":sid,"title_key":title,"updated_ms":updated,"available":available,"deleted":deleted,"authorized":authorized,"redacted":redacted}
def _request(query="",*,include_query=True,request_id="request-search-0001",generation=1,mode="literal_text",limit=20,cursor=None,backend="available",interruption="none",prior_request_proof=None,reconciliation_proof=None):
 request={}
 if include_query:request["query"]=query
 request.update({"request_id":request_id,"generation":generation,"mode":mode,"limit":limit,"cursor":cursor,"backend":backend,"interruption":interruption,"prior_request_proof":prior_request_proof,"reconciliation_proof":reconciliation_proof});return request
def _error(code,recovery,proof=None):return {"decision":"error","results":[],"next_cursor":None,"error":{"code":code,"message":"Search unavailable"},"recovery":recovery,"recovery_proof":proof,"transcript_mirror":False}
def _empty(decision="empty"):return {"decision":decision,"results":[],"next_cursor":None,"error":None,"recovery":"none","recovery_proof":None,"transcript_mirror":False}
def _is_empty_query(query):return not query or all(scalar in UNICODE_WHITE_SPACE for scalar in query)

def _execute(request,catalog,server):
 problem=_catalog_error(catalog)
 if problem:return _error(problem,"stop")
 required=("request_id","generation","mode","limit","cursor","backend","interruption","prior_request_proof","reconciliation_proof")
 if type(request)is not dict or type(server)is not _ServerState:return _error("malformed_request","correct_request")
 if "query" in request:
  if tuple(request.keys())!=("query",)+required:return _error("malformed_request","correct_request")
  query=request["query"]
 else:
  if tuple(request.keys())!=required:return _error("malformed_request","correct_request")
  query=""
 request_id,generation,mode,limit,cursor,backend,interruption,prior,reconciliation=(request[k] for k in required)
 if type(query)is not str or type(mode)is not str or not _opaque_id(request_id) or type(generation)is not int or type(generation)is bool or generation<1:return _error("malformed_request","correct_request")
 encoded=_utf8(query)
 if encoded is None or len(encoded)>MAX_QUERY_BYTES:return _error("invalid_query","correct_request")
 empty=_is_empty_query(query)
 if not empty and CONTROL_RE.search(query):return _error("invalid_query","correct_request")
 if type(limit)is not int or type(limit)is bool or not 1<=limit<=MAX_PAGE_SIZE:return _error("invalid_page_size","correct_request")
 if cursor is not None:
  encoded_cursor=_utf8(cursor) if type(cursor)is str else None
  if encoded_cursor is None or len(encoded_cursor)>MAX_CURSOR_BYTES or TOKEN_RE.fullmatch(cursor)is None:return _error("invalid_cursor","restart_search")
 if mode not in("exact_id","literal_text"):return _error("invalid_query","correct_request")
 if backend not in("available","unavailable") or interruption not in("none","before_response","unknown_response"):return _error("malformed_request","correct_request")
 if prior is not None and (type(prior)is not str or TOKEN_RE.fullmatch(prior)is None):return _error("retry_blocked","restart_search")
 if reconciliation is not None and (type(reconciliation)is not str or TOKEN_RE.fullmatch(reconciliation)is None):return _error("retry_blocked","restart_search")
 digest=_catalog_digest(catalog);binding=_request_binding(query,mode,limit,cursor,request_id,generation,digest)
 if backend=="unavailable":return _error("search_unavailable","explicit_retry")
 if interruption=="before_response":return _error("interrupted","same_request_retry",server.issue("r1","before",binding))
 if interruption=="unknown_response":return _error("delivery_uncertain","reconcile_then_same_request",server.issue("r1","unknown",binding))
 if prior is not None:
  before_valid=server.evidence(prior,"before",binding);unknown_valid=server.evidence(prior,"unknown",binding)
  if unknown_valid:
   reconciled_payload=[prior,*binding]
   if reconciliation is None or not server.evidence(reconciliation,"reconciled",reconciled_payload):return _error("retry_blocked","reconcile_then_same_request")
  elif reconciliation is not None or not before_valid:return _error("retry_blocked","restart_search")
 elif reconciliation is not None:return _error("retry_blocked","restart_search")
 if empty:return _empty()
 if mode=="exact_id" and not _opaque_id(query):return _empty("no_results")
 visible=[]
 for row in catalog:
  if not row["available"] or row["deleted"] or not row["authorized"]:continue
  matched=query==row["session_id"] if mode=="exact_id" else(not row["redacted"] and _subsequence(query,row["title_key"]))
  if matched:visible.append(row)
 visible.sort(key=lambda row:(-row["updated_ms"],row["session_id"].encode("ascii")))
 start=0
 if cursor is not None:
  for index,row in enumerate(visible):
   payload=[query,mode,digest,row["updated_ms"],row["session_id"]]
   if server.evidence(cursor,"cursor",payload):start=index+1;break
  else:return _error("invalid_cursor","restart_search")
 page=visible[start:start+limit];next_cursor=None
 if start+limit<len(visible):
  last=page[-1];next_cursor=server.issue("c1","cursor",[query,mode,digest,last["updated_ms"],last["session_id"]])
 return {"decision":"results" if page else "no_results","results":[{"session_id":r["session_id"]} for r in page],"next_cursor":next_cursor,"error":None,"recovery":"none","recovery_proof":None,"transcript_mirror":False}

def _standard_catalog():return [_row(SESSION_A,"project atlas",300),_row(SESSION_B,"project atlas beta",200),_row(SESSION_C,"Project Atlas",200),_row(SESSION_D,"東京 設計",100)]
def _scenario_material(label):
 server=_fixture_server(label);material={};atlas=_standard_catalog()
 if label=="cursor":material["cursor"]=_execute(_request("project",limit=1),atlas,server)["next_cursor"]
 elif label=="before":material["prior"]=_execute(_request("project",interruption="before_response"),atlas,server)["recovery_proof"]
 elif label in("unknown","reconciled"):
  request=_request("project");material["prior"]=_execute(_request("project",interruption="unknown_response"),atlas,server)["recovery_proof"]
  if label=="reconciled":
   binding=_request_binding("project","literal_text",20,None,request["request_id"],request["generation"],_catalog_digest(atlas));material["reconciliation"]=server.reconcile(material["prior"],binding)
 return server,material
def _run_case(case):return _execute(case["request"],case["catalog"],_scenario_material(case["server_scenario"])[0])
def _canonical_cases():
 atlas=_standard_catalog();a,b,g,d=atlas;hd=_row(SESSION_HIDDEN,"project atlas",400,deleted=True);hn=_row(SESSION_HIDDEN,"project atlas",400,authorized=False);hu=_row(SESSION_HIDDEN,"project atlas",400,available=False);hr=_row(SESSION_HIDDEN,"project atlas",400,redacted=True)
 cursor=_scenario_material("cursor")[1]["cursor"];before=_scenario_material("before")[1]["prior"];unknown=_scenario_material("unknown")[1]["prior"];reconciled_material=_scenario_material("reconciled")[1];reconciled_prior=reconciled_material["prior"];reconciled=reconciled_material["reconciliation"];forged="r1."+"A"*43
 definitions=[
 ("missing-query",_request(include_query=False),atlas,"fresh"),("empty-query",_request(""),atlas,"fresh"),("whitespace-only-query",_request(" \t\n"),atlas,"fresh"),("non-whitespace-control-u001c",_request(chr(0x1c)),atlas,"fresh"),("non-whitespace-control-u001f",_request(chr(0x1f)),atlas,"fresh"),("no-result",_request("absent"),atlas,"fresh"),
 ("exact-opaque-id",_request(SESSION_A,mode="exact_id"),atlas,"fresh"),("exact-id-prefix-rejected",_request(SESSION_A[:-1],mode="exact_id"),atlas,"fresh"),("exact-id-case-sensitive",_request(SESSION_A.upper(),mode="exact_id"),atlas,"fresh"),("exact-id-leading-space-not-trimmed",_request(" "+SESSION_A,mode="exact_id"),atlas,"fresh"),
 ("literal-subsequence-distinguishes-substring",_request("pa"),atlas,"fresh"),("literal-case-sensitive",_request("Atlas"),atlas,"fresh"),("unicode-literal-language-neutral",_request("東京"),atlas,"fresh"),("newest-first-order",_request("project"),atlas,"fresh"),("session-id-tie-break",_request("PA"),[_row(SESSION_C,"Project Atlas",200),_row(SESSION_B,"Project Atlas",200)],"fresh"),("input-order-independent",_request("project"),list(reversed(atlas)),"fresh"),
 ("first-page-with-cursor",_request("project",limit=1),atlas,"cursor"),("second-page-from-cursor",_request("project",limit=1,cursor=cursor),atlas,"cursor"),("cursor-query-mismatch",_request("atlas",limit=1,cursor=cursor),atlas,"cursor"),("cursor-mode-mismatch",_request(SESSION_A,mode="exact_id",limit=1,cursor=cursor),atlas,"cursor"),("cursor-visible-catalog-drift",_request("project",limit=1,cursor=cursor),atlas+[_row("session-new-0000000000000000006","project",500)],"cursor"),("cursor-hidden-catalog-drift",_request("project",limit=1,cursor=cursor),atlas+[_row("session-hidden-extra-000000000006","project",500,authorized=False)],"cursor"),("cursor-forgery",_request("project",cursor="c1."+"A"*43),atlas,"fresh"),("malformed-cursor",_request("project",cursor="bad"),atlas,"fresh"),("lone-surrogate-cursor",_request("project",cursor="\ud800"),atlas,"fresh"),
 ("zero-page-size",_request("project",limit=0),atlas,"fresh"),("oversized-page-size",_request("project",limit=51),atlas,"fresh"),("boolean-page-size",_request("project",limit=True),atlas,"fresh"),("malformed-query-control",_request("atlas"+chr(0)),atlas,"fresh"),("lone-surrogate-query",_request("\ud800"),atlas,"fresh"),("oversized-query",_request("é"*129),atlas,"fresh"),("invalid-mode",_request("atlas",mode="folded_text"),atlas,"fresh"),("duplicate-session-id",_request("project"),[a,dict(a)],"fresh"),
 ("deleted-session-nondisclosure",_request(SESSION_HIDDEN,mode="exact_id"),[hd],"fresh"),("unauthorized-session-nondisclosure",_request(SESSION_HIDDEN,mode="exact_id"),[hn],"fresh"),("unavailable-session-nondisclosure",_request(SESSION_HIDDEN,mode="exact_id"),[hu],"fresh"),("mixed-hidden-visible",_request("project"),[_row("session-hidden-deleted-0000000006","project atlas",400,deleted=True),_row("session-hidden-denied-00000000007","project atlas",400,authorized=False),_row("session-hidden-unavailable-00000008","project atlas",400,available=False),a],"fresh"),("redacted-metadata-not-searchable",_request("project"),[hr],"fresh"),("redacted-exact-id-only",_request(SESSION_HIDDEN,mode="exact_id"),[hr],"fresh"),
 ("backend-unavailable",_request("project",backend="unavailable"),atlas,"fresh"),("interrupted-before-response",_request("project",interruption="before_response"),atlas,"before"),("interrupted-safe-retry",_request("project",prior_request_proof=before),atlas,"before"),("interrupted-forged-proof",_request("project",prior_request_proof=forged),atlas,"fresh"),("unknown-response",_request("project",interruption="unknown_response"),atlas,"unknown"),("unknown-response-prior-only-blocked",_request("project",prior_request_proof=unknown),atlas,"unknown"),("unknown-response-reconciled-retry",_request("project",prior_request_proof=reconciled_prior,reconciliation_proof=reconciled),atlas,"reconciled"),("reconciliation-visible-catalog-drift",_request("project",prior_request_proof=reconciled_prior,reconciliation_proof=reconciled),atlas+[_row("session-new-0000000000000000006","project",500)],"reconciled"),("stable-repeatability",_request("project",limit=2),atlas,"fresh")]
 cases=[]
 for cid,request,catalog,scenario in definitions:
  case={"id":cid,"server_scenario":scenario,"request":request,"catalog":catalog,"expected":None,"notes":"Synthetic canonical session-search decision."};case["expected"]=_run_case(case);cases.append(case)
 return cases
def _document():return {"schema":SCHEMA,"operation":OPERATION,"contract":CONTRACT,"hermes_source_sha":SOURCE_SHA,"synthetic_only":True,"surface":"shared-web-apple","dependencies":DEPENDENCIES,"source_blobs":SOURCE_BLOBS,"source_observations":SOURCE_OBSERVATIONS,"rules":RULES,"cases":_canonical_cases(),"redaction":REDACTION}
def _strict_equal(actual,expected):
 _require(type(actual)is type(expected))
 if type(expected)is dict:_require(tuple(actual.keys())==tuple(expected.keys()));[_strict_equal(actual[k],expected[k]) for k in expected]
 elif type(expected)is list:_require(len(actual)==len(expected));[_strict_equal(a,b) for a,b in zip(actual,expected)]
 else:_require(actual==expected)
def _validate_redaction(root):
 allowed={"local_transcript_mirror","transcript_mirror","transcript_storage","redacted_metadata"};stack=[root]
 while stack:
  value=stack.pop()
  if type(value)is dict:
   for key,item in value.items():
    if not key.startswith("contains_") and key not in allowed:_require(SENSITIVE_KEY_RE.search(key)is None)
    stack.append(item)
  elif type(value)is list:stack.extend(value)
  elif type(value)is str:_require(SENSITIVE_VALUE_RE.search(value)is None)
def validate_document(document):
 _strict_equal(document,_document());_validate_redaction(document);ids=[c["id"] for c in document["cases"]];_require(len(ids)==len(set(ids)) and len(ids)>=30)
 for case in document["cases"]:_strict_equal(_run_case(case),case["expected"])
 return len(ids)
def _decimal(value):_require(type(value)in(int,float) and type(value)is not bool);_require(type(value)is not float or math.isfinite(value));return Decimal(str(value))
def _round3(value):return value.quantize(Decimal("0.001"),rounding=ROUND_HALF_EVEN)
def _percentile(values,q):
 ordered=sorted(values);position=Decimal(len(ordered)-1)*q;lower=int(position.to_integral_value(rounding=ROUND_FLOOR));upper=min(lower+1,len(ordered)-1);return _round3(ordered[lower]+(ordered[upper]-ordered[lower])*(position-Decimal(lower)))
def _distribution(samples):
 with localcontext() as context:
  context.prec=50;values=[_decimal(s) for s in samples];_require(values and all(v>0 for v in values));result={"min":_round3(min(values)),"p50":_percentile(values,Decimal(".50")),"p95":_percentile(values,Decimal(".95")),"p99":_percentile(values,Decimal(".99")),"max":_round3(max(values)),"mean":_round3(sum(values)/Decimal(len(values)))};return {k:float(v) for k,v in result.items()}
def validate_baseline(baseline,cases_raw):
 keys=("schema","validator","command","build_mode","artifact_files","artifact_bytes","environment","repetitions","normal","optimized","threshold");_require(type(baseline)is dict and tuple(baseline.keys())==keys);_require(baseline["schema"]==BASELINE_SCHEMA and baseline["validator"]=="contracts/fixtures/session-search/validate.py" and baseline["command"]==APPROVED_COMMANDS["normal"] and baseline["build_mode"]=="N/A")
 artifacts=baseline["artifact_files"];_require(type(artifacts)is list and len(artifacts)==len(BASELINE_ARTIFACTS));total=0
 for name,item in zip(BASELINE_ARTIFACTS,artifacts):
  _require(type(item)is dict and tuple(item.keys())==("path","sha256","size_bytes") and item["path"]==name and type(item["sha256"])is str and len(item["sha256"])==64 and type(item["size_bytes"])is int and type(item["size_bytes"])is not bool and item["size_bytes"]>0)
  raw=cases_raw if name=="cases.json" else _read_immutable_bytes(ROOT/name);digest=_canonical_validator_sha256(ROOT/name) if name=="validate.py" else _sha256_bytes(raw);_require(item["sha256"]==digest and item["size_bytes"]==len(raw));total+=len(raw)
 _require(type(baseline["artifact_bytes"])is int and type(baseline["artifact_bytes"])is not bool and baseline["artifact_bytes"]==total);_require(type(baseline["environment"])is dict and tuple(baseline["environment"].keys())==("platform","python") and all(type(v)is str and v for v in baseline["environment"].values()));_require(type(baseline["repetitions"])is int and type(baseline["repetitions"])is not bool and baseline["repetitions"]==30 and baseline["threshold"]is None)
 evidence=_parse_json_bytes(_read_immutable_bytes(EVIDENCE_PATH));_require(type(evidence)is dict and tuple(evidence.keys())==("schema","normal","optimized") and evidence["schema"]==EVIDENCE_SCHEMA)
 for mode in("normal","optimized"):
  item=baseline[mode];ev=evidence[mode];_require(type(item)is dict and tuple(item.keys())==("command","samples_ms","distribution") and type(ev)is dict and tuple(ev.keys())==("samples_ms","distribution") and item["command"]==APPROVED_COMMANDS[mode]);samples=item["samples_ms"];_require(type(samples)is list and len(samples)==30 and all(type(s)is float and math.isfinite(s) and s>0 for s in samples));_strict_equal(samples,ev["samples_ms"]);_strict_equal(item["distribution"],_distribution(samples));_strict_equal(item["distribution"],ev["distribution"])
 return total
def validate_all(document,baseline,cases_raw=None,baseline_raw=None,verify_trust=True):
 if cases_raw is None:cases_raw=_read_immutable_bytes(CASES_PATH)
 if baseline_raw is None:baseline_raw=_read_immutable_bytes(BASELINE_PATH)
 if verify_trust:
  _require(_canonical_validator_sha256()==REVIEWED_VALIDATOR_CANONICAL_SHA256 and _sha256_bytes(cases_raw)==REVIEWED_ARTIFACT_SHA256["cases.json"] and _sha256_bytes(baseline_raw)==REVIEWED_BASELINE_SHA256)
  for name,digest in REVIEWED_ARTIFACT_SHA256.items():
   if name!="cases.json":_require(_sha256_bytes(_read_immutable_bytes(ROOT/name))==digest)
 _validate_dependencies();return validate_document(document),validate_baseline(baseline,cases_raw)
def _emit_cases():print(json.dumps(_document(),ensure_ascii=True,indent=2)+"\n",end="")
def main(argv=None):
 parser=RedactedArgumentParser(add_help=False);parser.add_argument("--cases",default=str(CASES_PATH));parser.add_argument("--baseline",default=str(BASELINE_PATH));parser.add_argument("--emit-cases",action="store_true")
 try:
  args=parser.parse_args(argv)
  if args.emit_cases:_emit_cases();return 0
  cases_raw=_read_immutable_bytes(Path(args.cases));baseline_raw=_read_immutable_bytes(Path(args.baseline));document=_parse_json_bytes(cases_raw);baseline=_parse_json_bytes(baseline_raw);count,size=validate_all(document,baseline,cases_raw,baseline_raw);print(f"{SUCCESS_PREFIX}: cases={count} artifacts={size}");return 0
 except (ContractError,OSError,UnicodeError,ValueError,TypeError,OverflowError,RecursionError):print(json.dumps({"error":{"code":"contract","message":ERROR_MESSAGE}},separators=(",",":")));return 1
if __name__=="__main__":sys.exit(main())
