"""Validate deterministic synthetic deep-link resolver traces offline.

The validator reads bounded immutable byte snapshots. It never opens a socket,
contacts Hermes, reads a transcript store, creates a session, or shares a link.
Fixture events are inert JSON data.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, math, os, re, stat, statistics
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any, Mapping

FIXTURE_DIR=Path(__file__).resolve().parent
REPO_ROOT=FIXTURE_DIR.parents[2]
SCHEMA="hermternal.deep-link-resolution.v2"
BASELINE_SCHEMA="hermternal.deep-link-resolution-baseline.v2"
EVIDENCE_SCHEMA="hermternal.deep-link-resolution-baseline-evidence.v1"
REVIEW_SCHEMA="hermternal.deep-link-resolution-review-root.v1"
CONTRACT="dashboard-v0.0.1"; OPERATION="C-16"
HERMES_SOURCE_SHA="f5be9236e00ddf2f2a412697f267078fc4ee068e"
PENDING_TTL_SECONDS=300
ERROR_PAYLOAD={"error":{"code":"contract","message":"deep-link resolution fixture rejected"}}
MAX_FILE_BYTES=1_048_576; MAX_STRING_BYTES=4096; MAX_CONTAINER_ITEMS=256
MAX_NODES=50_000; MAX_DEPTH=32; MAX_INTEGER=1_000_000_000
MAX_LINEAGE_NODES=32; READ_CHUNK_BYTES=65_536
ROOT_ID="session-root-0000000000000000000000000000000000000001"
BRANCH_ID="session-branch-0000000000000000000000000000000000000002"
SIBLING_ID="session-sibling-0000000000000000000000000000000000000003"
MESSAGE_ID="synthetic-message-anchor-00000000000000000000000000000001"
DEFAULT_ORIGIN="https://synthetic.hermternal.test"
DEPENDENCIES={
 "deep-link-grammar/cases.json":"91fad69ec110ea8042678b963076056b4474072d24f9698067ed8bfc10c03d96",
 "deep-link-grammar/validate.py":"c01cc7958ebd573fa336d72de551e9c4b45e27397c6a38f5012eff35edff314e",
 "session-lineage/cases.json":"ebd320005dea1623b691346ef6b2b38a60fb510c7b4ed16855c02e9d395540ea",
 "session-lineage/validation-baseline.json":"c62ffce8836f873c03143d2716b83e99db1843083bef82d5697cd5a613f88b3d",
}
CASE_IDS=(
 "authenticated-exact-root-direct-load","authenticated-message-anchor-focus",
 "latest-descendant-ordered-branching","latest-descendant-order-tie-fails-closed",
 "latest-descendant-malformed-order-fails-closed","unknown-session-safe-not-found",
 "unauthorized-session-safe-not-found","message-not-found-opens-session",
 "pending-auth-resolves-and-clears","pending-target-expires-at-deadline",
 "pending-target-before-deadline-stays-pending","logout-clears-pending-target",
 "direct-reload-reparses-and-reauthenticates","interrupted-lookup-recovers",
 "invalid-private-https-origin","invalid-hermternal-authority","empty-no-target",
 "latest-descendant-message-focus",
)
# The independent review root authorizes local artifacts. These chunks are
# normalized only when the root records the validator source identity.
REVIEW_ROOT_DIGEST_PARTS=(
 "8e2c2bd594313c9f",
 "370dbbbf33918ab4",
 "47678f6365af6741",
 "0a07fb34e5473f86",
)
class ContractError(ValueError): pass
def require(condition:bool)->None:
 if not condition: raise ContractError("contract rejected")
def sha256_bytes(data:bytes)->str: return hashlib.sha256(data).hexdigest()
@dataclass(frozen=True)
class Artifact:
 path:Path; data:bytes; sha256:str

def read_artifact_once(path:Path,limit:int=MAX_FILE_BYTES)->Artifact:
 """Stream a stable regular file; reject symlinks and path replacement."""
 flags=os.O_RDONLY | (getattr(os,"O_NOFOLLOW",0))
 try: descriptor=os.open(path,flags)
 except OSError as exc: raise ContractError("contract rejected") from exc
 try:
  before=os.fstat(descriptor); require(stat.S_ISREG(before.st_mode) and before.st_size<=limit)
  chunks=[]; total=0; digest=hashlib.sha256()
  while True:
   chunk=os.read(descriptor,min(READ_CHUNK_BYTES,limit+1-total))
   if not chunk: break
   total+=len(chunk); require(total<=limit); digest.update(chunk); chunks.append(chunk)
  after=os.fstat(descriptor)
  require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns))
  current=os.stat(path,follow_symlinks=False)
  require(stat.S_ISREG(current.st_mode) and not stat.S_ISLNK(current.st_mode))
  require((current.st_dev,current.st_ino)==(after.st_dev,after.st_ino))
  data=b"".join(chunks); require(len(data)==after.st_size)
  return Artifact(path,data,digest.hexdigest())
 except OSError as exc: raise ContractError("contract rejected") from exc
 finally: os.close(descriptor)
class ArtifactStore:
 def __init__(self)->None: self.items:dict[Path,Artifact]={}
 def read(self,path:Path)->Artifact:
  key=Path(os.path.abspath(path))
  if key not in self.items: self.items[key]=read_artifact_once(key)
  return self.items[key]
def _pairs(pairs:list[tuple[str,Any]])->dict[str,Any]:
 result={}
 for key,value in pairs: require(key not in result); result[key]=value
 return result
def _constant(_value:str)->Any: raise ContractError("contract rejected")
def parse_json_bytes(data:bytes)->Any:
 try: value=json.loads(data.decode("utf-8"),object_pairs_hook=_pairs,parse_constant=_constant)
 except (UnicodeError,json.JSONDecodeError,ContractError) as exc: raise ContractError("contract rejected") from exc
 validate_tree(value); return value
def validate_tree(root:Any)->None:
 """Apply exact JSON bounds with an iterative walk."""
 stack=[(root,0)]; nodes=0
 while stack:
  value,depth=stack.pop(); nodes+=1; require(nodes<=MAX_NODES and depth<=MAX_DEPTH); kind=type(value)
  if value is None or kind is bool: continue
  if kind is str: require(len(value.encode())<=MAX_STRING_BYTES)
  elif kind is int: require(abs(value)<=MAX_INTEGER)
  elif kind is float: require(math.isfinite(value) and abs(value)<=MAX_INTEGER)
  elif kind is list: require(len(value)<=MAX_CONTAINER_ITEMS); stack.extend((item,depth+1) for item in reversed(value))
  elif kind is dict:
   require(len(value)<=MAX_CONTAINER_ITEMS)
   for key,item in value.items(): require(type(key)is str); stack.extend(((key,depth+1),(item,depth+1)))
  else: raise ContractError("contract rejected")
def strict_equal(left:Any,right:Any)->bool:
 pending=[(left,right)]
 while pending:
  a,b=pending.pop()
  if type(a)is not type(b): return False
  if type(a)is dict:
   if list(a)!=list(b): return False
   pending.extend((a[key],b[key]) for key in a)
  elif type(a)is list:
   if len(a)!=len(b): return False
   pending.extend(zip(a,b))
  elif a!=b: return False
 return True
def parse_link(link:Any)->tuple[bool,str|None,str|None]:
 """Apply the exact private grammar without opaque-ID normalization."""
 if type(link)is not str or len(link.encode())>MAX_STRING_BYTES: return False,None,None
 if any(ord(c)>127 or ord(c)<32 or 127<=ord(c)<=159 for c in link): return False,None,None
 if any(m in link for m in ("%","\\","?","#")) or link.endswith("/"): return False,None,None
 if link.startswith(DEFAULT_ORIGIN+"/"): path=link[len(DEFAULT_ORIGIN):]
 elif link.startswith("hermternal://open/"): path=link[len("hermternal://open"):]
 else: return False,None,None
 parts=path.split("/")
 if len(parts)not in {4,6} or parts[:3]!=["","v1","c"] or (len(parts)==6 and parts[4]!="m"): return False,None,None
 ids=[parts[3]]+([parts[5]] if len(parts)==6 else[]); allowed=frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
 if any(len(v)<16 or "..." in v or any(c not in allowed for c in v) for v in ids): return False,None,None
 return True,ids[0],ids[1] if len(ids)==2 else None
def pinned_lineage(store:ArtifactStore)->dict[str,tuple[str,str|None]]:
 artifact=store.read(REPO_ROOT/"contracts/fixtures/session-lineage/cases.json"); require(artifact.sha256==DEPENDENCIES["session-lineage/cases.json"])
 document=parse_json_bytes(artifact.data); found={}
 for case in document["cases"]:
  expected=case["expected"]; sid=expected["session_id"]
  if sid in {ROOT_ID,BRANCH_ID} and expected["durable"] is True: found[sid]=(expected["root_id"],expected["parent_id"])
 require(found=={ROOT_ID:(ROOT_ID,None),BRANCH_ID:(ROOT_ID,ROOT_ID)}); return found
def latest_descendant(requested:str,evidence:Any,lineage:Mapping[str,tuple[str,str|None]])->tuple[str,str,str|None]:
 """Derive one latest descendant from explicit bounded sequence evidence."""
 require(type(evidence)is list and 1<=len(evidence)<=MAX_LINEAGE_NODES); nodes={}
 for item in evidence:
  require(type(item)is dict and list(item)==["session_id","root_id","parent_id","sequence"])
  sid,root,parent,sequence=item.values(); require(type(sid)is str and type(root)is str and (parent is None or type(parent)is str)); require(type(sequence)is int and 0<=sequence<=MAX_INTEGER and sid not in nodes); nodes[sid]=(root,parent,sequence)
 require(requested in nodes)
 for sid,(root,parent,_sequence) in nodes.items():
  require(root==requested); require(parent is None if sid==requested else parent in nodes)
 candidates=[]
 for sid,(_root,_parent,sequence) in nodes.items():
  cursor=sid; visited=set()
  while cursor!=requested:
   require(cursor not in visited and len(visited)<MAX_LINEAGE_NODES); visited.add(cursor); parent=nodes[cursor][1]; require(parent is not None); cursor=parent
  candidates.append((sequence,sid))
 highest=max(sequence for sequence,_sid in candidates); winners=[sid for sequence,sid in candidates if sequence==highest]; require(len(winners)==1)
 selected=winners[0]; root,parent,_sequence=nodes[selected]
 if selected in lineage: require(lineage[selected]==(root,parent))
 return selected,root,parent
@dataclass
class Resolver:
 link_input:str|None; authenticated_context:bool; lookup_mode:str; ordering:Any
 state:str="idle"; pending_link:str|None=None; pending_session_id:str|None=None; pending_message_id:str|None=None; deadline_seconds:int|None=None
 opened_session_id:str|None=None; root_id:str|None=None; parent_id:str|None=None; focus:str="none"; decision:str="pending"
 lookup_attempts:int=0; parse_attempts:int=0; authentication_checks:int=0
 state_trace:list[str]=field(default_factory=lambda:["idle"]); effects:list[str]=field(default_factory=list)
 def transition(self,state:str)->None:
  if self.state!=state: self.state=state; self.state_trace.append(state)
 def cleanup(self)->None:
  self.pending_link=self.pending_session_id=self.pending_message_id=None; self.deadline_seconds=None; self.effects.append("pending_target_erased")
 def receive(self,now:int)->None:
  self.parse_attempts+=1; valid,sid,mid=parse_link(self.link_input)
  if not valid: self.decision="invalid_link"; self.effects.append("grammar_rejected_before_lookup"); self.transition("failed"); self.cleanup(); return
  self.pending_link=self.link_input; self.pending_session_id=sid; self.pending_message_id=mid; self.deadline_seconds=now+PENDING_TTL_SECONDS; self.effects.extend(("grammar_validated","deadline_set_300_seconds"))
  if self.authenticated_context: self.authentication_checks+=1; self.lookup_attempts+=1; self.effects.extend(("authentication_confirmed","authenticated_lookup_started")); self.transition("lookup_pending")
  else: self.transition("auth_pending")
 def apply(self,event:Mapping[str,Any],lineage:Mapping[str,tuple[str,str|None]])->None:
  require(type(event)is dict and list(event)==["type","at_seconds"]); kind,now=event.values(); require(type(kind)is str and type(now)is int and 0<=now<=MAX_INTEGER)
  if kind=="receive": require(self.state=="idle"); self.receive(now)
  elif kind=="authenticated": require(self.state=="auth_pending" and self.deadline_seconds is not None and now<self.deadline_seconds); self.authentication_checks+=1; self.lookup_attempts+=1; self.effects.extend(("authentication_confirmed","authenticated_lookup_started")); self.transition("lookup_pending")
  elif kind=="lookup_present":
   require(self.state=="lookup_pending" and self.pending_session_id is not None)
   try:
    if self.lookup_mode=="latest_descendant": selected,root,parent=latest_descendant(self.pending_session_id,self.ordering,lineage); self.effects.extend(("latest_descendant_selected_from_sequence","lineage_preserved"))
    else: selected=self.pending_session_id; require(selected in lineage); root,parent=lineage[selected]
   except ContractError: self.decision="lineage_unavailable"; self.effects.extend(("lineage_ordering_rejected","no_session_created")); self.transition("failed"); self.cleanup(); return
   self.opened_session_id,self.root_id,self.parent_id=selected,root,parent; self.effects.append("exact_full_id_resolved"); self.transition("session_open")
  elif kind in {"lookup_missing","lookup_denied"}: require(self.state=="lookup_pending"); self.decision="session_not_found"; self.effects.extend(("authorization_safe_session_not_found","no_session_created")); self.transition("failed"); self.cleanup()
  elif kind=="message_present": require(self.state=="session_open" and self.pending_message_id is not None); self.focus,self.decision="message","message_focused"; self.effects.append("message_anchor_focused"); self.transition("opened"); self.cleanup()
  elif kind=="message_missing": require(self.state=="session_open" and self.pending_message_id is not None); self.focus,self.decision="session_start","message_not_found"; self.effects.extend(("session_opened","message_not_found_fallback")); self.transition("opened"); self.cleanup()
  elif kind=="complete": require(self.state=="session_open" and self.pending_message_id is None); self.focus,self.decision="session","session_opened"; self.effects.append("session_opened"); self.transition("opened"); self.cleanup()
  elif kind=="reload": require(self.state=="opened" and self.pending_link is None and self.deadline_seconds is None); self.effects.append("direct_reload_requires_fresh_resolution"); self.transition("idle")
  elif kind=="interrupt": require(self.state=="lookup_pending"); self.effects.append("lookup_interrupted_safe_state"); self.transition("interrupted")
  elif kind=="recover": require(self.state=="interrupted" and self.pending_session_id is not None and self.deadline_seconds is not None and now<self.deadline_seconds); self.authentication_checks+=1; self.lookup_attempts+=1; self.effects.extend(("authentication_reconfirmed","authenticated_lookup_retried_idempotently")); self.transition("lookup_pending")
  elif kind=="expire":
   require(self.deadline_seconds is not None)
   if now<self.deadline_seconds: self.effects.append("deadline_not_reached")
   else: self.decision="target_expired"; self.effects.append("deadline_reached_300_seconds"); self.transition("expired"); self.cleanup()
  elif kind=="logout": require(self.pending_session_id is not None); self.authenticated_context=False; self.decision="signed_out"; self.transition("signed_out"); self.cleanup()
  else: raise ContractError("contract rejected")
 def result(self)->dict[str,Any]:
  return {"decision":self.decision,"final_state":self.state,"state_trace":self.state_trace,"effects":self.effects,"opened_session_id":self.opened_session_id,"root_id":self.root_id,"parent_id":self.parent_id,"focus":self.focus,"pending_link":self.pending_link,"pending_session_id":self.pending_session_id,"pending_message_id":self.pending_message_id,"deadline_seconds":self.deadline_seconds,"lookup_attempts":self.lookup_attempts,"parse_attempts":self.parse_attempts,"authentication_checks":self.authentication_checks,"session_creations":0,"shares":0,"transcript_mirror":False,"network":False}
def reduce_case(case:Mapping[str,Any],lineage:Mapping[str,tuple[str,str|None]])->dict[str,Any]:
 resolver=Resolver(case["link"],case["authenticated"],case["lookup_mode"],case["lineage_ordering"]); previous=-1
 for event in case["events"]: require(type(event)is dict and type(event.get("at_seconds"))is int and event["at_seconds"]>=previous); previous=event["at_seconds"]; resolver.apply(event,lineage)
 return resolver.result()
ROOT_KEYS=["schema","operation","contract","hermes_source_sha","synthetic_only","network","pending_ttl_seconds","dependencies","invariants","cases","redaction"]
CASE_KEYS=["id","link","authenticated","lookup_mode","lineage_ordering","events","expected","notes"]
EXPECTED_KEYS=["decision","final_state","state_trace","effects","opened_session_id","root_id","parent_id","focus","pending_link","pending_session_id","pending_message_id","deadline_seconds","lookup_attempts","parse_attempts","authentication_checks","session_creations","shares","transcript_mirror","network"]
INVARIANTS={"exact_ids":"full opaque IDs are preserved without normalization","latest_descendant":"explicit bounded sequence evidence selects one unique descendant","authorization":"missing and denied share one session-not-found outcome","pending_target":"link and IDs are erased on success, failure, expiry, or logout","reload":"repeat parse and authentication resolution before lookup","creation":False,"sharing":False,"local_transcript_mirror":False}
REDACTION={"synthetic_only":True,"raw_links_in_errors":False,"raw_ids_in_errors":False,"fixed_error":ERROR_PAYLOAD}
def verify_dependencies(document:Mapping[str,Any],store:ArtifactStore)->None:
 identities=document["dependencies"]; require(type(identities)is dict and list(identities)==list(DEPENDENCIES))
 for name,expected in DEPENDENCIES.items(): artifact=store.read(REPO_ROOT/"contracts/fixtures"/name); require(identities[name]=={"sha256":expected} and artifact.sha256==expected)
def validate_expected(value:Any)->None:
 require(type(value)is dict and list(value)==EXPECTED_KEYS)
 for key in ("decision","final_state","focus"): require(type(value[key])is str)
 for key in ("state_trace","effects"): require(type(value[key])is list and all(type(item)is str for item in value[key]))
 for key in ("opened_session_id","root_id","parent_id","pending_link","pending_session_id","pending_message_id"): require(value[key] is None or type(value[key])is str)
 require(value["deadline_seconds"] is None or type(value["deadline_seconds"])is int)
 for key in ("lookup_attempts","parse_attempts","authentication_checks","session_creations","shares"): require(type(value[key])is int and 0<=value[key]<=10)
 require(value["session_creations"]==0 and value["shares"]==0 and value["transcript_mirror"] is False and value["network"] is False)
 if value["final_state"] in {"opened","failed","expired","signed_out"}: require(all(value[key] is None for key in ("pending_link","pending_session_id","pending_message_id","deadline_seconds")))
def validate_document(document:Mapping[str,Any],store:ArtifactStore)->None:
 require(type(document)is dict and list(document)==ROOT_KEYS); require(document["schema"]==SCHEMA and document["operation"]==OPERATION and document["contract"]==CONTRACT and document["hermes_source_sha"]==HERMES_SOURCE_SHA); require(document["synthetic_only"] is True and document["network"] is False and type(document["pending_ttl_seconds"])is int and document["pending_ttl_seconds"]==PENDING_TTL_SECONDS); require(strict_equal(document["invariants"],INVARIANTS) and strict_equal(document["redaction"],REDACTION)); verify_dependencies(document,store); lineage=pinned_lineage(store)
 cases=document["cases"]; require(type(cases)is list and [case.get("id") if type(case)is dict else None for case in cases]==list(CASE_IDS))
 for case in cases:
  require(type(case)is dict and list(case)==CASE_KEYS and type(case["id"])is str and type(case["notes"])is str and (case["link"] is None or type(case["link"])is str) and type(case["authenticated"])is bool and case["lookup_mode"] in {"exact","latest_descendant"} and type(case["lineage_ordering"])is list and len(case["lineage_ordering"])<=MAX_LINEAGE_NODES and type(case["events"])is list); validate_expected(case["expected"]); require(strict_equal(reduce_case(case,lineage),case["expected"]))
def validate_mutations(document:Mapping[str,Any],store:ArtifactStore|None=None)->int:
 mutations=(
  lambda v:v.update({"extra":True}),lambda v:v.update({"pending_ttl_seconds":True}),lambda v:v["dependencies"]["deep-link-grammar/cases.json"].update({"sha256":"0"*64}),lambda v:v["cases"].reverse(),lambda v:v["cases"][0].update({"authenticated":1}),lambda v:v["cases"][0]["events"][0].update({"at_seconds":True}),lambda v:v["cases"][0]["events"][1].update({"at_seconds":0}),lambda v:v["cases"][0]["expected"].update({"decision":"pending"}),lambda v:v["cases"][0]["expected"].update({"session_creations":1}),lambda v:v["cases"][0]["expected"].update({"pending_session_id":ROOT_ID}),lambda v:v["cases"][0]["expected"].update({"deadline_seconds":1300}),lambda v:v["cases"][12]["expected"].update({"parse_attempts":1}),lambda v:v["cases"][12]["expected"].update({"authentication_checks":1}),lambda v:v["cases"][2]["lineage_ordering"][1].update({"sequence":5}),lambda v:v["cases"][3]["expected"].update({"decision":"session_opened"}),lambda v:v["cases"][4]["expected"].update({"decision":"session_opened"}),lambda v:v["cases"][9]["events"][1].update({"at_seconds":1299}),lambda v:v["cases"][6]["expected"].update({"decision":"denied"}),lambda v:v["redaction"]["fixed_error"]["error"].update({"message":ROOT_ID}),lambda v:v["cases"][0]["expected"].update({"network":True}),
 )
 completed=0; shared_store=store or ArtifactStore()
 for mutate in mutations:
  changed=copy.deepcopy(document); mutate(changed)
  try: validate_document(changed,shared_store)
  except ContractError: completed+=1
  else: raise ContractError("contract rejected")
 return completed
def percentile_r7(values:list[float],quantile:Decimal)->float:
 ordered=sorted(Decimal(str(value)) for value in values); position=Decimal(len(ordered)-1)*quantile; lower=int(position); upper=min(lower+1,len(ordered)-1); fraction=position-Decimal(lower)
 with localcontext() as context: context.prec=50; value=ordered[lower]+(ordered[upper]-ordered[lower])*fraction
 return round(float(value),6)
def distribution(samples:list[float])->dict[str,float]: return {"min":round(min(samples),6),"p50":percentile_r7(samples,Decimal("0.50")),"p95":percentile_r7(samples,Decimal("0.95")),"max":round(max(samples),6),"mean":round(statistics.mean(samples),6)}
def validate_evidence(evidence:Any)->None:
 require(type(evidence)is dict and list(evidence)==["schema","percentile_method","normal","optimized"] and evidence["schema"]==EVIDENCE_SCHEMA and evidence["percentile_method"]=="inclusive_linear_interpolation_r7")
 for mode in ("normal","optimized"):
  item=evidence[mode]; require(type(item)is dict and list(item)==["samples_ms","distribution"]); samples=item["samples_ms"]; require(type(samples)is list and len(samples)==30 and all(type(sample)is float and math.isfinite(sample) and sample>0 for sample in samples)); require(strict_equal(item["distribution"],distribution(samples)))
def validate_baseline(baseline:Any,evidence:Any)->None:
 keys=["schema","validator","commands","build_mode","environment","repetitions","percentile_method","normal","optimized","threshold"]
 require(type(baseline)is dict and list(baseline)==keys and baseline["schema"]==BASELINE_SCHEMA and baseline["validator"]=="contracts/fixtures/deep-link-resolution/validate.py" and baseline["commands"]=={"normal":"python3 contracts/fixtures/deep-link-resolution/validate.py","optimized":"python3 -O contracts/fixtures/deep-link-resolution/validate.py"} and baseline["build_mode"]=="N/A" and baseline["threshold"] is None and type(baseline["repetitions"])is int and baseline["repetitions"]==30 and baseline["percentile_method"]=="inclusive_linear_interpolation_r7" and strict_equal(baseline["normal"],evidence["normal"]) and strict_equal(baseline["optimized"],evidence["optimized"]))
def normalized_validator_bytes(data:bytes)->bytes:
 text=data.decode(); text=re.sub(r'REVIEW_ROOT_DIGEST_PARTS=\(\n(?: "[^"]+",\n){4}\)', 'REVIEW_ROOT_DIGEST_PARTS=(\n "<REVIEWED>",\n "<REVIEWED>",\n "<REVIEWED>",\n "<REVIEWED>",\n)',text); return text.encode()
def validate_review_root(root:Any,artifacts:Mapping[str,Artifact])->None:
 require(type(root)is dict and list(root)==["schema","reviewed_operation","artifact_sha256"] and root["schema"]==REVIEW_SCHEMA and root["reviewed_operation"]==OPERATION)
 names=["README.md","cases.json","test_validate.py","validate.py.normalized","baseline-evidence.json","validation-baseline.json","docs/architecture/deep-links.md",*DEPENDENCIES]; identities=root["artifact_sha256"]; require(type(identities)is dict and list(identities)==names)
 for name in names:
  actual=sha256_bytes(normalized_validator_bytes(artifacts["validate.py"].data)) if name=="validate.py.normalized" else artifacts[name].sha256; require(identities[name]==actual)
def validate_all(cases_path:Path,baseline_path:Path,evidence_path:Path)->tuple[int,int]:
 store=ArtifactStore(); paths={"README.md":FIXTURE_DIR/"README.md","cases.json":cases_path,"test_validate.py":FIXTURE_DIR/"test_validate.py","validate.py":FIXTURE_DIR/"validate.py","baseline-evidence.json":evidence_path,"validation-baseline.json":baseline_path,"docs/architecture/deep-links.md":REPO_ROOT/"docs/architecture/deep-links.md"}; paths.update({name:REPO_ROOT/"contracts/fixtures"/name for name in DEPENDENCIES}); artifacts={name:store.read(path) for name,path in paths.items()}; review=store.read(FIXTURE_DIR/"review-root.json"); digest=store.read(FIXTURE_DIR/"review-root-sha256.txt"); approved="".join(REVIEW_ROOT_DIGEST_PARTS); require(len(approved)==64 and digest.data==(approved+"\n").encode("ascii") and review.sha256==approved); validate_review_root(parse_json_bytes(review.data),artifacts); document=parse_json_bytes(artifacts["cases.json"].data); validate_document(document,store); evidence=parse_json_bytes(artifacts["baseline-evidence.json"].data); validate_evidence(evidence); baseline=parse_json_bytes(artifacts["validation-baseline.json"].data); validate_baseline(baseline,evidence); return len(document["cases"]),validate_mutations(document,store)
def controlled_arguments(argv:list[str]|None)->argparse.Namespace:
 parser=argparse.ArgumentParser(add_help=False,exit_on_error=False)
 parser.add_argument("--cases",type=Path,default=FIXTURE_DIR/"cases.json"); parser.add_argument("--baseline",type=Path,default=FIXTURE_DIR/"validation-baseline.json"); parser.add_argument("--evidence",type=Path,default=FIXTURE_DIR/"baseline-evidence.json")
 try: args,unknown=parser.parse_known_args(argv)
 except (argparse.ArgumentError,SystemExit) as exc: raise ContractError("contract rejected") from exc
 require(not unknown); return args
def main(argv:list[str]|None=None)->int:
 try: args=controlled_arguments(argv); count,mutations=validate_all(args.cases,args.baseline,args.evidence)
 except Exception: print(json.dumps(ERROR_PAYLOAD,separators=(",",":"),sort_keys=True)); return 1
 print(f"deep_link_resolution_validation=ok cases={count} mutations={mutations}"); return 0
if __name__=="__main__": raise SystemExit(main())
