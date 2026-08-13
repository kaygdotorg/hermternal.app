#!/usr/bin/env python3
"""Bind retained replay evidence to the fixed integrated final authority.

The production entry point is intentionally unavailable until a separate
approved retained-driver artifact exists.  This module authenticates that
future boundary; its tests run only the approved final-freeze prepare path.
"""
from __future__ import annotations
import hashlib, json, os, re, stat, sys, tempfile, types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

BASE = Path(__file__).resolve().parents[1]
FINAL_ROOT = BASE / "task464-candidate5-final"
FREEZE = BASE / "task464-candidate5-final-freeze" / "final_freeze.py"
ORCHESTRATOR = BASE / "task464-candidate5-final-triad" / "generator_orchestrator.py"
AUTHORITY = BASE / "task464-candidate5-authority-successor" / "candidate5_authority.py"
GIT_AUTHORITY = BASE / "task464-candidate5-git-config-successor" / "candidate5_git_config_successor.py"
FREEZE_SHA = "714f6ef3fd780acccd1520a090428c3d4c20c1be8178e84114015b1c07f87316"
ORCHESTRATOR_SHA = "d9c36a3c3e99d0379186fc9ea0a26a5d93ac26eb4bd1c826c209b9bee0547361"
AUTHORITY_SHA = "1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8"
GIT_AUTHORITY_SHA = "b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a"
PROVENANCE_SHA = "363d6f62335a5ff9f92eefabe87dd568032e71871390fa9fc5ae6fd72e3ac320"
OID = re.compile(r"[0-9a-f]{40}\Z")

class Reject(Exception): pass
def require(ok: bool, message: str) -> None:
    if not ok: raise Reject(message)

def stable_read(path: Path, label: str, mode: int | None = None) -> bytes:
    """Return exact 0600 single-link bytes after three no-follow reads."""
    path = Path(path); require(path.is_absolute() and os.path.realpath(path) == str(path), f"{label} is not canonical")
    seen=[]
    for _ in range(3):
        fd=os.open(path, os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        try:
            before=os.fstat(fd); require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and (mode is None or stat.S_IMODE(before.st_mode)==mode), f"{label} is not an expected single-link file")
            raw=os.read(fd, before.st_size+1); after=os.fstat(fd)
        finally: os.close(fd)
        final=os.lstat(path); require((before.st_dev,before.st_ino,before.st_size)==(after.st_dev,after.st_ino,after.st_size)==(final.st_dev,final.st_ino,final.st_size) and len(raw)==before.st_size, f"{label} changed")
        seen.append(raw)
    require(seen[0]==seen[1]==seen[2], f"{label} changed across reads"); return seen[0]

def verified_module(path: Path, digest: str, name: str) -> types.ModuleType:
    raw=stable_read(path, name); require(hashlib.sha256(raw).hexdigest()==digest, f"{name} hash differs")
    module=types.ModuleType(name); module.__file__=str(path); module.__package__=""; module.__loader__=None; module.__spec__=None
    sys.modules[name]=module; exec(compile(raw,str(path),"exec",dont_inherit=True),module.__dict__); return module

def strict_json(raw: bytes, label: str) -> dict[str,Any]:
    def pairs(items):
        out={}
        for key,value in items: require(key not in out,f"{label} duplicate key"); out[key]=value
        return out
    value=json.loads(raw.decode(),object_pairs_hook=pairs); require(isinstance(value,dict),f"{label} root differs"); return value

@dataclass(frozen=True)
class ApprovedAuthority:
    freeze: types.ModuleType; orchestrator: types.ModuleType; candidate: types.ModuleType; reviewer: types.ModuleType
    root: Path; provenance_sha256: str; argv: tuple[str,...]; stdin: bytes
    base: str; base_tree: str; main: str; source: str; required: tuple[str,...]; forbidden: tuple[str,...]

def _load_authority_at(root: Path, provenance_sha: str) -> ApprovedAuthority:
    """Verified-load only the exact integrated #403/#401/#400 modules and root."""
    freeze=verified_module(FREEZE,FREEZE_SHA,"issue397_final_freeze")
    orchestrator=verified_module(ORCHESTRATOR,ORCHESTRATOR_SHA,"issue397_orchestrator")
    candidate=verified_module(AUTHORITY,AUTHORITY_SHA,"issue397_candidate_authority")
    reviewer=verified_module(GIT_AUTHORITY,GIT_AUTHORITY_SHA,"issue397_git_authority").install_successor()
    require(orchestrator.FINAL_NAMES["json"] == "candidate-five.json", "#403 final names differ")
    # Genuine #401 returns the only executable argv/stdin after descriptor validation.
    auth=candidate.validate(root / "authority-descriptor.json", root, hashlib.sha256(stable_read(root / "authority-descriptor.json","descriptor",0o600)).hexdigest())
    freeze_orch, _ = freeze.load_approved(); require(freeze_orch.__dict__.get("APPROVED_PUBLICATION_SHA256")==orchestrator.APPROVED_PUBLICATION_SHA256,"#403 orchestration differs")
    provenance_raw=stable_read(root / "provenance-manifest.json","provenance",0o600); require(hashlib.sha256(provenance_raw).hexdigest()==provenance_sha,"provenance pin differs")
    provenance=strict_json(provenance_raw,"provenance"); require(provenance.get("repository_boundary",{}).get("output_root")==str(root),"provenance output root differs")
    document=strict_json(auth.artifacts["json"].raw,"candidate JSON"); base=document.get("base",{}); forbidden=document.get("forbidden_ancestry",{})
    for value in (base.get("commit"),base.get("tree"),base.get("protected_main_commit")): require(isinstance(value,str) and OID.fullmatch(value),"candidate base pins differ")
    source=next((lane.get("source_commit",{}).get("commit") for lane in document.get("ordered_lanes",[]) if lane.get("source_commit")), None)
    require(isinstance(source,str) and OID.fullmatch(source),"candidate source pin differs")
    forbidden_values=tuple(forbidden.get("commits",[])); require(all(isinstance(x,str) and OID.fullmatch(x) for x in forbidden_values),"candidate forbidden pins differ")
    return ApprovedAuthority(freeze,orchestrator,candidate,reviewer,root,provenance_sha,auth.argv,auth.stdin,base["commit"],base["tree"],base["protected_main_commit"],source,(),forbidden_values)

def load_approved_authority() -> ApprovedAuthority:
    """Accept only the fixed canonical durable final root and its pinned bytes."""
    require(FINAL_ROOT == verified_module(FREEZE,FREEZE_SHA,"issue397_root_freeze").FINAL_ROOT, "fixed final root differs")
    return _load_authority_at(FINAL_ROOT, PROVENANCE_SHA)

def prepare_authority_only() -> ApprovedAuthority:
    """Exercise the real #403 disposable preparation path; never execute a shell."""
    freeze=verified_module(FREEZE,FREEZE_SHA,"issue397_prepare_freeze")
    with tempfile.TemporaryDirectory(prefix="issue397-authority-prepare-") as parent:
        root=(Path(parent)/"output").resolve(); result=freeze.freeze_to_root(root)
        return _load_authority_at(result.root, result.snapshots["provenance-manifest.json"].sha256)

def retained_replay_is_not_ready(*_args: Any, **_kwargs: Any) -> None:
    """No retained-driver artifact is approved, so no replay can be invoked."""
    raise Reject("retained replay driver is not approved; execution remains blocked")
