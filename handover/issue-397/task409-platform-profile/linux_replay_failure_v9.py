#!/usr/bin/env python3
"""Propagate the authenticated v10 adapter through the exact v8 failure path."""
from __future__ import annotations
import hashlib, os, stat, sys, types
from pathlib import Path
HERE=Path(__file__).resolve().parent
V8_PATH=HERE/"linux_replay_failure_v8.py"
V8_SHA256="d61a1ad845eeee69978b0bed78f6e03e73b21ab04969117582010ab391e14558"
PHASE_A_V10_PATH=HERE/"linux_phase_a_v10.py"
PHASE_A_V10_SHA256="15e1492607fcb43f14cd290eef9e0e3df6d4b4a19e5b4bbf278b69647853461b"
SCHEMA="hermternal.issue-397.replay-failure.v9"
DIRECTORY_NAME="hermternal-issue397-replay-failure-v9"
def _stable_bytes(path:Path,digest:str,label:str)->bytes:
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: raise RuntimeError(f"{label} is not a single-link regular file")
  raw=os.read(fd,before.st_size); after=os.fstat(fd)
 finally: os.close(fd)
 current=os.lstat(path); identity=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,value.st_size,value.st_nlink,value.st_mtime_ns,value.st_ctime_ns)
 if identity(before)!=identity(after) or identity(before)!=identity(current): raise RuntimeError(f"{label} changed during read")
 if hashlib.sha256(raw).hexdigest()!=digest: raise RuntimeError(f"{label} SHA-256 differs")
 return raw
def _load_v8()->types.ModuleType:
 """Use one authenticated v8 failure source with only v10 pin substitutions."""
 raw=_stable_bytes(V8_PATH,V8_SHA256,"failure v8")
 replacements=((b"linux_phase_a_v9.py",b"linux_phase_a_v10.py"),(b"290d4ae114dad91b3bd15da0e31d698fe8a1b9d67dcc95f2e90d1f0b44c4b331",PHASE_A_V10_SHA256.encode()),(b"hermternal.issue-397.replay-failure.v8",SCHEMA.encode()),(b"hermternal-issue397-replay-failure-v8",DIRECTORY_NAME.encode()))
 for old,new in replacements:
  if raw.count(old)!=1: raise RuntimeError("failure v9 successor transform differs")
  raw=raw.replace(old,new,1)
 module=types.ModuleType("issue397_linux_replay_failure_v9_base"); module.__file__=os.fspath(Path(__file__).resolve()); sys.modules[module.__name__]=module
 exec(compile(raw,os.fspath(V8_PATH),"exec",dont_inherit=True),module.__dict__)
 module.SCHEMA=SCHEMA; module.DIRECTORY_NAME=DIRECTORY_NAME
 return module
def load_approved_wrapper(expected_anchor_sha256:str): return _load_v8().load_approved_wrapper(expected_anchor_sha256)
def __getattr__(name:str): return getattr(_load_v8(),name)
