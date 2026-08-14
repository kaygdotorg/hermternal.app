#!/usr/bin/env python3
"""Install v10 authority pins through the reviewed v9 lifecycle source."""
from __future__ import annotations
import hashlib, json, os, stat, sys, types
from pathlib import Path
from typing import Sequence
HERE = Path(__file__).resolve().parent
V9_PATH = HERE / "linux_phase_a_v9.py"
V9_SHA256 = "290d4ae114dad91b3bd15da0e31d698fe8a1b9d67dcc95f2e90d1f0b44c4b331"
WRAPPER_V6_PATH = HERE / "linux_replay_wrapper_v6.py"
DRIVER_V6_PATH = HERE / "linux_retained_driver_v6.py"
LINUX_WRAPPER_ADAPTER_SHA256 = "c8887fd0449ad6af3cfdebb721cf14ef9c91840f4d9b35e53f47b150f9821331"
LINUX_DRIVER_ADAPTER_SHA256 = "4363f123a52863304f56eb6847c7e228fc43eae765eb1658d3c0cf521af88cde"
V10_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v10"
V10_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v10"
V10_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v10"

def _stable_bytes(path: Path, digest: str | None, label: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1: raise RuntimeError(f"{label} is not a single-link regular file")
        raw=os.read(fd,before.st_size); after=os.fstat(fd)
    finally: os.close(fd)
    current=os.lstat(path); identity=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,value.st_size,value.st_nlink,value.st_mtime_ns,value.st_ctime_ns)
    if identity(before)!=identity(after) or identity(before)!=identity(current): raise RuntimeError(f"{label} changed during read")
    if digest is not None and hashlib.sha256(raw).hexdigest()!=digest: raise RuntimeError(f"{label} SHA-256 differs")
    return raw

def _patch_v8(raw: bytes) -> bytes:
    """Retarget authenticated v8 import-time pins before it can load v3."""
    replacements=((b"import linux_replay_wrapper_v5\n",b"import linux_replay_wrapper_v6 as linux_replay_wrapper_v5\n"),(b"import linux_retained_driver_v5\n",b"import linux_retained_driver_v6 as linux_retained_driver_v5\n"),(b"linux_replay_wrapper_v5 as linux_replay_wrapper_v4",b"linux_replay_wrapper_v6 as linux_replay_wrapper_v4"),(b"linux_retained_driver_v5 as linux_retained_driver_v4",b"linux_retained_driver_v6 as linux_retained_driver_v4"),(b"linux_replay_wrapper_v5 as linux_replay_wrapper",b"linux_replay_wrapper_v6 as linux_replay_wrapper"),(b"linux_retained_driver_v5.py",b"linux_retained_driver_v6.py"),(b"83b9dd0fecb26889ddaa0de78a146ad1af22c3e991f4d4bcf56f7900b01c1968",LINUX_WRAPPER_ADAPTER_SHA256.encode()),(b"0510d5f7ff5e011cb1875378ede3649222c8383ecb702978af8d791a408400e7",LINUX_DRIVER_ADAPTER_SHA256.encode()))
    for old,new in replacements:
        if raw.count(old)!=1: raise RuntimeError("Phase A v10 v8 import pin differs")
        raw=raw.replace(old,new,1)
    return raw

def _load_v9() -> types.ModuleType:
    """Make the exact current adapter substitutions once in authenticated v9 bytes."""
    raw=_stable_bytes(V9_PATH,V9_SHA256,"Phase A v9 adapter")
    replacements=((b"linux_replay_wrapper_v5.py",b"linux_replay_wrapper_v6.py"),(b"linux_retained_driver_v5.py",b"linux_retained_driver_v6.py"),(b'"linux_replay_wrapper_v5", "Linux replay wrapper v5"',b'"linux_replay_wrapper_v6", "Linux replay wrapper v6"'),(b'"linux_retained_driver_v5", "Linux retained-driver v5"',b'"linux_retained_driver_v6", "Linux retained-driver v6"'),(b"83b9dd0fecb26889ddaa0de78a146ad1af22c3e991f4d4bcf56f7900b01c1968",LINUX_WRAPPER_ADAPTER_SHA256.encode()),(b"0510d5f7ff5e011cb1875378ede3649222c8383ecb702978af8d791a408400e7",LINUX_DRIVER_ADAPTER_SHA256.encode()),(b"hermternal.issue-397.phase-a-anchor-runner.v9",V10_SCHEMA.encode()),(b"hermternal.issue-397.phase-a-anchor-evidence.v9",V10_EVIDENCE_SCHEMA.encode()),(b"hermternal-issue397-phase-a-anchor-v9",V10_ROOT_NAME.encode()),(b"Phase A v8 authority is not installed",b"Phase A v10 authority is not installed"))
    for old,new in replacements:
        if raw.count(old)!=1: raise RuntimeError("Phase A v10 successor transform differs")
        raw=raw.replace(old,new,1)
    raw=raw.replace(b"raw = _stable_bytes(V8_PATH, V8_SHA256, \"Phase A v8 adapter\")",b"raw = _patch_v8(_stable_bytes(V8_PATH, V8_SHA256, \"Phase A v8 adapter\"))",1)
    module=types.ModuleType("issue397_linux_phase_a_v10_base"); module.__file__=os.fspath(Path(__file__).resolve()); module._patch_v8=_patch_v8; sys.modules[module.__name__]=module
    exec(compile(raw,os.fspath(V9_PATH),"exec",dont_inherit=True),module.__dict__)
    return module

def _adapter_sha256() -> str: return hashlib.sha256(_stable_bytes(Path(__file__).resolve(),None,"Phase A v10 adapter")).hexdigest()
def load_runner(): return _load_v9().load_runner()
def phase_a():
    base=_load_v9(); runner=base.load_runner(); return runner.phase_a(runner.load_modules(),repository_root=runner.REPOSITORY_ROOT,external_root=runner.EXTERNAL_ROOT)
def anchor(expected_phase_a_sha256: str):
    base=_load_v9(); runner=base.load_runner(); return runner.anchor(runner.load_modules(),repository_root=runner.REPOSITORY_ROOT,external_root=runner.EXTERNAL_ROOT,expected_phase_a_sha256=expected_phase_a_sha256)
def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    if expected_adapter_sha256 != _adapter_sha256(): raise RuntimeError("Phase A v10 adapter SHA-256 differs")
    wrapper,authority=_load_v9().load_approved_wrapper(expected_anchor_sha256,expected_adapter_sha256); wrapper.PHASE_A_RUNNER_PATH=Path(__file__); return wrapper,authority
_EXPORT_BASE=_load_v9(); _EXPORT_RUNNER=_EXPORT_BASE.load_runner()
def __getattr__(name: str): return getattr(_EXPORT_RUNNER,name)
def main(argv: Sequence[str]|None=None)->int:
    arguments=list(sys.argv[1:] if argv is None else argv)
    if arguments==["phase-a"]: print(json.dumps(phase_a(),sort_keys=True,separators=(",",":"))); return 0
    if len(arguments)==3 and arguments[:2]==["anchor","--expected-phase-a-sha256"]: print(json.dumps(anchor(arguments[2]),sort_keys=True,separators=(",",":"))); return 0
    print("usage: linux_phase_a_v10.py phase-a | anchor --expected-phase-a-sha256 SHA256",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
