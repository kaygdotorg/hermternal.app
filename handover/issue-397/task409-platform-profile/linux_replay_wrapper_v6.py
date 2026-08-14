#!/usr/bin/env python3
"""Keep replay disabled while it authenticates the root-shape driver."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
import linux_replay_wrapper_v5 as predecessor
import linux_retained_driver_v6
HERE = Path(__file__).resolve().parent
V5_PATH = HERE / "linux_replay_wrapper_v5.py"
V5_SHA256 = "83b9dd0fecb26889ddaa0de78a146ad1af22c3e991f4d4bcf56f7900b01c1968"
DRIVER_PATH = HERE / "linux_retained_driver_v6.py"
DRIVER_SHA256 = "4363f123a52863304f56eb6847c7e228fc43eae765eb1658d3c0cf521af88cde"
DERIVED_STDIN_SHA256 = "740204d456c4890d1821ef9898338935b0ffe0f246b8cd6ae4c9641de97682ff"
def _load_v5():
    if hashlib.sha256(V5_PATH.read_bytes()).hexdigest() != V5_SHA256: raise RuntimeError("Linux replay wrapper v5 SHA-256 differs")
    if hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest() != DRIVER_SHA256: raise RuntimeError("Linux retained-driver v6 SHA-256 differs")
    module = predecessor._load_v4(); module.linux_retained_driver = linux_retained_driver_v6; module.DRIVER_ADAPTER_PATH = DRIVER_PATH; module.DRIVER_ADAPTER_SHA256 = DRIVER_SHA256; module.DERIVED_STDIN_SHA256 = DERIVED_STDIN_SHA256
    return module
def load_wrapper():
    """Do not authorize replay until separately approved Phase A v10 evidence."""
    wrapper, authority = _load_v5().load_wrapper()
    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v10 authority is not installed"))
    return wrapper, authority
def preflight() -> dict[str, object]:
    result = _load_v5().preflight(); result.pop("phase_a_v3_required", None); result.pop("phase_a_v8_required", None); result.update({"driver_adapter_sha256": DRIVER_SHA256, "derived_stdin_sha256": DERIVED_STDIN_SHA256, "phase_a_v10_required": True, "execution_enabled": False}); return result
if __name__ == "__main__": print(json.dumps(preflight(), sort_keys=True))
