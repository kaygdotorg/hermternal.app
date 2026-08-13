#!/usr/bin/env python3
"""Bind reviewed #405 to the forbidden-object proof successor."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import forbidden_proof
import linux_replay_wrapper_v2
import linux_retained_driver_v3

HERE = Path(__file__).resolve().parent
V2_PATH = HERE / "linux_replay_wrapper_v2.py"
V2_SHA256 = "9c2ce8a191efe8dcefd427da5c4bde7353683e5787ce8d32b988d9106aa32e54"
DRIVER_PATH = HERE / "linux_retained_driver_v3.py"
DRIVER_SHA256 = "b19072f9d6cbc6cb9e6fc271bf468ffe182c3e4b7e1f04b0f6f4c7a54fcc2de5"
DERIVED_STDIN_SHA256 = "f2cfe111eeaec6850a57076c46c883f40ad91ef059be658c51d5e58b01f281c6"


def _load_v2():
    """Install v3 authority data in the exact reviewed v2 wrapper."""
    if hashlib.sha256(V2_PATH.read_bytes()).hexdigest() != V2_SHA256:
        raise RuntimeError("Linux replay wrapper v2 SHA-256 differs")
    if hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest() != DRIVER_SHA256:
        raise RuntimeError("Linux retained-driver v3 SHA-256 differs")
    module = linux_replay_wrapper_v2._load_v1()
    module.linux_retained_driver = linux_retained_driver_v3
    module.DRIVER_ADAPTER_PATH = DRIVER_PATH
    module.DRIVER_ADAPTER_SHA256 = hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest()
    module.DERIVED_STDIN_SHA256 = DERIVED_STDIN_SHA256
    return module


def load_wrapper():
    """Return #405 with the proof-aware driver, still disabled for Phase A v6."""
    wrapper, authority = _load_v2().load_wrapper()
    # Keep the reviewed disabled-boundary anchor exact. Phase A v6 removes this
    # line only after its proof-bound anchor is authenticated.
    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v3 authority is not installed"))
    return wrapper, authority


def preflight() -> dict[str, object]:
    """Authenticate the full proof classification without starting replay."""
    result = _load_v2().preflight()
    proof = linux_retained_driver_v3.forbidden_proof_record()
    result.update({"driver_adapter_sha256": hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest(),
                   "derived_stdin_sha256": DERIVED_STDIN_SHA256,
                   "forbidden_proof_sha256": forbidden_proof.record_sha256(proof),
                   "phase_a_v6_required": True, "execution_enabled": False})
    return result


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
