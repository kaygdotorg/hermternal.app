#!/usr/bin/env python3
"""Bind the disabled outer wrapper to the LF-corrected driver contract."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import linux_retained_driver_v4
import linux_replay_wrapper_v3 as predecessor

HERE = Path(__file__).resolve().parent
V3_PATH = HERE / "linux_replay_wrapper_v3.py"
V3_SHA256 = "a357566dc7c451cf38e94be5fa4927b229807ef047d2f8d5fa8fc98bcb32ce8a"
DRIVER_PATH = HERE / "linux_retained_driver_v4.py"
DRIVER_SHA256 = "9a3f8dadbd1e013b5d663a72433c133cb12eede277ef677f04b620fab34d832d"
DERIVED_STDIN_SHA256 = "f55ed658e99452649745bc06b3f02cc4a4c46f3c8b4873076848bdbc4a2b9219"


def _load_v3():
    if hashlib.sha256(V3_PATH.read_bytes()).hexdigest() != V3_SHA256:
        raise RuntimeError("Linux replay wrapper v3 SHA-256 differs")
    if hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest() != DRIVER_SHA256:
        raise RuntimeError("Linux retained-driver v4 SHA-256 differs")
    module = predecessor._load_v2()
    module.linux_retained_driver = linux_retained_driver_v4
    module.DRIVER_ADAPTER_PATH = DRIVER_PATH
    module.DRIVER_ADAPTER_SHA256 = DRIVER_SHA256
    module.DERIVED_STDIN_SHA256 = DERIVED_STDIN_SHA256
    return module


def load_wrapper():
    """Keep replay disabled until separately approved Phase A v7 evidence."""
    wrapper, authority = _load_v3().load_wrapper()
    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v3 authority is not installed"))
    return wrapper, authority


def preflight() -> dict[str, object]:
    result = _load_v3().preflight()
    result.update({"driver_adapter_sha256": DRIVER_SHA256, "derived_stdin_sha256": DERIVED_STDIN_SHA256,
                   "phase_a_v7_required": True, "execution_enabled": False})
    return result


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
