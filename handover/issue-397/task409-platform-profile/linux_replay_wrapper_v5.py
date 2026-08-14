#!/usr/bin/env python3
"""Keep replay disabled while it authenticates the parent-binding driver."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import linux_replay_wrapper_v4 as predecessor
import linux_retained_driver_v5

HERE = Path(__file__).resolve().parent
V4_PATH = HERE / "linux_replay_wrapper_v4.py"
V4_SHA256 = "cdc91d0761ba78afa53d8de5a0857b5b8e0851d5880b9e249945aa29ae63eb85"
DRIVER_PATH = HERE / "linux_retained_driver_v5.py"
DRIVER_SHA256 = "0510d5f7ff5e011cb1875378ede3649222c8383ecb702978af8d791a408400e7"
DERIVED_STDIN_SHA256 = "df9a71fafdf1263e032644180b5211c4dd70771c624461e2e6a3a2b1e89d911c"


def _load_v4():
    if hashlib.sha256(V4_PATH.read_bytes()).hexdigest() != V4_SHA256:
        raise RuntimeError("Linux replay wrapper v4 SHA-256 differs")
    if hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest() != DRIVER_SHA256:
        raise RuntimeError("Linux retained-driver v5 SHA-256 differs")
    module = predecessor._load_v3()
    module.linux_retained_driver = linux_retained_driver_v5
    module.DRIVER_ADAPTER_PATH = DRIVER_PATH
    module.DRIVER_ADAPTER_SHA256 = DRIVER_SHA256
    module.DERIVED_STDIN_SHA256 = DERIVED_STDIN_SHA256
    return module


def load_wrapper():
    """Do not authorize replay until separately approved Phase A v8 evidence."""
    wrapper, authority = _load_v4().load_wrapper()
    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v8 authority is not installed"))
    return wrapper, authority


def preflight() -> dict[str, object]:
    result = _load_v4().preflight()
    # This is the current authorization boundary; do not expose v3 as a
    # parallel replay contract merely because its mechanics are inherited.
    result.pop("phase_a_v3_required", None)
    result.update({"driver_adapter_sha256": DRIVER_SHA256, "derived_stdin_sha256": DERIVED_STDIN_SHA256, "phase_a_v8_required": True, "execution_enabled": False})
    return result


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
