#!/usr/bin/env python3
"""Keep replay disabled while it authenticates local object preservation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import linux_replay_wrapper_v6 as predecessor
import linux_retained_driver_v7

HERE = Path(__file__).resolve().parent
V6_PATH = HERE / "linux_replay_wrapper_v6.py"
V6_SHA256 = "c8887fd0449ad6af3cfdebb721cf14ef9c91840f4d9b35e53f47b150f9821331"
DRIVER_PATH = HERE / "linux_retained_driver_v7.py"
DRIVER_SHA256 = "8194a315b31c78bac6c7ff80077131f3b9975e786b626fb229daed94bbf76684"
DERIVED_STDIN_SHA256 = "66fe55b02f4c60c37fd23b63321f183248c2f94148c039caed35bacae49ed991"


def _load_v6():
    if hashlib.sha256(V6_PATH.read_bytes()).hexdigest() != V6_SHA256:
        raise RuntimeError("Linux replay wrapper v6 SHA-256 differs")
    if hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest() != DRIVER_SHA256:
        raise RuntimeError("Linux retained-driver v7 SHA-256 differs")
    module = predecessor._load_v5()
    module.linux_retained_driver = linux_retained_driver_v7
    module.DRIVER_ADAPTER_PATH = DRIVER_PATH
    module.DRIVER_ADAPTER_SHA256 = DRIVER_SHA256
    module.DERIVED_STDIN_SHA256 = DERIVED_STDIN_SHA256
    return module


def load_wrapper():
    """Do not authorize replay until approved Phase A v11 evidence exists."""
    wrapper, authority = _load_v6().load_wrapper()
    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("Phase A v11 authority is not installed")
    )
    return wrapper, authority


def preflight() -> dict[str, object]:
    result = _load_v6().preflight()
    result.pop("phase_a_v10_required", None)
    result.update({
        "driver_adapter_sha256": DRIVER_SHA256,
        "derived_stdin_sha256": DERIVED_STDIN_SHA256,
        "phase_a_v11_required": True,
        "execution_enabled": False,
    })
    return result


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
