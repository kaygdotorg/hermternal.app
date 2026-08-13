#!/usr/bin/env python3
"""Bind reviewed #405 to retained-driver v2 and the shared #400 policy."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

import linux_git_config_adapter
import linux_retained_driver_v2

HERE = Path(__file__).resolve().parent
V1_PATH = HERE / "linux_replay_wrapper.py"
V1_SHA256 = "faf4abdb90b1e446270f2b93d50c85f6c25decfeef03696526405e10b33c43aa"
DRIVER_PATH = HERE / "linux_retained_driver_v2.py"
DRIVER_SHA256 = "77f7fc5262b5f4eb3b9eff336ebc50b1ed1a6b46d124f42d91ff444ec0db03be"
GIT_CONFIG_ADAPTER_SHA256 = "fda4eb39c0b60f8f27aee17f6d9f5b755fd519283cb4979e33b0ad998f8d6479"
DERIVED_STDIN_SHA256 = "f73b69b4cb9185fb7a16fc51eee9cc1c7385356ab6008aead23a7f5eb166d08c"


def _load_v1() -> types.ModuleType:
    """Install successor data in one exact approved wrapper module."""
    raw = V1_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V1_SHA256:
        raise RuntimeError("Linux replay wrapper v1 SHA-256 differs")
    if hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest() != DRIVER_SHA256:
        raise RuntimeError("Linux retained-driver v2 SHA-256 differs")
    if hashlib.sha256(Path(linux_git_config_adapter.__file__).read_bytes()).hexdigest() != GIT_CONFIG_ADAPTER_SHA256:
        raise RuntimeError("Linux #400 adapter SHA-256 differs")
    # This validates the shared canonical policy against #400 without changing
    # the reviewed #405 reviewer installation path.
    linux_git_config_adapter.load_successor()
    disabled = b'    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v3 authority is not installed"))\n'
    preserved = b"    wrapper._phase_a_v3_predecessor_execute_and_publish = wrapper.execute_and_publish\n"
    if raw.count(disabled) != 1:
        raise RuntimeError("Linux replay wrapper v1 disabled boundary differs")
    raw = raw.replace(disabled, preserved, 1)
    module = types.ModuleType("issue397_linux_replay_wrapper_v2_base")
    module.__file__ = os.fspath(V1_PATH)
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    module.linux_retained_driver = linux_retained_driver_v2
    module.DRIVER_ADAPTER_PATH = DRIVER_PATH
    module.DRIVER_ADAPTER_SHA256 = DRIVER_SHA256
    module.DERIVED_STDIN_SHA256 = DERIVED_STDIN_SHA256
    return module


def load_wrapper():
    """Return the approved #405 wrapper with v2 authority data installed."""
    wrapper, authority = _load_v1().load_wrapper()
    # Phase A v5 removes only this exact line after its evidence is approved.
    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v3 authority is not installed"))
    return wrapper, authority


def preflight() -> dict[str, object]:
    """Verify all successor bindings without enabling replay."""
    result = _load_v1().preflight()
    result["phase_a_v5_required"] = True
    result["git_config_adapter_sha256"] = GIT_CONFIG_ADAPTER_SHA256
    return result


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
