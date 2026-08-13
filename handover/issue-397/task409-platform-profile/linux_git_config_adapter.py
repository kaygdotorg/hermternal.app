#!/usr/bin/env python3
"""Bind the shared Linux policy to the frozen #400 reviewer successor."""
from __future__ import annotations

import hashlib
import os
import sys
import types
from pathlib import Path

import git_config_policy

BASE = Path(__file__).resolve().parents[1]
SUCCESSOR_PATH = BASE / "task464-candidate5-git-config-successor" / "candidate5_git_config_successor.py"
SUCCESSOR_SHA256 = "b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a"
POLICY_SHA256 = "ecc9c1e8e3b98a989c19b15b4c9c8bce535d97a02d5c31b79d227785d7f057fa"


def load_successor() -> types.ModuleType:
    """Compile only the authenticated frozen #400 successor bytes."""
    policy_raw = Path(git_config_policy.__file__).read_bytes()
    if hashlib.sha256(policy_raw).hexdigest() != POLICY_SHA256:
        raise RuntimeError("shared Git config policy SHA-256 differs")
    raw = SUCCESSOR_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SUCCESSOR_SHA256:
        raise RuntimeError("frozen #400 successor SHA-256 differs")
    module = types.ModuleType("issue397_linux_git_config_base")
    module.__file__ = os.fspath(SUCCESSOR_PATH)
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    git_config_policy.validate_git_successor_contract(module)
    return module


def install_successor():
    """Return #400 only after it agrees with the shared canonical policy."""
    return load_successor().install_successor()
