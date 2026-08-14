#!/usr/bin/env python3
"""Public-contract tests for the final Linux publication adapter."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PATH = HERE / "linux_publication_compat.py"


LOAD_COUNT = 0


def load():
    global LOAD_COUNT
    LOAD_COUNT += 1
    spec = importlib.util.spec_from_file_location(f"issue397_publication_compat_test_{LOAD_COUNT}", PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LinuxPublicationCompatTests(unittest.TestCase):
    def test_real_v11_publication_contract(self) -> None:
        module = load()
        authority = module.load_authority()
        self.assertEqual(module.load().authority_root, "/tmp/hermternal-397-integrate/handover/issue-397/task464-candidate5-linux-v3-root-shape-final")
        evidence = module.load_phase_a_evidence(
            module.ANCHOR_PATH, module.ANCHOR_SHA256
        )
        self.assertEqual(module.RESULT_SCHEMA, "task409-execution-preflight/replay-result/v2")
        self.assertEqual(module.COMPLETION_SCHEMA, "hermternal.issue-397.replay-completion/v2")
        self.assertEqual(module.STDERR_POLICY, "exact-known-clone-init-notices")
        self.assertEqual(authority.base_commit, "729f2613af2b78d58b07918478e9102d5716f367")
        self.assertEqual(authority.source_commit, "d3c40687659ee645a5f03bc80cbf61ec8c49979a")
        self.assertIsInstance(authority.required_ancestors, list)
        self.assertEqual(authority.required_ancestors, ["729f2613af2b78d58b07918478e9102d5716f367"])
        self.assertIsInstance(authority.forbidden_ancestors, list)
        self.assertEqual(authority.forbidden_ancestors[:2], ["13df3d058f1d14ca07b199a45c5b01cb4bf7b020", "f87ce048b5afc4fad7ac361baa589d47745b580b"])
        self.assertEqual(authority.forbidden_ancestors[-1], "027806c8596f8b9a4ce200b2fe1344e013f46685")
        self.assertEqual(len(authority.forbidden_ancestors), 22)
        self.assertEqual(evidence.manifest_sha256, "c83846f231f0b9b4c2d614a42da56984d75356bcf01a5e00fa221be3bc39c1a3")
        self.assertEqual(module.EVIDENCE_SCHEMA, "hermternal.issue-397.phase-a-anchor-evidence.v11")

    def test_wrong_hash_and_old_v2_anchor_reject(self) -> None:
        module = load()
        with self.assertRaises(module.Reject):
            module.load_phase_a_evidence(module.ANCHOR_PATH, "0" * 64)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / "anchor.json"
            path.write_text(json.dumps({"schema": "hermternal.issue-397.phase-a-anchor-evidence.v2"}) + "\n")
            path.chmod(0o600)
            with self.assertRaises(module.Reject):
                module.load_phase_a_evidence(path, module._digest(path.read_bytes()))
        original = module.AUTHORITY_HASHES["candidate-five.json"]
        module.AUTHORITY_HASHES["candidate-five.json"] = "0" * 64
        try:
            with self.assertRaises(module.Reject):
                module.load_authority()
        finally:
            module.AUTHORITY_HASHES["candidate-five.json"] = original

    def test_preloaded_schema_cache_rejects(self) -> None:
        code = (
            "import importlib.util,sys,types;"
            "sys.modules['poison_test.issue397_publication_schema_base']=types.ModuleType('poison');"
            f"p={str(PATH)!r};s=importlib.util.spec_from_file_location('poison_test',p);"
            "m=importlib.util.module_from_spec(s);sys.modules['poison_test']=m;s.loader.exec_module(m)"
        )
        result = subprocess.run((sys.executable, "-I", "-B", "-c", code), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"cache", result.stderr)

    def test_repeated_same_role_load_leaves_no_synthetic_cache(self) -> None:
        role = "issue397_publication_same_role"
        synthetic = role + ".issue397_publication_schema_base"
        self.assertNotIn(synthetic, sys.modules)
        for _ in range(2):
            spec = importlib.util.spec_from_file_location(role, PATH)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual(module.RESULT_SCHEMA, "task409-execution-preflight/replay-result/v2")
            self.assertNotIn(synthetic, sys.modules)


if __name__ == "__main__":
    unittest.main()
