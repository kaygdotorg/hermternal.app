#!/usr/bin/env python3
"""Regressions for the successor Phase B lifecycle validator."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("phase_b_lifecycle_successor", HERE / "phase_b_lifecycle_successor.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load lifecycle successor")
MODULE = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="issue397-phase-b-")
        self.root = Path(self.temp.name).resolve()
        self.shell = b"#!/bin/bash\nprintf '%s\\n' offline\n"
        self.shell_sha = hashlib.sha256(self.shell).hexdigest()
        token = "0" * 64
        while True:
            document = {"schema": "test-triad/v1", "shell_sha256": self.shell_sha, "driver_shell_sha256": self.shell_sha, "expected_body_sha256": self.shell_sha, "normalized_json_sha256": token}
            raw = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
            computed = MODULE.normalized_json_sha256(raw, token)
            if computed == token:
                break
            token = computed
        self.json_raw = raw
        self.markdown = b"# Candidate five fixture\n\n```bash\n" + self.shell + b"```\n"
        self.paths = {"markdown": self.root / "candidate-five.md", "json": self.root / "candidate-five.json", "shell": self.root / "candidate-five.sh"}
        for role, raw_value in (("markdown", self.markdown), ("json", self.json_raw), ("shell", self.shell)):
            self.paths[role].write_bytes(raw_value)
            self.paths[role].chmod(0o600)
        self.normalized = token
        self.descriptor_path = self.root / "triad-descriptor.json"
        self._write_descriptor()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _descriptor(self) -> dict:
        return {"schema": MODULE.SCHEMA, "artifacts": [{"role": role, "path": str(self.paths[role]), "sha256": hashlib.sha256(self.paths[role].read_bytes()).hexdigest()} for role in MODULE.ROLES], "normalized_json_sha256": self.normalized}

    def _write_descriptor(self, value=None) -> str:
        raw = (json.dumps(value or self._descriptor(), sort_keys=True, indent=2) + "\n").encode()
        self.descriptor_path.write_bytes(raw)
        self.descriptor_path.chmod(0o600)
        self.descriptor_sha = hashlib.sha256(raw).hexdigest()
        return self.descriptor_sha

    @staticmethod
    def _observe_git() -> dict[str, str]:
        return {"final_head": "a" * 40, "parent": "b" * 40, "tree": "c" * 40}

    def test_genuine_phase_a_anchor_phase_b_calls_exactly_one_plus_one(self) -> None:
        calls = 0
        original = MODULE.validate_phase_a
        def counted(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)
        MODULE.validate_phase_a = counted
        try:
            anchor, first = MODULE.provision_anchor(self.descriptor_path, self.descriptor_sha)
            observed, second = MODULE.validate_phase_b(self.descriptor_path, self.descriptor_sha, anchor, self._observe_git)
        finally:
            MODULE.validate_phase_a = original
        self.assertEqual(calls, 2)  # exactly one anchor call plus one Phase B call
        self.assertEqual(first.approval_digest, second.approval_digest)
        self.assertEqual(observed["final_head"], "a" * 40)

    def test_path_substitution_and_duplicate_paths_reject(self) -> None:
        for mutation in ("substitute", "duplicate"):
            descriptor = self._descriptor()
            if mutation == "substitute":
                descriptor["artifacts"][0]["path"] = str(self.root / "missing.md")
            else:
                descriptor["artifacts"][1]["path"] = descriptor["artifacts"][0]["path"]
                descriptor["artifacts"][1]["sha256"] = descriptor["artifacts"][0]["sha256"]
            digest = self._write_descriptor(descriptor)
            with self.assertRaises((MODULE.Reject, FileNotFoundError)):
                MODULE.provision_anchor(self.descriptor_path, digest)

    def test_role_cardinality_and_hash_substitution_reject(self) -> None:
        mutations = []
        duplicate_role = self._descriptor()
        duplicate_role["artifacts"][1]["role"] = "markdown"
        mutations.append(duplicate_role)
        extra_role = self._descriptor()
        extra_role["artifacts"].append(dict(extra_role["artifacts"][2]))
        mutations.append(extra_role)
        false_hash = self._descriptor()
        false_hash["artifacts"][2]["sha256"] = "f" * 64
        mutations.append(false_hash)
        for descriptor in mutations:
            digest = self._write_descriptor(descriptor)
            with self.assertRaises(MODULE.Reject):
                MODULE.provision_anchor(self.descriptor_path, digest)

    def test_false_normalized_digest_rejects(self) -> None:
        descriptor = self._descriptor()
        descriptor["normalized_json_sha256"] = "f" * 64
        digest = self._write_descriptor(descriptor)
        with self.assertRaisesRegex(MODULE.Reject, "normalized"):
            MODULE.provision_anchor(self.descriptor_path, digest)

    def test_bypass_sentinels_reject_before_git(self) -> None:
        called = False
        def forbidden_git():
            nonlocal called
            called = True
            return self._observe_git()
        anchor, _ = MODULE.provision_anchor(self.descriptor_path, self.descriptor_sha)
        forged = json.loads(anchor)
        forged["phase_a_approval_digest"] = "f" * 64
        forged_raw = (json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self.assertRaisesRegex(MODULE.Reject, "anchor authority"):
            MODULE.validate_phase_b(self.descriptor_path, self.descriptor_sha, forged_raw, forbidden_git)
        self.assertFalse(called)
        with self.assertRaisesRegex(MODULE.Reject, "descriptor SHA"):
            MODULE.validate_phase_b(self.descriptor_path, "f" * 64, anchor, forbidden_git)
        self.assertFalse(called)

    def test_artifact_swap_during_git_observation_rejects_final_stable_read(self) -> None:
        anchor, _ = MODULE.provision_anchor(self.descriptor_path, self.descriptor_sha)
        original = self.paths["shell"]
        moved = self.root / "verified-shell"
        replacement = self.root / "replacement-shell"

        def swap_then_observe():
            replacement.write_bytes(b"#!/bin/bash\nprintf 'replacement\\n'\n")
            replacement.chmod(0o600)
            os.rename(original, moved)
            os.rename(replacement, original)
            return self._observe_git()

        with self.assertRaisesRegex(MODULE.Reject, "shell authority changed"):
            MODULE.validate_phase_b(self.descriptor_path, self.descriptor_sha, anchor, swap_then_observe)


if __name__ == "__main__":
    unittest.main(verbosity=2)
