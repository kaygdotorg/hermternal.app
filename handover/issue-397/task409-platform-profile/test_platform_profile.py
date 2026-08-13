#!/usr/bin/env python3
"""Offline regression checks for the immutable Linux platform profile."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
sys.path.insert(0, os.fspath(HERE))

import linux_replay_wrapper
import linux_retained_driver
import platform_profile
import platform_successor


class PlatformProfileTests(unittest.TestCase):
    def test_profile_binds_current_host_and_is_immutable(self) -> None:
        profile = platform_profile.load()
        self.assertTrue(profile.tools["python3"].path.startswith("/"))
        self.assertTrue(profile.source_repository.startswith("/"))
        with self.assertRaises(TypeError):
            profile.tools["python3"] = profile.tools["python3"]  # type: ignore[index]

    def test_duplicate_key_and_host_drift_reject(self) -> None:
        value = json.loads(platform_profile.PROFILE_PATH.read_text())
        value["tools"]["python3"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / "profile.json"
            path.write_text(json.dumps(value, separators=(",", ":")) + "\n")
            with self.assertRaises(platform_profile.Reject):
                platform_profile.load(path, verify_host=True)
            duplicate = Path(parent) / "duplicate.json"
            duplicate.write_text('{"schema":"x","schema":"y"}\n')
            with self.assertRaises(platform_profile.Reject):
                platform_profile.load(duplicate, verify_host=False)

    def test_generation_is_deterministic_and_profile_limited(self) -> None:
        with tempfile.TemporaryDirectory() as left_parent, tempfile.TemporaryDirectory() as right_parent:
            left_root, right_root = Path(left_parent) / "final", Path(right_parent) / "final"
            left_root.mkdir(mode=0o700); right_root.mkdir(mode=0o700)
            left = platform_successor.generate(left_root)
            right = platform_successor.generate(right_root)
            # A normalized JSON identity must ignore all dependent self-hashes.
            for generated in (left, right):
                document = json.loads(generated.payloads["json"])
                declared = document["execution_driver"]["matrix_identity"]["expected_normalized_sha256"]
                authority = platform_successor.load_approved()[2]
                self.assertEqual(authority.normalized_json_sha256(generated.payloads["json"], declared), declared)
            profile = platform_profile.load()
            self.assertEqual(dict(left.translation_counts), {profile.predecessor_bindings["python3"]: 2, profile.predecessor_bindings["source_repository"]: 3, profile.predecessor_bindings["temporary_parent"]: 35})

    def test_semantic_diff_is_only_declared_platform_bindings(self) -> None:
        orchestrator, _, _ = platform_successor.load_approved()
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "final"; root.mkdir(mode=0o700)
            old = json.loads(orchestrator.generate_in_memory(root).payloads["json"])
            new = json.loads(platform_successor.generate(root).payloads["json"])

        ignored = {"expected_normalized_sha256", "shell_sha256", "driver_shell_sha256", "expected_body_sha256", "expected_body_bytes", "expected_body_lines", "body_bytes", "body_lines"}
        def normalize(value):
            profile = platform_profile.load()
            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items() if key not in ignored}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            if isinstance(value, str):
                value = value.replace(profile.tools["python3"].path, "<PYTHON>").replace(profile.predecessor_bindings["python3"], "<PYTHON>").replace(profile.source_repository, "<SOURCE>").replace(profile.predecessor_bindings["source_repository"], "<SOURCE>").replace(profile.predecessor_bindings["temporary_parent"], "<TEMP>").replace(profile.temporary_parent, "<TEMP>")
                return re.sub(r"(?<=[`'=\" ])[0-9a-f]{64}(?=[`'\"\n ])", "<DERIVED_SHA256>", value)
            return value
        def collect(value, output):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key not in ignored:
                        collect(item, output)
            elif isinstance(value, list):
                for item in value: collect(item, output)
            elif isinstance(value, str) and any(token in value for token in (*platform_profile.load().predecessor_bindings.values(), platform_profile.load().tools["python3"].path, platform_profile.load().source_repository, platform_profile.load().temporary_parent)):
                output.append(value)
        old_platform, new_platform = [], []
        collect(old, old_platform); collect(new, new_platform)
        self.assertEqual([normalize(item) for item in old_platform], [normalize(item) for item in new_platform])
        self.assertEqual(old["ordered_lanes"], new["ordered_lanes"])
        self.assertEqual(old["base"], new["base"])
        self.assertEqual(old["forbidden_ancestry"], new["forbidden_ancestry"])

    def test_final_set_and_wrapper_pins(self) -> None:
        self.assertEqual({path.name for path in platform_successor.FINAL_ROOT.iterdir()}, set(platform_successor.NAMES))
        for name, digest in linux_retained_driver.HASHES.items():
            self.assertEqual(hashlib.sha256((platform_successor.FINAL_ROOT / name).read_bytes()).hexdigest(), digest)
        result = linux_replay_wrapper.preflight()
        self.assertTrue(result["phase_a_v3_required"])
        self.assertFalse(result["replay_run"])

    def test_successor_sources_have_no_undeclared_host_literals(self) -> None:
        allowed = {"platform_profile.py"}
        profile = platform_profile.load()
        needles = (*profile.predecessor_bindings.values(), profile.source_repository, profile.tools["python3"].path, profile.temporary_parent)
        for path in HERE.glob("*.py"):
            text = path.read_text()
            for needle in needles:
                if needle in text:
                    self.assertIn(path.name, allowed, f"undeclared platform literal in {path.name}: {needle}")

    def test_generated_shell_has_valid_bash_and_python_heredocs(self) -> None:
        contract = linux_retained_driver.derive_contract()
        result = subprocess.run(["/bin/bash", "-n"], input=contract.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        driver = linux_retained_driver.load_driver()
        driver.compile_derived(contract.stdin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
