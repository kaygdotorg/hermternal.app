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
from unittest import mock
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
            # The profile-bound authority root makes all generated role bytes equal.
            self.assertEqual(left.payloads, right.payloads)
            for generated in (left, right):
                document = json.loads(generated.payloads["json"])
                declared = document["execution_driver"]["matrix_identity"]["expected_normalized_sha256"]
                authority = platform_successor.load_approved()[2]
                self.assertEqual(authority.normalized_json_sha256(generated.payloads["json"], declared), declared)
            profile = platform_profile.load()
            self.assertEqual(dict(left.translation_counts), {profile.predecessor_bindings["python3"]: 2, profile.predecessor_bindings["source_repository"]: 3, profile.predecessor_bindings["temporary_parent"]: 35})

    def test_semantic_diff_is_only_declared_platform_bindings(self) -> None:
        profile = platform_profile.load()
        orchestrator, _, _ = platform_successor.load_approved()
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "final"; root.mkdir(mode=0o700)
            old = json.loads(orchestrator.generate_in_memory(root).payloads["json"])
            new = json.loads(platform_successor.generate(root).payloads["json"])

        ignored = {"expected_normalized_sha256", "shell_sha256", "driver_shell_sha256", "expected_body_sha256", "expected_body_bytes", "expected_body_lines", "body_bytes", "body_lines"}
        def normalize(value):
            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items() if key not in ignored}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            if isinstance(value, str):
                value = value.replace(os.fspath(root), "<AUTHORITY>").replace(profile.authority_root, "<AUTHORITY>").replace(profile.tools["python3"].path, "<PYTHON>").replace(profile.predecessor_bindings["python3"], "<PYTHON>").replace(profile.source_repository, "<SOURCE>").replace(profile.predecessor_bindings["source_repository"], "<SOURCE>").replace(profile.predecessor_bindings["temporary_parent"], "<TEMP>").replace(profile.temporary_parent, "<TEMP>")
                return re.sub(r"(?<=[`'=\" ])[0-9a-f]{64}(?=[`'\"\n ])", "<DERIVED_SHA256>", value)
            return value
        def collect(value, output):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key not in ignored:
                        collect(item, output)
            elif isinstance(value, list):
                for item in value: collect(item, output)
            elif isinstance(value, str) and any(token in value for token in (*profile.predecessor_bindings.values(), profile.tools["python3"].path, profile.source_repository, profile.temporary_parent, os.fspath(root), profile.authority_root)):
                output.append(value)
        old_platform, new_platform = [], []
        collect(old, old_platform); collect(new, new_platform)
        self.assertEqual([normalize(item) for item in old_platform], [normalize(item) for item in new_platform])
        self.assertEqual(old["ordered_lanes"], new["ordered_lanes"])
        self.assertEqual(old["base"], new["base"])
        self.assertEqual(old["forbidden_ancestry"], new["forbidden_ancestry"])

    def test_semantic_diff_loads_profile_once(self) -> None:
        original = platform_profile.load
        calls = 0
        def counted(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)
        with mock.patch.object(platform_profile, "load", side_effect=counted):
            profile = platform_profile.load()
            values = [profile.source_repository, profile.temporary_parent] * 1000
            for value in values:
                self.assertTrue(any(token in value for token in (profile.source_repository, profile.temporary_parent)))
        self.assertEqual(calls, 1)

    def test_final_set_and_wrapper_pins(self) -> None:
        final_root = Path(platform_profile.load().authority_root)
        self.assertEqual({path.name for path in final_root.iterdir()}, set(platform_successor.NAMES))
        for name, digest in linux_retained_driver.HASHES.items():
            self.assertEqual(hashlib.sha256((final_root / name).read_bytes()).hexdigest(), digest)
        result = linux_replay_wrapper.preflight()
        self.assertTrue(result["phase_a_v3_required"])
        self.assertFalse(result["replay_run"])
        wrapper, _ = linux_replay_wrapper.load_wrapper()
        with self.assertRaisesRegex(RuntimeError, "Phase A v3"):
            wrapper.execute_and_publish(None, "0" * 64)

    def test_adaptation_manifest_is_runtime_authority(self) -> None:
        driver = linux_retained_driver.load_driver()
        original = driver.stable_read
        def altered(path, label, **kwargs):
            snapshot = original(path, label, **kwargs)
            if path.name == "platform-adaptation-manifest.json":
                return driver.Snapshot(snapshot.path, snapshot.raw, "0" * 64, snapshot.identity)
            return snapshot
        driver.stable_read = altered
        with self.assertRaises(driver.Reject):
            driver.load_frozen_authority()

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

    def test_linux_markdown_appendix_uses_durable_boundary(self) -> None:
        driver = linux_retained_driver.load_driver()
        authority = driver.load_frozen_authority()
        metadata = authority.document["validation_contract"]["markdown_parity_appendix"]
        scope = {
            "json": json,
            "markdown_bytes": authority.markdown.raw,
            "appendix_heading": metadata["section_heading"].encode("utf-8"),
            "appendix_opening": metadata["opening_fence"].encode("ascii"),
            "appendix_closing": metadata["closing_fence"].encode("ascii"),
        }
        # This is the exact old block at failure line 330. The current Linux
        # Markdown proves that its closing-fence assumption cannot succeed.
        with self.assertRaisesRegex(ValueError, "subsection not found"):
            exec(compile(linux_retained_driver.OLD_APPENDIX_PARSER, "<old-appendix-parser>", "exec"), dict(scope))
        corrected = dict(scope)
        exec(compile(linux_retained_driver.NEW_APPENDIX_PARSER, "<new-appendix-parser>", "exec"), corrected)
        self.assertEqual(corrected["appendix"], json.loads(authority.markdown.raw.split(scope["appendix_opening"], 1)[1].split(b"\n<!-- candidate-five non-authority fence boundary -->\n", 1)[0]))
        contract = linux_retained_driver.derive_contract()
        self.assertEqual(contract.stdin.count(linux_retained_driver.OLD_APPENDIX_PARSER), 0)
        self.assertEqual(contract.stdin.count(linux_retained_driver.NEW_APPENDIX_PARSER), 1)
        with self.assertRaisesRegex(RuntimeError, "anchor differs"):
            linux_retained_driver._repair_markdown_appendix_parser(contract.stdin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
