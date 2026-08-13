#!/usr/bin/env python3
"""Adversarial tests for the speculative candidate-five orchestrator."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("generator_orchestrator", HERE / "generator_orchestrator.py")
assert SPEC and SPEC.loader
ORCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ORCH
SPEC.loader.exec_module(ORCH)


class OrchestratorTests(unittest.TestCase):
    def private_root(self, parent: str) -> Path:
        root = Path(parent) / "output"
        root.mkdir(mode=0o700)
        return root.resolve()

    def test_verified_dependencies_and_git_install(self) -> None:
        snapshots = ORCH.verify_dependencies()
        self.assertIn("task464-inputs/task464-working-input.json", snapshots)
        module = ORCH.install_git_authority()
        self.assertEqual(module.CANONICAL_RECORDS[-1], ("protocol.allow", "never"))

    def test_generation_is_deterministic_and_does_not_publish(self) -> None:
        with tempfile.TemporaryDirectory() as left_parent, tempfile.TemporaryDirectory() as right_parent:
            left = self.private_root(left_parent)
            first = ORCH.generate_in_memory(left)
            second = ORCH.generate_in_memory(left)
            self.assertEqual(first.payloads, second.payloads)
            self.assertFalse(any(left.iterdir()))
            right = self.private_root(right_parent)
            third = ORCH.generate_in_memory(right)
            self.assertNotEqual(first.payloads["json"], third.payloads["json"])
            self.assertEqual(first.payloads["shell"], ORCH.json.loads(first.payloads["json"])["execution_driver"]["shell"].encode())
            authority = ORCH.verified_module(ORCH.AUTHORITY, ORCH.EXPECTED[ORCH.AUTHORITY], "generation_authority")
            self.assertEqual(authority.extract_shell(first.payloads["markdown"]), first.payloads["shell"])
            self.assertIn(b"<!-- candidate-five non-authority fence boundary -->", first.payloads["markdown"])

    def test_descriptor_is_distinct_from_closed_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            generated = ORCH.generate_in_memory(root)
            authority = ORCH.verified_module(ORCH.AUTHORITY, ORCH.EXPECTED[ORCH.AUTHORITY], "test_authority")
            descriptor = ORCH.descriptor_bytes(generated, authority)
            descriptor_value = json.loads(descriptor)
            self.assertEqual(set(descriptor_value), {"schema", "roles", "normalized_json_sha256"})
            facts = {"generation": {}, "repository_boundary": {}, "dependencies": [], "source_inputs": [], "publication": {}, "safety_claims": {}}
            provenance = ORCH.provenance_bytes(generated, facts)
            self.assertEqual(set(json.loads(provenance)), ORCH.PROVENANCE_KEYS)
            self.assertNotEqual(descriptor, provenance)

    def test_partial_set_is_never_authority(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            (root / "candidate-five.md").write_bytes(b"partial\n")
            os.chmod(root / "candidate-five.md", 0o600)
            with self.assertRaisesRegex(ORCH.Reject, "incomplete"):
                ORCH.inspect_complete(root, "0" * 64, "0" * 64)

    def test_hash_substitution_fails_closed(self) -> None:
        bad = dict(ORCH.EXPECTED); bad[ORCH.INPUT_JSON] = "0" * 64
        with mock.patch.object(ORCH, "EXPECTED", bad), self.assertRaisesRegex(ORCH.Reject, "SHA-256"):
            ORCH.verify_dependencies()

    @staticmethod
    def compatible_publication(doc: str) -> types.ModuleType:
        module = types.ModuleType("test_publication")
        module.__doc__ = doc
        def publish(targets, payloads, *, validate=None):
            for target, payload in zip(targets, payloads):
                with open(target, "xb") as stream:
                    stream.write(payload); stream.flush(); os.fsync(stream.fileno())
                os.chmod(target, 0o600)
            return validate(tuple(targets), tuple(payloads))
        module.publish = publish
        return module

    def test_behavior_not_source_format_decides_compatibility(self) -> None:
        # Different source-format metadata cannot change the decision. Both
        # modules must pass the same genuine #401 behavioral boundary.
        for doc in ("old compact formatting", "new reformatted source\nwith comments"):
            with self.subTest(doc=doc), tempfile.TemporaryDirectory() as parent:
                root = self.private_root(parent)
                generated = ORCH.generate_in_memory(root)
                authority = ORCH.verified_module(ORCH.AUTHORITY, ORCH.EXPECTED[ORCH.AUTHORITY], "behavior_authority_" + str(len(doc)))
                result = ORCH.behavioral_publication_check(self.compatible_publication(doc), generated, authority)
                self.assertEqual(result.stdin, generated.payloads["shell"])

    def test_behavior_rejects_two_link_callback(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent); generated = ORCH.generate_in_memory(root)
            authority = ORCH.verified_module(ORCH.AUTHORITY, ORCH.EXPECTED[ORCH.AUTHORITY], "two_link_authority")
            module = types.ModuleType("two_link_publication")
            def publish(targets, payloads, *, validate=None):
                stage = root / "stage"; stage.mkdir(mode=0o700)
                for target, payload in zip(targets, payloads):
                    source = stage / target.name; source.write_bytes(payload); os.chmod(source, 0o600); os.link(source, target)
                return validate(tuple(targets), tuple(payloads))
            module.publish = publish
            with self.assertRaisesRegex(Exception, "single-link"):
                ORCH.behavioral_publication_check(module, generated, authority)


if __name__ == "__main__":
    unittest.main(verbosity=2)
