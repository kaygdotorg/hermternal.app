#!/usr/bin/env python3
"""Test the exact local object-preservation policy in disposable roots."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import linux_retained_driver_v7 as driver
import object_preservation as policy
import platform_profile


class ObjectPreservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = Path(platform_profile.load().source_repository)
        frozen = driver.load_driver().load_frozen_authority()
        cls.authority_path = frozen.json.path
        cls.authority = frozen.document
        cls.record = driver.preservation_record()

    def test_exact_inventory_and_record(self) -> None:
        inventory = policy.typed_inventory(self.authority)
        self.assertEqual(len(inventory), 563)
        self.assertEqual(self.record["typed_counts"], {"blob": 315, "commit": 128, "tree": 120})
        self.assertEqual(len(self.record["independent_roots"]), 11)
        self.assertEqual(len(self.record["present_forbidden"]), 17)
        self.assertEqual(tuple(self.record["missing_proved"]), policy.MISSING_PROVED)

    def test_missing_extra_and_wrong_type_are_rejected(self) -> None:
        def first_blob(document):
            if isinstance(document, dict):
                if "blob" in document:
                    return document
                for value in document.values():
                    found = first_blob(value)
                    if found is not None:
                        return found
            if isinstance(document, list):
                for value in document:
                    found = first_blob(value)
                    if found is not None:
                        return found
            return None

        missing = copy.deepcopy(self.authority)
        del first_blob(missing)["blob"]
        with self.assertRaises(policy.PreservationError):
            policy.typed_inventory(missing)
        extra = copy.deepcopy(self.authority)
        extra["unexpected"] = {"blob": "0000000000000000000000000000000000000000"}
        with self.assertRaises(policy.PreservationError):
            policy.typed_inventory(extra)
        wrong = copy.deepcopy(self.authority)
        first_blob(wrong)["blob"] = self.record["present_forbidden"][0]
        with self.assertRaises(policy.PreservationError):
            policy._validate_repository(self.source, wrong, self.record)

    def test_root_drift_is_rejected(self) -> None:
        inventory = policy.typed_inventory(self.authority)
        types = {**inventory, **{oid: "commit" for oid in self.record["present_forbidden"]},
                 **{oid: "missing" for oid in self.record["missing_proved"]}}
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(policy, "_types", return_value=types), \
             mock.patch.object(policy, "_output", return_value=b"0" * 40 + b"\n"), \
             mock.patch.object(policy, "_run", return_value=success), \
             self.assertRaisesRegex(policy.PreservationError, "roots differ"):
            policy._validate_repository(self.source, self.authority, self.record)

    def test_tamper_and_thin_import_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-import-test.") as raw:
            root = Path(raw)
            repository = root / "repository"
            subprocess.run(["/usr/bin/git", "init", "--bare", os.fspath(repository)], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pack = root / "transfer.pack"
            pack.write_bytes(b"PACK\x00tampered")
            pack.chmod(0o400)
            with self.assertRaisesRegex(policy.PreservationError, "thin"):
                policy.import_pack(repository, pack)
            with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"unresolved delta")) as run:
                with self.assertRaisesRegex(policy.PreservationError, "thin"):
                    policy.import_pack(repository, pack)
                self.assertNotIn("--fix-thin", run.call_args.args[0])

    def test_policy_tamper_is_rejected_before_derived_repair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-policy-test.") as raw:
            tampered = Path(raw) / "object_preservation.py"
            tampered.write_bytes(policy.POLICY_PATH.read_bytes() if hasattr(policy, "POLICY_PATH") else Path(policy.__file__).read_bytes() + b"\n")
            with self.assertRaisesRegex(policy.PreservationError, "policy SHA-256"):
                policy.repair_generated_validator(
                    driver.derive_contract().stdin, self.record,
                    driver.PRESERVATION_RECORD_SHA256, tampered, "0" * 64
                )

    def test_disposable_clone_imports_complete_authority_pack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="issue397-pack-test.") as raw:
            root = Path(raw)
            clean = root / "repository"
            subprocess.run([
                "/usr/bin/git", "-c", "protocol.file.allow=always", "clone", "--no-local",
                "--no-hardlinks", "--no-checkout", "--no-tags", os.fspath(self.source),
                os.fspath(clean),
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = policy.preserve(
                self.source, clean, root, self.authority_path, self.record,
                driver.PRESERVATION_RECORD_SHA256
            )
            self.assertEqual(result["typed_count"], 563)
            self.assertEqual(result["present_forbidden_count"], 17)
            self.assertEqual(result["missing_proved_count"], 5)
            self.assertFalse((root / "authority-transfer.pack").exists())


if __name__ == "__main__":
    unittest.main()
