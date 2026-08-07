#!/usr/bin/env python3
"""Regression tests for immutable aggregate fixture authority verification.

The tests use only synthetic local copies. They do not create commits, fetch
remotes, contact Hermes, read credentials, or claim live compatibility. The
checkout copy is deliberately separate from the real Git object database so a
coordinated local rewrite cannot manufacture a replacement authority.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_fixture_registry_authority.py"
AUTHORITY_FILE = ROOT / "scripts" / "fixture_registry_authority.json"

spec = importlib.util.spec_from_file_location("verify_fixture_registry_authority", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


class FixtureRegistryAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority: dict[str, Any] = json.loads(AUTHORITY_FILE.read_text(encoding="utf-8"))
        cls.checkout_paths = (verifier.AUTHORITY_PATH, *verifier.EXPECTED_ARTIFACT_PATHS)

    def run_cli(self, checkout_root: Path, *, optimized: bool) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(
            [
                str(SCRIPT),
                "--repo-root",
                str(ROOT),
                "--checkout-root",
                str(checkout_root),
            ]
        )
        return subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def copy_checkout(self) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-")
        checkout = Path(temporary.name)
        for relative_path in self.checkout_paths:
            source = ROOT / relative_path
            destination = checkout / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        return temporary

    @staticmethod
    def assert_success(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        if completed.returncode != 0:
            raise AssertionError(completed.stderr or completed.stdout)
        if completed.stderr != "":
            raise AssertionError(completed.stderr)
        if completed.stdout.count("\n") != 1:
            raise AssertionError(completed.stdout)
        payload = json.loads(completed.stdout)
        if payload.get("ok") is not True or payload.get("live_claim") is not False:
            raise AssertionError(payload)
        return payload

    @staticmethod
    def assert_bounded_failure(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        if completed.returncode == 0:
            raise AssertionError(completed.stdout)
        if completed.stderr != "":
            raise AssertionError(completed.stderr)
        if completed.stdout.count("\n") != 1:
            raise AssertionError(completed.stdout)
        payload = json.loads(completed.stdout)
        if payload != {
            "error": {
                "code": "fixture_registry_authority_invalid",
                "message": "fixture registry authority rejected",
            },
            "live_claim": False,
            "ok": False,
        }:
            raise AssertionError(payload)
        for forbidden in (str(ROOT), "--checkout-root", "Traceback", "source_commit"):
            if forbidden in completed.stdout:
                raise AssertionError(completed.stdout)
        return payload

    def test_normal_and_optimized_success_are_identical(self) -> None:
        normal = self.run_cli(ROOT, optimized=False)
        optimized = self.run_cli(ROOT, optimized=True)
        self.assertEqual(normal.stdout, optimized.stdout)
        normal_payload = self.assert_success(normal)
        self.assertEqual(normal_payload["stage"], "bootstrap_predecessor")
        self.assertEqual(normal_payload["artifact_count"], 4)
        self.assertNotEqual(normal_payload["authority_commit"], normal_payload["source_commit"])
        self.assertEqual(normal_payload["source_commit"], self.authority["source_commit"])

    def test_authority_relationship_is_external_and_exact(self) -> None:
        trusted = verifier.load_trusted_authority(ROOT)
        authority_commit = trusted["authority_commit"]
        source_commit = trusted["source_commit"]
        self.assertNotEqual(authority_commit, source_commit)
        subprocess.run(
            ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", source_commit, authority_commit],
            check=True,
            capture_output=True,
        )
        self.assertEqual(authority_commit, "8dad73e6da3922d1caa9f37c2a74d8b28e9a32bc")
        self.assertEqual(source_commit, "abb6754bddd1cf18927b0172ed9fa3456235b035")
        for record in trusted["artifact_manifest"]:
            object_bytes = subprocess.check_output(
                ["git", "-C", str(ROOT), "show", f"{source_commit}:{record['path']}"],
            )
            blob_oid = subprocess.check_output(
                ["git", "-C", str(ROOT), "rev-parse", f"{source_commit}:{record['path']}"],
                text=True,
            ).strip()
            self.assertEqual(blob_oid, record["blob_oid"])
            self.assertEqual(len(object_bytes), record["size_bytes"])
            self.assertEqual(hashlib.sha256(object_bytes).hexdigest(), record["sha256"])

    def test_checkout_only_authority_rewrite_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            authority_path = checkout / verifier.AUTHORITY_PATH
            authority_path.write_bytes(authority_path.read_bytes() + b"\n")
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_checkout_only_registry_rewrite_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            index_path = checkout / "contracts/fixtures/index.json"
            index_path.write_bytes(index_path.read_bytes() + b"\n")
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_coordinated_local_rewrites_cannot_replace_git_authority(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            for relative_path in self.checkout_paths:
                target = checkout / relative_path
                target.write_bytes(target.read_bytes() + b"\n# local rewrite\n")
            self.assertFalse((checkout / ".git").exists())
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_unknown_cli_arguments_are_bounded(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--unknown-flag"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assert_bounded_failure(completed)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
