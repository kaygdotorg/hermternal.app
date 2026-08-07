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
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_fixture_registry_authority.py"
LEGACY_AUTHORITY_FILE = ROOT / "scripts" / "fixture_registry_authority.json"
V2_AUTHORITY_FILE = ROOT / "scripts" / "fixture_registry_authority.v2.json"
LEGACY_AUTHORITY_SHA256 = "3792ee51370ec6b5cf7257d8473f71c7e810e03c7216969d079d933033734a14"
LEGACY_AUTHORITY_SIZE = 442

spec = importlib.util.spec_from_file_location("verify_fixture_registry_authority", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


class FixtureRegistryAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority: dict[str, Any] = json.loads(V2_AUTHORITY_FILE.read_text(encoding="utf-8"))
        cls.checkout_paths = (
            verifier.LEGACY_AUTHORITY_PATH,
            verifier.AUTHORITY_PATH,
            *verifier.EXPECTED_ARTIFACT_PATHS,
        )

    def run_cli(
        self,
        checkout_root: Path,
        *,
        optimized: bool,
        object_repo: Path = ROOT,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(
            [
                str(SCRIPT),
                "--repo-root",
                str(object_repo),
                "--checkout-root",
                str(checkout_root),
            ]
        )
        child_environment = os.environ.copy()
        if environment:
            child_environment.update(environment)
        return subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=child_environment,
        )

    def copy_object_repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-object-repo-")
        object_repo = Path(temporary.name) / "repo"
        completed = subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT), str(object_repo)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            temporary.cleanup()
            raise AssertionError(completed.stderr or completed.stdout)
        return temporary, object_repo

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
        self.assertEqual(normal_payload["stage"], "bootstrap_predecessor_v2")
        self.assertEqual(normal_payload["authority_path"], verifier.AUTHORITY_PATH)
        self.assertEqual(normal_payload["schema"], verifier.AUTHORITY_SCHEMA)
        self.assertEqual(normal_payload["artifact_count"], 4)
        self.assertNotEqual(normal_payload["authority_commit"], normal_payload["source_commit"])
        self.assertEqual(normal_payload["source_commit"], self.authority["source_commit"])

    def test_legacy_v1_path_and_fields_remain_readable(self) -> None:
        legacy = verifier.load_legacy_authority(ROOT)
        self.assertEqual(verifier.LEGACY_AUTHORITY_PATH, "scripts/fixture_registry_authority.json")
        self.assertEqual(verifier.LEGACY_AUTHORITY_SCHEMA, "hermternal.fixture-registry-authority.v1")
        self.assertEqual(tuple(legacy.keys()), verifier.LEGACY_AUTHORITY_KEYS)
        self.assertEqual(legacy["validator_path"], verifier.LEGACY_VALIDATOR_PATH)
        self.assertEqual(legacy["baseline_path"], verifier.LEGACY_BASELINE_PATH)
        self.assertEqual(legacy["validator_size_bytes"], 84337)
        self.assertEqual(legacy["baseline_size_bytes"], 2614)
        self.assertEqual(
            legacy["validator_sha256"],
            "2a2f32a42ca1867ab92e5be6180cef0caca71e51c2ccae7a33cb99724ae7bffa",
        )
        self.assertEqual(
            legacy["baseline_sha256"],
            "b1b2d03037854bb8e80d2a084b09977c869d7c0ea466b248971d95c1d782b0e1",
        )
        legacy_bytes = LEGACY_AUTHORITY_FILE.read_bytes()
        self.assertEqual(len(legacy_bytes), LEGACY_AUTHORITY_SIZE)
        self.assertEqual(hashlib.sha256(legacy_bytes).hexdigest(), LEGACY_AUTHORITY_SHA256)
        self.assertNotIn("artifact_manifest", legacy)
        self.assertNotIn("source_commit", legacy)

    def test_v2_path_selection_ignores_legacy_path_rewrites(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            legacy_path = checkout / verifier.LEGACY_AUTHORITY_PATH
            legacy_path.write_bytes(b'{"schema":"hermternal.fixture-registry-authority.v1"}\n')
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_success(normal)
            self.assert_success(optimized)

    def test_v2_path_missing_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            (checkout / verifier.AUTHORITY_PATH).unlink()
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_v2_schema_rewrite_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            authority_path = checkout / verifier.AUTHORITY_PATH
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            authority["schema"] = verifier.LEGACY_AUTHORITY_SCHEMA
            authority_path.write_text(json.dumps(authority, indent=2) + "\\n", encoding="utf-8")
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_git_blob_rejects_non_blob_object_types(self) -> None:
        with mock.patch.object(verifier, "_git", side_effect=(b"a" * 40 + b"\\n", b"tree\\n")):
            with self.assertRaises(verifier.AuthorityError):
                verifier._git_blob(ROOT, "0" * 40, "contracts/fixtures/index.json")

    def test_strict_git_environment_removes_hostile_overrides(self) -> None:
        hostile = {
            "GIT_DIR": "/tmp/hostile-git",
            "GIT_COMMON_DIR": "/tmp/hostile-common",
            "GIT_OBJECT_DIRECTORY": "/tmp/hostile-objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/hostile-alternates",
            "GIT_NAMESPACE": "hostile",
            "GIT_WORK_TREE": "/tmp/hostile-worktree",
            "GIT_INDEX_FILE": "/tmp/hostile-index",
            "GIT_CEILING_DIRECTORIES": "/tmp",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
            "GIT_REPLACE_REF_BASE": "refs/replace-hostile",
            "GIT_PROMISOR_REMOTE": "hostile-promisor",
            "GIT_CONFIG_PARAMETERS": "'core.bare=true'",
            "GIT_NO_REPLACE_OBJECTS": "0",
            "GIT_NO_LAZY_FETCH": "0",
        }
        captured: dict[str, str] = {}
        real_run = verifier.subprocess.run

        def capture_environment(*args: object, **kwargs: object) -> subprocess.CompletedProcess[object]:
            command = args[0] if args else kwargs.get("args")
            if isinstance(command, list) and command and command[0] == "git":
                captured.update(kwargs["env"])
            return real_run(*args, **kwargs)

        with (
            mock.patch.dict(os.environ, hostile, clear=False),
            mock.patch.object(verifier.subprocess, "run", side_effect=capture_environment),
        ):
            self.assertTrue(verifier.verify_checkout(ROOT, ROOT)["ok"])
        self.assertEqual(captured["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(captured["GIT_NO_LAZY_FETCH"], "1")
        for variable in hostile:
            if variable not in {"GIT_NO_REPLACE_OBJECTS", "GIT_NO_LAZY_FETCH"}:
                self.assertNotIn(variable, captured)

    def test_promisor_missing_object_fails_closed_without_fetch(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-promisor-")
        self.addCleanup(temporary.cleanup)
        origin = Path(temporary.name) / "origin"
        client = Path(temporary.name) / "client"
        for repository in (origin, client):
            subprocess.run(["git", "init", "--quiet", str(repository)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "fixture-tests"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.email", "fixture-tests@example.invalid"],
                check=True,
                capture_output=True,
            )
        blob = subprocess.check_output(
            ["git", "-C", str(origin), "hash-object", "-w", "--stdin"],
            input=b"promised object\n",
        ).decode("ascii").strip()
        tree = subprocess.check_output(
            ["git", "-C", str(origin), "mktree"],
            input=f"100644 blob {blob}\tfixture.txt\n".encode("ascii"),
        ).decode("ascii").strip()
        commit = subprocess.check_output(
            ["git", "-C", str(origin), "hash-object", "-t", "commit", "-w", "--stdin"],
            input=(
                f"tree {tree}\n"
                "author fixture-tests <fixture-tests@example.invalid> 0 +0000\n"
                "committer fixture-tests <fixture-tests@example.invalid> 0 +0000\n"
                "\npromisor commit\n"
            ).encode("utf-8"),
        ).decode("ascii").strip()
        for object_type, object_id in (("tree", tree), ("commit", commit)):
            object_bytes = subprocess.check_output(
                ["git", "-C", str(origin), "cat-file", object_type, object_id],
            )
            subprocess.run(
                ["git", "-C", str(client), "hash-object", "-t", object_type, "-w", "--stdin"],
                input=object_bytes,
                check=True,
                capture_output=True,
            )
        subprocess.run(
            ["git", "-C", str(client), "update-ref", "refs/heads/main", commit],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(client), "symbolic-ref", "HEAD", "refs/heads/main"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(client), "remote", "add", "origin", str(origin)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(client), "config", "extensions.partialClone", "origin"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(client), "config", "remote.origin.promisor", "true"],
            check=True,
            capture_output=True,
        )
        with mock.patch.dict(
            os.environ,
            {"GIT_PROMISOR_REMOTE": "origin", "GIT_NO_LAZY_FETCH": "0"},
            clear=False,
        ):
            with self.assertRaises(verifier.AuthorityError):
                verifier._git(client, "cat-file", "blob", blob)
        missing = subprocess.run(
            ["git", "-C", str(client), "cat-file", "-e", blob],
            check=False,
            capture_output=True,
            env=verifier._strict_git_environment(),
        )
        self.assertNotEqual(missing.returncode, 0)

    def test_hostile_git_redirects_replace_refs_and_promisor_are_ignored(self) -> None:
        with self.copy_checkout() as temporary:
            object_temporary, object_repo = self.copy_object_repo()
            self.addCleanup(object_temporary.cleanup)
            checkout = Path(temporary)
            decoy = object_repo.parent / "decoy"
            subprocess.run(
                ["git", "init", "--quiet", str(decoy)],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            authority_commit = subprocess.check_output(
                ["git", "-C", str(object_repo), "rev-parse", "HEAD"],
                text=True,
            ).strip()
            subprocess.run(
                ["git", "-C", str(object_repo), "replace", authority_commit, "0f3a05ff5468fb9a3bd238cf788d746ec383e01a"],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            hostile = {
                "GIT_DIR": str(decoy / ".git"),
                "GIT_COMMON_DIR": str(decoy / ".git"),
                "GIT_OBJECT_DIRECTORY": str(decoy / ".git" / "objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(decoy / ".git" / "objects"),
                "GIT_NAMESPACE": "decoy",
                "GIT_WORK_TREE": str(decoy),
                "GIT_INDEX_FILE": str(decoy / ".git" / "index"),
                "GIT_CEILING_DIRECTORIES": str(object_repo.parent),
                "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
                "GIT_REPLACE_REF_BASE": "refs/replace",
                "GIT_PROMISOR_REMOTE": "hostile-promisor",
                "GIT_NO_REPLACE_OBJECTS": "0",
                "GIT_NO_LAZY_FETCH": "0",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true",
                "GIT_CONFIG_PARAMETERS": "'core.bare=true'",
            }
            normal = self.run_cli(checkout, optimized=False, object_repo=object_repo, environment=hostile)
            optimized = self.run_cli(checkout, optimized=True, object_repo=object_repo, environment=hostile)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_success(normal)
            self.assert_success(optimized)

    def test_checkout_reads_are_bounded_and_reject_parent_symlinks(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            oversized = checkout / "contracts/fixtures/index.json"
            oversized.write_bytes(b"x" * (verifier.MAX_GIT_OUTPUT + 1))
            with self.assertRaises(verifier.AuthorityError):
                verifier._read_checkout_file(checkout, "contracts/fixtures/index.json")

            shutil.rmtree(checkout / "contracts")
            outside = checkout / "outside-fixtures"
            (outside / "fixtures").mkdir(parents=True)
            (outside / "fixtures" / "index.json").write_bytes(b"outside\\n")
            (checkout / "contracts").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(verifier.AuthorityError):
                verifier._read_checkout_file(checkout, "contracts/fixtures/index.json")

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
        self.assertEqual(trusted["authority_path"], verifier.AUTHORITY_PATH)
        self.assertEqual(trusted["schema"], verifier.AUTHORITY_SCHEMA)
        self.assertNotEqual(authority_commit, "8dad73e6da3922d1caa9f37c2a74d8b28e9a32bc")
        self.assertEqual(source_commit, "abb6754bddd1cf18927b0172ed9fa3456235b035")
        introduced = subprocess.check_output(
            [
                "git",
                "-C",
                str(ROOT),
                "log",
                "--format=%H",
                "--diff-filter=A",
                "--first-parent",
                "HEAD",
                "--",
                verifier.AUTHORITY_PATH,
            ],
            text=True,
        ).splitlines()
        self.assertEqual(introduced, [authority_commit])
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
