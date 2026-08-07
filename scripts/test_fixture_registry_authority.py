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
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_fixture_registry_authority.py"
LEGACY_AUTHORITY_FILE = ROOT / "scripts" / "fixture_registry_authority.json"
V2_AUTHORITY_FILE = ROOT / "scripts" / "fixture_registry_authority.v2.final.json"
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
        cls.object_repo_temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-class-repo-")
        cls.object_repo = (Path(cls.object_repo_temporary.name) / "repo").resolve()
        completed = subprocess.run(
            ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT), str(cls.object_repo)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            cls.object_repo_temporary.cleanup()
            raise AssertionError(completed.stderr or completed.stdout)
        cls.addClassCleanup(cls.object_repo_temporary.cleanup)

    def run_cli(
        self,
        checkout_root: Path,
        *,
        optimized: bool,
        object_repo: Path | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        if object_repo is None:
            object_repo = self.object_repo
        try:
            checkout_argument = checkout_root.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            checkout_argument = checkout_root
        try:
            object_argument = object_repo.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            object_argument = object_repo
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(
            [
                str(SCRIPT),
                "--repo-root",
                str(object_argument),
                "--checkout-root",
                str(checkout_argument),
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
            timeout=timeout,
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
            destination = checkout / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            if relative_path in verifier.EXPECTED_ARTIFACT_PATHS:
                data = subprocess.check_output(
                    ["git", "-C", str(self.object_repo), "show", f"{verifier.EXPECTED_SOURCE_COMMIT}:{relative_path}"],
                )
                destination.write_bytes(data)
            else:
                shutil.copyfile(ROOT / relative_path, destination)
        return temporary

    def make_packed_remote_object_repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        """Create a synthetic branch-only remote clone with a real pack over 1 MiB."""

        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-packed-remote-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        bare = root / "origin.git"
        client = root / "client"
        branch = "fixture-authority-test"
        head = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        completed = subprocess.run(
            ["git", "clone", "--bare", "--no-hardlinks", "--quiet", str(ROOT), str(bare)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr or completed.stdout)
        subprocess.run(
            ["git", "--git-dir", str(bare), "update-ref", f"refs/heads/{branch}", head],
            check=True,
            capture_output=True,
        )
        completed = subprocess.run(
            [
                "git",
                "clone",
                "--single-branch",
                "--branch",
                branch,
                "--no-local",
                "--quiet",
                str(bare),
                str(client),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr or completed.stdout)
        pack_files = tuple((client / ".git/objects/pack").glob("*.pack"))
        self.assertTrue(pack_files)
        self.assertGreater(
            max(path.stat().st_size for path in pack_files),
            verifier.MAX_SNAPSHOT_FILE_BYTES,
        )
        return temporary, client

    def assert_pair_failure(
        self,
        checkout: Path,
        *,
        object_repo: Path | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 30,
    ) -> None:
        try:
            normal = self.run_cli(
                checkout,
                optimized=False,
                object_repo=object_repo,
                environment=environment,
                timeout=timeout,
            )
            optimized = self.run_cli(
                checkout,
                optimized=True,
                object_repo=object_repo,
                environment=environment,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            self.fail(f"authority verifier exceeded {timeout}s: {exc}")
        self.assertEqual(normal.stdout, optimized.stdout)
        self.assert_bounded_failure(normal)
        self.assert_bounded_failure(optimized)

    def make_synthetic_authority_repo(
        self,
        *,
        annotated_tag: bool = False,
        grafted_parent: bool = False,
        non_direct_predecessor: bool = False,
    ) -> tuple[Path, Path]:
        """Create a local-only authority history for ancestry/type regressions."""

        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-synthetic-")
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name) / "repo"
        subprocess.run(["git", "init", "--quiet", str(repo)], check=True, capture_output=True)
        for key, value in (
            ("user.name", "fixture-tests"),
            ("user.email", "fixture-tests@example.invalid"),
        ):
            subprocess.run(
                ["git", "-C", str(repo), "config", key, value],
                check=True,
                capture_output=True,
            )
        source_commit = self.authority["source_commit"]
        for relative_path in verifier.EXPECTED_ARTIFACT_PATHS:
            data = subprocess.check_output(
                ["git", "-C", str(self.object_repo), "show", f"{source_commit}:{relative_path}"],
            )
            destination = repo / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        subprocess.run(
            ["git", "-C", str(repo), "add", "--", *verifier.EXPECTED_ARTIFACT_PATHS],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "commit", "--quiet", "-m", "source artifacts"],
            check=True,
            capture_output=True,
        )
        artifact_source_commit = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        source_commit = artifact_source_commit
        if non_direct_predecessor:
            marker = repo / "source-marker"
            marker.write_text("synthetic predecessor marker\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repo), "add", "--", "source-marker"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "commit", "--quiet", "-m", "intermediate predecessor"],
                check=True,
                capture_output=True,
            )
        records: list[dict[str, Any]] = []
        for relative_path in verifier.EXPECTED_ARTIFACT_PATHS:
            data = (repo / relative_path).read_bytes()
            blob_oid = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", f"HEAD:{relative_path}"],
                text=True,
            ).strip()
            records.append(
                {
                    "path": relative_path,
                    "blob_oid": blob_oid,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                }
            )
        authority = dict(self.authority)
        authority["source_commit"] = source_commit
        authority["artifact_manifest"] = records
        if annotated_tag:
            subprocess.run(
                ["git", "-C", str(repo), "tag", "-a", "source-tag", source_commit, "-m", "source tag"],
                check=True,
                capture_output=True,
            )
            authority["source_commit"] = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "refs/tags/source-tag"],
                text=True,
            ).strip()
        authority_path = repo / verifier.AUTHORITY_PATH
        authority_path.parent.mkdir(parents=True, exist_ok=True)
        authority_path.write_text(json.dumps(authority, indent=2) + "\n", encoding="utf-8")
        if grafted_parent:
            subprocess.run(
                ["git", "-C", str(repo), "checkout", "--quiet", "--orphan", "authority"],
                check=True,
                capture_output=True,
            )
            for child in repo.iterdir():
                if child.name != ".git":
                    if child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
            authority_path.parent.mkdir(parents=True, exist_ok=True)
            authority_path.write_text(json.dumps(authority, indent=2) + "\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "add", "--", verifier.AUTHORITY_PATH],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "commit", "--quiet", "-m", "authority"],
            check=True,
            capture_output=True,
        )
        introduction = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        if grafted_parent:
            grafts = repo / ".git/info/grafts"
            grafts.parent.mkdir(parents=True, exist_ok=True)
            grafts.write_text(f"{introduction} {source_commit}\n", encoding="ascii")
            subprocess.run(
                ["git", "-C", str(repo), "config", "advice.graftFileDeprecated", "false"],
                check=True,
                capture_output=True,
            )
        checkout_temporary = self.copy_checkout()
        checkout = Path(checkout_temporary.name)
        (checkout / verifier.AUTHORITY_PATH).write_bytes(authority_path.read_bytes())
        self.addCleanup(checkout_temporary.cleanup)
        return repo, checkout

    def make_oversized_git_helper(self) -> Path:
        """Make a local Git stand-in that blocks after writing over the cap."""

        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-git-output-")
        self.addCleanup(temporary.cleanup)
        helper = Path(temporary.name) / "git-output-helper"
        helper.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "import sys\n"
            "import time\n"
            "\n"
            "mode = next((argument for argument in sys.argv[1:] if argument in {\"stderr\", \"history\", \"log\"}), \"stdout\")\n"
            "file_descriptor = 2 if mode == \"stderr\" else 1\n"
            "payload = b\"x\" * (524 * 1024 + 1)\n"
            "written = 0\n"
            "while written < len(payload):\n"
            "    try:\n"
            "        written += os.write(file_descriptor, payload[written:])\n"
            "    except BrokenPipeError:\n"
            "        raise SystemExit(0)\n"
            "time.sleep(30)\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        return helper

    @staticmethod
    def assert_process_exited(pid_file: Path) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not pid_file.exists():
            time.sleep(0.01)
        if not pid_file.exists():
            raise AssertionError("bounded Git child did not publish its pid")
        pid = int(pid_file.read_text(encoding="ascii"))
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                return
            time.sleep(0.01)
        raise AssertionError(f"bounded Git child {pid} survived cleanup")

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
        # The active checkout may contain corrected scanner bytes that are not
        # part of the historical v2 authority. Reconstruct the reviewed
        # predecessor checkout from its pinned source commit before invoking
        # the standalone verifier.
        with self.copy_checkout() as checkout_temporary:
            checkout = Path(checkout_temporary)
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
        self.assertEqual(normal.stdout, optimized.stdout)
        normal_payload = self.assert_success(normal)
        self.assertEqual(normal_payload["stage"], "aggregate_predecessor_v2")
        self.assertEqual(normal_payload["authority_path"], verifier.AUTHORITY_PATH)
        self.assertEqual(normal_payload["schema"], verifier.AUTHORITY_SCHEMA)
        self.assertEqual(normal_payload["artifact_count"], 4)
        self.assertNotEqual(normal_payload["authority_commit"], normal_payload["source_commit"])
        self.assertEqual(normal_payload["source_commit"], self.authority["source_commit"])

        # A fresh single-branch clone exercises the ordinary remote-packed
        # layout rather than the local object layout used by most regressions.
        _packed_temporary, packed_repo = self.make_packed_remote_object_repo()
        with self.copy_checkout() as checkout_temporary:
            checkout = Path(checkout_temporary)
            packed_normal = self.run_cli(checkout, optimized=False, object_repo=packed_repo)
            packed_optimized = self.run_cli(checkout, optimized=True, object_repo=packed_repo)
        self.assertEqual(packed_normal.stdout, packed_optimized.stdout)
        self.assert_success(packed_normal)
        self.assert_success(packed_optimized)

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

    def test_legacy_v1_same_shape_rewrite_fails_closed(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary)
            path = checkout / verifier.LEGACY_AUTHORITY_PATH
            rewritten = bytearray(path.read_bytes())
            rewritten[-2] = ord(" ") if rewritten[-2] != ord(" ") else ord("\\n")
            self.assertEqual(len(rewritten), verifier.LEGACY_AUTHORITY_SIZE)
            path.write_bytes(bytes(rewritten))
            with self.assertRaises(verifier.AuthorityError):
                verifier.load_legacy_authority(checkout)

    def test_v2_path_selection_ignores_legacy_path_rewrites(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
            legacy_path = checkout / verifier.LEGACY_AUTHORITY_PATH
            legacy_path.write_bytes(b'{"schema":"hermternal.fixture-registry-authority.v1"}\n')
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_success(normal)
            self.assert_success(optimized)

    def test_v2_path_missing_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
            (checkout / verifier.AUTHORITY_PATH).unlink()
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_v2_schema_rewrite_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
            authority_path = checkout / verifier.AUTHORITY_PATH
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            authority["schema"] = verifier.LEGACY_AUTHORITY_SCHEMA
            authority_path.write_text(json.dumps(authority, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(json.loads(authority_path.read_text(encoding="utf-8"))["schema"], verifier.LEGACY_AUTHORITY_SCHEMA)
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_git_blob_rejects_non_blob_object_types(self) -> None:
        with mock.patch.object(verifier, "_git", side_effect=(b"a" * 40 + b"\n", b"tree\n")) as git_mock:
            with self.assertRaises(verifier.AuthorityError):
                verifier._git_blob(ROOT, "0" * 40, "contracts/fixtures/index.json")
        self.assertEqual(git_mock.call_args_list[0].args[1:], ("rev-parse", "0" * 40 + ":contracts/fixtures/index.json"))
        self.assertEqual(git_mock.call_args_list[1].args[1:], ("cat-file", "-t", "a" * 40))

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
        real_popen = verifier.subprocess.Popen

        def capture_environment(*args: object, **kwargs: object) -> Any:
            command = args[0] if args else kwargs.get("args")
            if isinstance(command, list) and command and command[0] == str(verifier.TRUSTED_GIT_EXECUTABLE):
                captured.update(kwargs["env"])
            return real_popen(*args, **kwargs)

        with self.copy_checkout() as checkout_temporary:
            with (
                mock.patch.dict(os.environ, hostile, clear=False),
                mock.patch.object(verifier.subprocess, "Popen", side_effect=capture_environment),
            ):
                self.assertTrue(verifier.verify_checkout(Path(checkout_temporary), self.object_repo)["ok"])
        self.assertEqual(captured["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(captured["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(captured["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(captured["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(captured["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(captured["GIT_CONFIG_COUNT"], "0")
        self.assertEqual(captured["PATH"], verifier.TRUSTED_HELPER_PATH)
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
            checkout = Path(temporary).resolve()
            decoy = checkout.parent / "decoy"
            subprocess.run(
                ["git", "init", "--quiet", str(decoy)],
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
                "GIT_CEILING_DIRECTORIES": str(checkout.parent),
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
            normal = self.run_cli(checkout, optimized=False, environment=hostile)
            optimized = self.run_cli(checkout, optimized=True, environment=hostile)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_success(normal)
            self.assert_success(optimized)

    def test_checkout_reads_are_bounded_and_reject_parent_symlinks(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
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

    def test_ancestor_replacement_after_open_keeps_original_descriptor(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-ancestor-race-")
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name) / "parent"
        original_child = parent / "child"
        original_child.mkdir(parents=True)
        (original_child / "marker").write_text("original\n", encoding="ascii")
        outside = Path(temporary.name) / "outside"
        outside_child = outside / "child"
        outside_child.mkdir(parents=True)
        (outside_child / "marker").write_text("redirected\n", encoding="ascii")
        saved = parent.with_name("parent.saved")
        original_stat = original_child.stat()
        real_open = verifier.os.open
        mutated = False

        def open_and_replace(path: object, flags: int, *args: object, **kwargs: object) -> int:
            nonlocal mutated
            descriptor = real_open(path, flags, *args, **kwargs)
            if path == "parent" and kwargs.get("dir_fd") is not None and not mutated:
                parent.rename(saved)
                parent.symlink_to(outside, target_is_directory=True)
                mutated = True
            return descriptor

        with mock.patch.object(verifier.os, "open", side_effect=open_and_replace):
            descriptor, _ = verifier._open_directory_chain(original_child)
        try:
            self.assertTrue(mutated)
            self.assertEqual(os.fstat(descriptor).st_ino, original_stat.st_ino)
            marker_fd = real_open("marker", os.O_RDONLY, dir_fd=descriptor)
            try:
                self.assertEqual(os.read(marker_fd, 64), b"original\n")
            finally:
                os.close(marker_fd)
        finally:
            os.close(descriptor)

    def test_oversized_blob_output_is_bounded_in_both_modes(self) -> None:
        object_temporary, object_repo = self.copy_object_repo()
        self.addCleanup(object_temporary.cleanup)
        blob_oid = subprocess.check_output(
            ["git", "-C", str(object_repo), "hash-object", "-w", "--stdin"],
            input=b"x" * (verifier.MAX_GIT_OUTPUT + 1),
        ).decode("ascii").strip()
        started = time.monotonic()
        with self.assertRaises(verifier.AuthorityError):
            verifier._git(object_repo, "cat-file", "blob", blob_oid)
        self.assertLess(time.monotonic() - started, 5)

    def test_oversized_snapshot_files_fail_closed_in_both_modes(self) -> None:
        variants = ("pack", "loose", "reflog", "metadata")
        for variant in variants:
            with self.subTest(variant=variant):
                object_temporary, object_repo = self.copy_object_repo()
                self.addCleanup(object_temporary.cleanup)
                git_dir = object_repo / ".git"
                if variant == "pack":
                    target = git_dir / "objects/pack/oversized.pack"
                elif variant == "loose":
                    target = git_dir / "objects/aa/oversized-loose-object"
                elif variant == "reflog":
                    target = git_dir / "logs/refs/heads/oversized"
                else:
                    target = git_dir / "description"
                target.parent.mkdir(parents=True, exist_ok=True)
                limit = (
                    verifier.MAX_SNAPSHOT_PACK_FILE_BYTES
                    if variant == "pack"
                    else verifier.MAX_SNAPSHOT_FILE_BYTES
                )
                target.write_bytes(b"x" * (limit + 1))
                with self.copy_checkout() as checkout_temporary:
                    started = time.monotonic()
                    self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)
                    self.assertLess(time.monotonic() - started, 5)

    def test_aggregate_snapshot_budget_fails_closed_in_both_modes(self) -> None:
        object_temporary, object_repo = self.copy_object_repo()
        self.addCleanup(object_temporary.cleanup)
        budget_files = verifier.MAX_SNAPSHOT_TOTAL_BYTES // verifier.MAX_SNAPSHOT_FILE_BYTES + 1
        for index in range(budget_files):
            (object_repo / ".git" / f"snapshot-budget-{index}").write_bytes(
                b"x" * verifier.MAX_SNAPSHOT_FILE_BYTES
            )
        with self.copy_checkout() as checkout_temporary:
            started = time.monotonic()
            self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)
            self.assertLess(time.monotonic() - started, 5)

    def test_snapshot_deadline_fails_closed(self) -> None:
        object_temporary, object_repo = self.copy_object_repo()
        self.addCleanup(object_temporary.cleanup)
        with (
            mock.patch.object(verifier, "SNAPSHOT_TIMEOUT_SECONDS", 0.5),
            mock.patch.object(verifier.time, "monotonic", side_effect=(0.0, 1.0)),
        ):
            with self.assertRaises(verifier.AuthorityError):
                verifier._snapshot_object_repository(object_repo)

    def test_corrupt_loose_object_under_existing_oid_fails_fsck(self) -> None:
        object_temporary, object_repo = self.copy_object_repo()
        self.addCleanup(object_temporary.cleanup)
        object_oid = subprocess.check_output(
            ["git", "-C", str(object_repo), "hash-object", "-w", "--stdin"],
            input=b"unreachable trusted-object\n",
        ).decode("ascii").strip()
        object_path = object_repo / ".git/objects" / object_oid[:2] / object_oid[2:]
        decoded = zlib.decompress(object_path.read_bytes())
        corrupted = decoded[:-1] + bytes((decoded[-1] ^ 1,))
        object_path.chmod(0o600)
        object_path.write_bytes(zlib.compress(corrupted))
        with self.copy_checkout() as checkout_temporary:
            self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)

    def test_oversized_stderr_is_bounded_without_deadlock(self) -> None:
        helper = self.make_oversized_git_helper()
        started = time.monotonic()
        with mock.patch.object(verifier, "TRUSTED_GIT_EXECUTABLE", helper):
            with self.assertRaises(verifier.AuthorityError):
                verifier._git(self.object_repo, "stderr")
        self.assertLess(time.monotonic() - started, 5)

    def test_oversized_history_output_is_bounded_without_deadlock(self) -> None:
        helper = self.make_oversized_git_helper()
        started = time.monotonic()
        with mock.patch.object(verifier, "TRUSTED_GIT_EXECUTABLE", helper):
            with self.assertRaises(verifier.AuthorityError):
                verifier._authority_introduction_commit(self.object_repo)
        self.assertLess(time.monotonic() - started, 5)

    def test_no_output_timeout_terminates_and_reaps_child(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-timeout-")
        self.addCleanup(temporary.cleanup)
        pid_file = Path(temporary.name) / "pid"
        script = (
            "import os, pathlib, sys, time; "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
            "time.sleep(30)"
        )
        started = time.monotonic()
        with mock.patch.object(verifier, "GIT_TIMEOUT_SECONDS", 0.2):
            with self.assertRaises(verifier.AuthorityError):
                verifier._run_bounded_git(
                    [sys.executable, "-c", script, str(pid_file)],
                    verifier._strict_git_environment(),
                )
        self.assertLess(time.monotonic() - started, 5)
        self.assert_process_exited(pid_file)

    def test_selector_setup_failure_terminates_and_reaps_child(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-selector-setup-")
        self.addCleanup(temporary.cleanup)
        pid_file = Path(temporary.name) / "pid"
        script = (
            "import os, pathlib, sys, time; "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
            "time.sleep(30)"
        )
        def fail_selector() -> Any:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and not pid_file.exists():
                time.sleep(0.01)
            raise RuntimeError("setup")

        with mock.patch.object(verifier.selectors, "DefaultSelector", side_effect=fail_selector):
            with self.assertRaises(verifier.AuthorityError):
                verifier._run_bounded_git(
                    [sys.executable, "-c", script, str(pid_file)],
                    verifier._strict_git_environment(),
                )
        self.assert_process_exited(pid_file)

    def test_descendant_pipe_holder_is_killed_with_child_session(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-descendant-")
        self.addCleanup(temporary.cleanup)
        pid_file = Path(temporary.name) / "descendant-pid"
        script = (
            "import os, pathlib, sys, time\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii')\n"
            "    time.sleep(30)\n"
            "else:\n"
            "    time.sleep(30)\n"
        )
        with mock.patch.object(verifier, "GIT_TIMEOUT_SECONDS", 0.2):
            with self.assertRaises(verifier.AuthorityError):
                verifier._run_bounded_git(
                    [sys.executable, "-c", script, str(pid_file)],
                    verifier._strict_git_environment(),
                )
        self.assert_process_exited(pid_file)

    def test_simultaneous_stdout_and_stderr_saturation_cleans_child(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-dual-output-")
        self.addCleanup(temporary.cleanup)
        pid_file = Path(temporary.name) / "pid"
        script = (
            "import os, pathlib, sys, time; "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
            "chunk=b'x'*65536; "
            "[ (os.write(1, chunk), os.write(2, chunk)) for _ in range(32) ]; "
            "time.sleep(30)"
        )
        started = time.monotonic()
        with self.assertRaises(verifier.AuthorityError):
            verifier._run_bounded_git(
                [sys.executable, "-c", script, str(pid_file)],
                verifier._strict_git_environment(),
            )
        self.assertLess(time.monotonic() - started, 5)
        self.assert_process_exited(pid_file)

    def test_authority_relationship_is_external_and_exact(self) -> None:
        trusted = verifier.load_trusted_authority(self.object_repo)
        authority_commit = trusted["authority_commit"]
        source_commit = trusted["source_commit"]
        self.assertNotEqual(authority_commit, source_commit)
        subprocess.run(
            ["git", "-C", str(self.object_repo), "merge-base", "--is-ancestor", source_commit, authority_commit],
            check=True,
            capture_output=True,
        )
        self.assertEqual(trusted["authority_path"], verifier.AUTHORITY_PATH)
        self.assertEqual(trusted["schema"], verifier.AUTHORITY_SCHEMA)
        self.assertEqual(authority_commit, verifier.EXPECTED_AUTHORITY_COMMIT)
        self.assertEqual(source_commit, verifier.EXPECTED_SOURCE_COMMIT)
        first_parent = subprocess.check_output(
            ["git", "-C", str(self.object_repo), "rev-parse", f"{authority_commit}^1"],
            text=True,
        ).strip()
        self.assertEqual(source_commit, first_parent)
        introduced = subprocess.check_output(
            [
                "git",
                "-C",
                str(self.object_repo),
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
                ["git", "-C", str(self.object_repo), "show", f"{source_commit}:{record['path']}"],
            )
            blob_oid = subprocess.check_output(
                ["git", "-C", str(self.object_repo), "rev-parse", f"{source_commit}:{record['path']}"],
                text=True,
            ).strip()
            self.assertEqual(blob_oid, record["blob_oid"])
            self.assertEqual(len(object_bytes), record["size_bytes"])
            self.assertEqual(hashlib.sha256(object_bytes).hexdigest(), record["sha256"])

    def test_checkout_only_authority_rewrite_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
            authority_path = checkout / verifier.AUTHORITY_PATH
            authority_path.write_bytes(authority_path.read_bytes() + b"\n")
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_checkout_only_registry_rewrite_fails_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
            index_path = checkout / "contracts/fixtures/index.json"
            index_path.write_bytes(index_path.read_bytes() + b"\n")
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_coordinated_local_rewrites_cannot_replace_git_authority(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
            for relative_path in self.checkout_paths:
                target = checkout / relative_path
                target.write_bytes(target.read_bytes() + b"\n# local rewrite\n")
            self.assertFalse((checkout / ".git").exists())
            normal = self.run_cli(checkout, optimized=False)
            optimized = self.run_cli(checkout, optimized=True)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_bounded_failure(normal)
            self.assert_bounded_failure(optimized)

    def test_fifo_checkout_read_exits_bounded_in_both_modes(self) -> None:
        with self.copy_checkout() as temporary:
            checkout = Path(temporary).resolve()
            target = checkout / "contracts/fixtures/index.json"
            target.unlink()
            os.mkfifo(target)
            self.assert_pair_failure(checkout, timeout=5)

    def test_empty_checkout_helper_path_is_fail_closed(self) -> None:
        with self.copy_checkout() as temporary:
            with self.assertRaises(verifier.AuthorityError):
                verifier._read_checkout_file(Path(temporary), ".")

    def test_synthetic_internally_valid_authority_history_fails_external_pins(self) -> None:
        object_repo, checkout = self.make_synthetic_authority_repo()
        synthetic_introduction = subprocess.check_output(
            ["git", "-C", str(object_repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        self.assertNotEqual(synthetic_introduction, verifier.EXPECTED_AUTHORITY_COMMIT)
        self.assert_pair_failure(checkout, object_repo=object_repo)

    def test_source_commit_must_be_direct_authority_predecessor(self) -> None:
        object_repo, checkout = self.make_synthetic_authority_repo(non_direct_predecessor=True)
        authority_commit = subprocess.check_output(
            ["git", "-C", str(object_repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        first_parent = subprocess.check_output(
            ["git", "-C", str(object_repo), "rev-parse", f"{authority_commit}^1"],
            text=True,
        ).strip()
        authority = json.loads((object_repo / verifier.AUTHORITY_PATH).read_text(encoding="utf-8"))
        self.assertNotEqual(authority["source_commit"], first_parent)
        self.assert_pair_failure(checkout, object_repo=object_repo)

    def test_warning_suppressed_grafts_cannot_forge_ancestry(self) -> None:
        object_repo, checkout = self.make_synthetic_authority_repo(grafted_parent=True)
        self.assert_pair_failure(checkout, object_repo=object_repo)

    def test_empty_local_objects_with_alternates_are_rejected(self) -> None:
        external_temporary, external = self.copy_object_repo()
        self.addCleanup(external_temporary.cleanup)
        local_temporary, local = self.copy_object_repo()
        self.addCleanup(local_temporary.cleanup)
        objects = local / ".git/objects"
        shutil.rmtree(objects)
        (objects / "info").mkdir(parents=True)
        (objects / "info/alternates").write_text(
            str(external / ".git/objects") + "\n", encoding="utf-8"
        )
        with self.copy_checkout() as temporary:
            self.assert_pair_failure(Path(temporary), object_repo=local)

    def test_shallow_repository_is_rejected_in_both_modes(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-shallow-")
        self.addCleanup(temporary.cleanup)
        object_repo = Path(temporary.name) / "repo"
        subprocess.run(
            ["git", "clone", "--no-local", "--depth", "1", "--quiet", ROOT.as_uri(), str(object_repo)],
            check=True,
            capture_output=True,
        )
        with self.copy_checkout() as checkout_temporary:
            self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)

    def test_symlinked_and_external_git_boundaries_are_rejected(self) -> None:
        variants: list[str] = ["git-marker", "commondir", "gitdir"]
        for variant in variants:
            with self.subTest(variant=variant):
                object_temporary, object_repo = self.copy_object_repo()
                self.addCleanup(object_temporary.cleanup)
                marker = object_repo / ".git"
                if variant == "git-marker":
                    real_marker = object_repo / ".git-real"
                    marker.rename(real_marker)
                    marker.symlink_to(real_marker, target_is_directory=True)
                elif variant == "commondir":
                    (marker / "commondir").write_text("/tmp/external-common\n", encoding="ascii")
                else:
                    (marker / "gitdir").symlink_to(object_repo.parent / "external-gitdir")
                with self.copy_checkout() as checkout_temporary:
                    self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)

    def test_linked_worktree_gitdir_is_rejected(self) -> None:
        base_temporary, base_repo = self.copy_object_repo()
        self.addCleanup(base_temporary.cleanup)
        linked_repo = base_repo.parent / "linked-worktree"
        subprocess.run(
            ["git", "-C", str(base_repo), "worktree", "add", "--quiet", "--detach", str(linked_repo), "HEAD"],
            check=True,
            capture_output=True,
        )
        with self.copy_checkout() as checkout_temporary:
            self.assert_pair_failure(Path(checkout_temporary), object_repo=linked_repo)

    def test_nested_object_pack_and_ref_symlinks_are_rejected(self) -> None:
        variants = ("fanout", "pack", "ref")
        for variant in variants:
            with self.subTest(variant=variant):
                object_temporary, object_repo = self.copy_object_repo()
                self.addCleanup(object_temporary.cleanup)
                git_dir = object_repo / ".git"
                outside = object_repo.parent / f"outside-{variant}"
                outside.write_bytes(b"external\n")
                if variant == "fanout":
                    fanout = git_dir / "objects" / "aa"
                    fanout.mkdir(exist_ok=True)
                    nested = fanout / "nested-redirect"
                elif variant == "pack":
                    pack = git_dir / "objects" / "pack"
                    pack.mkdir(exist_ok=True)
                    nested = pack / "redirect.pack"
                else:
                    heads = git_dir / "refs" / "heads"
                    heads.mkdir(parents=True, exist_ok=True)
                    nested = heads / "redirect"
                nested.symlink_to(outside)
                with self.copy_checkout() as checkout_temporary:
                    self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)

    def test_source_replacements_after_descriptor_walk_do_not_race_snapshot(self) -> None:
        variants = ("fanout", "pack", "ref", "config", "metadata")
        for variant in variants:
            with self.subTest(variant=variant):
                object_temporary, object_repo = self.copy_object_repo()
                self.addCleanup(object_temporary.cleanup)
                git_dir = object_repo / ".git"
                outside = object_repo.parent / f"race-outside-{variant}"
                if variant == "fanout":
                    source_commit = self.authority["source_commit"]
                    target = git_dir / "objects" / source_commit[:2] / source_commit[2:]
                    if not target.is_file():
                        # Packed clones have no loose source object. Materialize
                        # the exact verified commit as a valid loose object so
                        # this nested fanout replacement race stays independent
                        # of HEAD symbolicness and pack layout.
                        object_data = subprocess.check_output(
                            [
                                "git",
                                "-C",
                                str(object_repo),
                                "cat-file",
                                "commit",
                                source_commit,
                            ]
                        )
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(
                            zlib.compress(
                                b"commit "
                                + str(len(object_data)).encode("ascii")
                                + b"\x00"
                                + object_data
                            )
                        )
                    self.assertTrue(target.is_file())
                    backup = target.with_name(target.name + ".saved")
                    outside.write_bytes(b"not a Git object")
                    mutate = lambda: (target.rename(backup), target.symlink_to(outside))
                elif variant == "pack":
                    subprocess.run(
                        ["git", "-C", str(object_repo), "repack", "-ad"],
                        check=True,
                        capture_output=True,
                    )
                    subprocess.run(
                        ["git", "-C", str(object_repo), "prune-packed"],
                        check=True,
                        capture_output=True,
                    )
                    target = git_dir / "objects" / "pack"
                    self.assertTrue(target.is_dir())
                    # A real pack may exceed the snapshot's deliberate
                    # per-file cap. That is a bounded rejection, not a race
                    # success case; the dedicated oversized-pack regression
                    # below covers this trust boundary.
                    if any(
                        child.is_file() and child.stat().st_size > verifier.MAX_SNAPSHOT_PACK_FILE_BYTES
                        for child in target.iterdir()
                    ):
                        with self.copy_checkout() as checkout_temporary:
                            self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)
                        continue
                    backup = target.with_name("pack.saved")
                    outside.mkdir()
                    mutate = lambda: (target.rename(backup), target.symlink_to(outside, target_is_directory=True))
                elif variant == "ref":
                    # Create a deterministic loose ref instead of assuming
                    # the caller checkout has a symbolic HEAD. This keeps the
                    # race regression valid for detached exact-SHA checkouts.
                    ref_name = "refs/heads/authority-race"
                    target = git_dir / ref_name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(
                        subprocess.check_output(
                            ["git", "-C", str(object_repo), "rev-parse", "HEAD"],
                            text=True,
                        ),
                        encoding="ascii",
                    )
                    backup = target.with_name(target.name + ".saved")
                    outside.write_text("0" * 40 + "\n", encoding="ascii")
                    mutate = lambda: (target.rename(backup), target.symlink_to(outside))
                elif variant == "config":
                    target = git_dir / "config"
                    backup = target.with_name("config.saved")
                    outside.write_text("[core]\n\tbare = true\n", encoding="ascii")
                    mutate = lambda: (target.rename(backup), target.symlink_to(outside))
                else:
                    target = git_dir / "HEAD"
                    backup = target.with_name("HEAD.saved")
                    outside.write_text("ref: refs/heads/missing\n", encoding="ascii")
                    mutate = lambda: (target.rename(backup), target.symlink_to(outside))

                real_walk = verifier._walk_plain_tree
                mutated = False

                def race_walk(path: Path) -> None:
                    nonlocal mutated
                    real_walk(path)
                    if not mutated:
                        mutate()
                        mutated = True

                with mock.patch.object(verifier, "_walk_plain_tree", side_effect=race_walk):
                    trusted = verifier.load_trusted_authority(object_repo)
                self.assertTrue(mutated)
                self.assertEqual(trusted["source_commit"], self.authority["source_commit"])

    def test_local_include_promisor_and_redirect_config_is_rejected(self) -> None:
        configurations = (
            "[include]\n    path = /tmp/hostile-include\n",
            '[remote "origin"]\n    promisor = true\n',
            "[extensions]\n    partialClone = origin\n",
            '[url "file:///tmp/hostile/"]\n    insteadOf = origin\n',
        )
        for index, configuration in enumerate(configurations):
            with self.subTest(index=index):
                object_temporary, object_repo = self.copy_object_repo()
                self.addCleanup(object_temporary.cleanup)
                with (object_repo / ".git/config").open("a", encoding="utf-8") as config:
                    config.write(configuration)
                with self.copy_checkout() as checkout_temporary:
                    self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)

    def test_local_replacement_refs_are_rejected_not_followed(self) -> None:
        object_temporary, object_repo = self.copy_object_repo()
        self.addCleanup(object_temporary.cleanup)
        authority_commit = subprocess.check_output(
            ["git", "-C", str(object_repo), "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(
            ["git", "-C", str(object_repo), "replace", authority_commit, "0f3a05ff5468fb9a3bd238cf788d746ec383e01a"],
            check=True,
            capture_output=True,
        )
        with self.copy_checkout() as checkout_temporary:
            self.assert_pair_failure(Path(checkout_temporary), object_repo=object_repo)

    def test_annotated_tag_source_commit_is_rejected_in_both_modes(self) -> None:
        object_repo, checkout = self.make_synthetic_authority_repo(annotated_tag=True)
        self.assert_pair_failure(checkout, object_repo=object_repo)

    def test_hostile_path_and_global_config_cannot_intercept_git(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-hostile-host-")
        self.addCleanup(temporary.cleanup)
        host = Path(temporary.name)
        shim_dir = host / "bin"
        shim_dir.mkdir()
        marker = host / "shim-used"
        shim = shim_dir / "git"
        shim.write_text(f"#!/bin/sh\nprintf used > {marker}\nexit 99\n", encoding="utf-8")
        shim.chmod(0o755)
        global_config = host / "global.gitconfig"
        global_config.write_text("[core]\n    bare = true\n", encoding="utf-8")
        hostile = {
            "PATH": str(shim_dir),
            "HOME": str(host),
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_CONFIG_SYSTEM": str(global_config),
            "GIT_CONFIG_NOSYSTEM": "0",
        }
        with self.copy_checkout() as checkout_temporary:
            checkout = Path(checkout_temporary)
            normal = self.run_cli(checkout, optimized=False, environment=hostile)
            optimized = self.run_cli(checkout, optimized=True, environment=hostile)
            self.assertEqual(normal.stdout, optimized.stdout)
            self.assert_success(normal)
            self.assert_success(optimized)
        self.assertFalse(marker.exists())

    def test_checkout_and_object_root_resolution_failures_are_bounded(self) -> None:
        with self.copy_checkout() as checkout_temporary:
            checkout = Path(checkout_temporary)
            checkout_loop_temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-checkout-loop-")
            self.addCleanup(checkout_loop_temporary.cleanup)
            checkout_loop = Path(checkout_loop_temporary.name) / "loop"
            checkout_loop_target = Path(checkout_loop_temporary.name) / "loop-target"
            checkout_loop.symlink_to(checkout_loop_target, target_is_directory=True)
            checkout_loop_target.symlink_to(checkout_loop, target_is_directory=True)
            self.assert_pair_failure(checkout_loop, object_repo=self.object_repo)
        object_loop_temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-object-loop-")
        self.addCleanup(object_loop_temporary.cleanup)
        object_loop = Path(object_loop_temporary.name) / "loop"
        object_loop_target = Path(object_loop_temporary.name) / "loop-target"
        object_loop.symlink_to(object_loop_target, target_is_directory=True)
        object_loop_target.symlink_to(object_loop, target_is_directory=True)
        with self.copy_checkout() as checkout_temporary:
            self.assert_pair_failure(Path(checkout_temporary), object_repo=object_loop)

    def test_resolution_oserror_runtimeerror_and_valueerror_are_authority_errors(self) -> None:
        for failure in (OSError("resolve"), RuntimeError("resolve"), ValueError("resolve")):
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(Path, "resolve", side_effect=failure):
                    with self.assertRaises(verifier.AuthorityError):
                        verifier._read_checkout_file(ROOT, "contracts/fixtures/index.json")

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
