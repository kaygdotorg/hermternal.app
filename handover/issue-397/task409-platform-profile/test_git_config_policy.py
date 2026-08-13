#!/usr/bin/env python3
"""Regress the exact generated repository config and shared #400 policy."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))

import git_config_policy as policy  # noqa: E402
import linux_git_config_adapter  # noqa: E402
import linux_retained_driver as driver_v1  # noqa: E402
import linux_retained_driver_v2 as driver_v2  # noqa: E402


class GitConfigPolicyTests(unittest.TestCase):
    """Prove that remote metadata and protocol permissions are not conflated."""

    SAFE_ENV = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
    }

    @staticmethod
    def exact_source_records() -> bytes:
        profile = driver_v1.platform_profile.load()
        result = subprocess.run(
            [
                profile.tools["git"].path,
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "-C",
                profile.source_repository,
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                policy.PROTOCOL_OVERRIDE,
                "config",
                "--local",
                "--get-regexp",
                r"^(extensions\.partialClone|remote\..*|protocol\.allow|protocol\..*\.allow)$",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            env=dict(GitConfigPolicyTests.SAFE_ENV),
        )
        return result.stdout

    def test_exact_source_config_is_accepted(self) -> None:
        records = self.exact_source_records()
        self.assertIn(b"remote.origin.url ", records)
        self.assertNotIn(b"protocol.allow never\n", records)
        policy.validate_generated_records(records)

    def test_clean_primary_records_and_unsafe_protocol(self) -> None:
        profile = driver_v1.platform_profile.load()
        records = (
            f"remote.origin.url {profile.source_repository}\n".encode()
            + b"remote.origin.fetch +refs/heads/*:refs/remotes/origin/*\n"
            + b"protocol.allow never\n"
        )
        policy.validate_generated_records(records)
        with self.assertRaisesRegex(ValueError, "unsafe protocol"):
            policy.validate_generated_records(records.replace(b"protocol.allow never", b"protocol.allow always"))
        with self.assertRaisesRegex(ValueError, "unsafe protocol"):
            policy.validate_generated_records(b"protocol.file.allow always\n")

    def test_actual_generated_clean_primary_records(self) -> None:
        profile = driver_v1.platform_profile.load()
        with tempfile.TemporaryDirectory(prefix="issue397-clean-primary-") as parent:
            seed = Path(parent) / "seed"
            clean = Path(parent) / "clean"
            subprocess.run(["/usr/bin/git", "init", "-q", os.fspath(seed)], check=True, env=dict(self.SAFE_ENV))
            subprocess.run(
                ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", policy.PROTOCOL_OVERRIDE, "-c", "protocol.file.allow=always", "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--no-tags", os.fspath(seed), os.fspath(clean)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(self.SAFE_ENV),
            )
            prefix = ["/usr/bin/git", "-C", os.fspath(clean), "-c", "core.hooksPath=/dev/null", "-c", policy.PROTOCOL_OVERRIDE]
            for key, value in (
                ("core.hooksPath", "/dev/null"),
                (policy.PROTOCOL_KEY, policy.PROTOCOL_VALUE),
                ("remote.origin.url", profile.source_repository),
                ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
            ):
                subprocess.run([*prefix, "config", "--local", key, value], check=True, env=dict(self.SAFE_ENV))
            observed = subprocess.run(
                [*prefix, "config", "--local", "--get-regexp", r"^(extensions\.partialClone|remote\..*|protocol\.allow|protocol\..*\.allow)$"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(self.SAFE_ENV),
            ).stdout
            expected = (
                f"remote.origin.url {profile.source_repository}\n".encode()
                + b"remote.origin.tagopt --no-tags\n"
                + b"remote.origin.fetch +refs/heads/*:refs/remotes/origin/*\n"
                + b"protocol.allow never\n"
            )
            self.assertEqual(observed, expected)
            policy.validate_generated_records(observed)

    def test_replay_config_is_exact_frozen_400_contract(self) -> None:
        successor = linux_git_config_adapter.load_successor()
        policy.validate_git_successor_contract(successor)
        with tempfile.TemporaryDirectory(prefix="issue397-config-policy-") as parent:
            root = Path(parent) / "repo"
            subprocess.run(["/usr/bin/git", "init", "-q", os.fspath(root)], check=True, env=dict(successor.SAFE_ENV))
            subprocess.run(["/usr/bin/git", "-C", os.fspath(root), "config", "--local", "core.hooksPath", "/dev/null"], check=True, env=dict(successor.SAFE_ENV))
            subprocess.run(["/usr/bin/git", "-C", os.fspath(root), "config", "--local", policy.PROTOCOL_KEY, policy.PROTOCOL_VALUE], check=True, env=dict(successor.SAFE_ENV))
            self.assertEqual((root / ".git" / "config").read_bytes(), policy.CANONICAL_CONFIG)
            successor.validate_canonical_config((root / ".git" / "config").read_bytes())

    def test_derived_stdin_has_one_shared_predicate(self) -> None:
        old = driver_v1.derive_contract()
        new = driver_v2.derive_contract()
        self.assertEqual(old.stdin.count(policy.OLD_OBJECT_CLOSURE_BLOCK), 1)
        self.assertEqual(new.stdin.count(policy.OLD_OBJECT_CLOSURE_BLOCK), 0)
        self.assertEqual(new.stdin.count(policy.NEW_OBJECT_CLOSURE_BLOCK), 1)
        self.assertEqual(new.derived_sha256, hashlib.sha256(new.stdin).hexdigest())
        self.assertNotEqual(old.derived_sha256, new.derived_sha256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
