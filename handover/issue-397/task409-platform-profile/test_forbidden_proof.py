#!/usr/bin/env python3
"""Adversarial tests for the forbidden historical object proof."""
from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import forbidden_proof as PROOF  # noqa: E402
import linux_retained_driver_v2 as V2  # noqa: E402
import linux_retained_driver_v3 as V3  # noqa: E402


class ForbiddenProofTests(unittest.TestCase):
    ENV = {**PROOF.SAFE_ENV, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
           "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid"}

    def git(self, repo: Path, *args: str, input_bytes: bytes | None = None) -> str:
        return subprocess.run(["/usr/bin/git", "-C", os.fspath(repo), *args], input=input_bytes,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                              env=self.ENV).stdout.decode().strip()

    def repository(self):
        temporary = tempfile.TemporaryDirectory(prefix="issue397-forbidden-proof-")
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name) / "repo"
        repo.mkdir()
        self.git(repo, "init", "-q")
        self.git(repo, "commit", "--allow-empty", "-q", "-m", "base")
        base = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "branch", "side")
        self.git(repo, "commit", "--allow-empty", "-q", "-m", "final")
        final = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "checkout", "-q", "side")
        self.git(repo, "commit", "--allow-empty", "-q", "-m", "rejected")
        rejected = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "checkout", "-q", final)
        return repo, base, final, rejected

    def test_current_profile_classifies_exact_five_missing(self) -> None:
        profile = V2.platform_profile.load()
        authority = V2.load_driver().load_frozen_authority().document
        forbidden = authority["forbidden_ancestry"]
        record = PROOF.classify(Path(profile.source_repository), profile.source_detached_head,
                                [*forbidden["commits"], *forbidden["raw_semantic_source_commits"]],
                                [authority["base"]["commit"], authority["base"]["protected_main_commit"], profile.source_detached_head])
        missing = [row["oid"] for row in record["forbidden"] if row["status"] == "missing-proved"]
        self.assertEqual(missing, ["7271e7bac836a519c3df66a93ceb3b2c5a0d8921",
                                   "03e2b0c828276044d1229c0200a5ac969140a344",
                                   "ad9bc22b7cc86e0c007a0347e2dec78fa49132a4",
                                   "48b58c19e4e4991d1d15321a8e39b8261937b59b",
                                   "c7ab4f9b0fec97b4e4de20bada6f43e57bd7d5e3"])
        self.assertEqual(len(record["forbidden"]), 22)
        self.assertEqual(PROOF.record_sha256(record), PROOF.record_sha256(json.loads(PROOF.canonical_bytes(record))))

    def test_present_nonancestor_passes_and_ancestor_rejects(self) -> None:
        repo, base, final, rejected = self.repository()
        record = PROOF.classify(repo, final, [rejected], [base, final])
        self.assertEqual(record["forbidden"], [{"oid": rejected, "status": "present-non-ancestor"}])
        with self.assertRaisesRegex(PROOF.ProofError, "forbidden commit ancestry"):
            PROOF.classify(repo, final, [base], [base, final])

    def test_driver_changes_only_the_three_availability_predicates(self) -> None:
        base = V2.derive_contract()
        proof = V3.forbidden_proof_record()
        expected = PROOF.repair_generated_validator(base.stdin, proof, PROOF.record_sha256(proof))
        derived = V3.derive_contract()
        self.assertEqual(derived.argv, base.argv)
        self.assertEqual(derived.source_sha256, base.source_sha256)
        self.assertEqual(derived.stdin, expected)
        self.assertEqual(derived.derived_sha256, hashlib.sha256(expected).hexdigest())
        self.assertEqual(expected.count(b"missing_proved_forbidden ="), 1)
        self.assertEqual(expected.count(b"MISSING_PROVED = frozenset"), 1)
        V3.load_driver().compile_derived(expected)

    def test_missing_rejects_unsafe_repository_indirection(self) -> None:
        mutations = {
            "shallow": lambda repo: (repo / ".git" / "shallow").write_text("0" * 40 + "\n"),
            "alternate": lambda repo: (repo / ".git" / "objects" / "info" / "alternates").write_text("/tmp/objects\n"),
            "http-alternate": lambda repo: (repo / ".git" / "objects" / "info" / "http-alternates").write_text("https://example.invalid/objects\n"),
            "graft": lambda repo: (repo / ".git" / "info" / "grafts").write_text("0" * 40 + "\n"),
            "replacement": lambda repo: (repo / ".git" / "refs" / "replace").mkdir(parents=True),
            "promisor": lambda repo: (repo / ".git" / "objects" / "pack" / "test.promisor").write_bytes(b""),
            "partial-clone-extension": lambda repo: self.git(repo, "config", "extensions.partialClone", "origin"),
            "promisor-config": lambda repo: self.git(repo, "config", "remote.origin.promisor", "true"),
            "partial-clone-filter": lambda repo: self.git(repo, "config", "remote.origin.partialCloneFilter", "blob:none"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                repo, base, final, _ = self.repository()
                mutate(repo)
                with self.assertRaises(PROOF.ProofError):
                    PROOF.classify(repo, final, ["f" * 40], [base, final])

    def test_missing_rejects_fsck_and_root_closure_failures(self) -> None:
        repo, base, final, _ = self.repository()
        original = PROOF._run
        def fail_fsck(repository, *args, **kwargs):
            if args and args[0] == "fsck":
                return subprocess.CompletedProcess(args, 1, b"", b"broken")
            return original(repository, *args, **kwargs)
        with mock.patch.object(PROOF, "_run", side_effect=fail_fsck):
            with self.assertRaisesRegex(PROOF.ProofError, "fsck"):
                PROOF.classify(repo, final, ["f" * 40], [base, final])

        def fail_root(repository, *args, **kwargs):
            if len(args) >= 2 and args[:2] == ("rev-list", "--objects") and "--all" not in args:
                return subprocess.CompletedProcess(args, 1, b"", b"missing")
            return original(repository, *args, **kwargs)
        with mock.patch.object(PROOF, "_run", side_effect=fail_root):
            with self.assertRaisesRegex(PROOF.ProofError, "closure"):
                PROOF.classify(repo, final, ["f" * 40], [base, final])


if __name__ == "__main__":
    unittest.main(verbosity=2)
