#!/usr/bin/env python3
"""Offline tests for the authority-bound retained replay publisher."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("replay_result_successor", HERE / "replay_result_successor.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MOD; SPEC.loader.exec_module(MOD)
O40 = "1" * 40

def write(path: Path, raw: bytes) -> None:
    path.write_bytes(raw); os.chmod(path, 0o600)

class Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name).resolve()
        self.authority = self.base / "authority"; self.authority.mkdir(mode=0o700)
        shell = b"#!/bin/bash\nprintf retained\n"
        markdown = b"# Candidate\n\n```bash\n" + shell + b"```\n"
        document = {"execution_driver": {"argv": ["/usr/bin/env", "-i", "/bin/bash", "-s"], "shell": shell.decode()}}
        json_raw = (json.dumps(document, sort_keys=True) + "\n").encode()
        self.raws = {"markdown": markdown, "json": json_raw, "shell": shell}
        for role, name in MOD.ROLE_NAMES.items(): write(self.authority / name, self.raws[role])
        roles = [{"role": role, "path": str(self.authority / name), "sha256": hashlib.sha256(self.raws[role]).hexdigest()} for role, name in MOD.ROLE_NAMES.items()]
        write(self.authority / "authority-descriptor.json", (json.dumps({"schema": "fixture", "roles": roles, "normalized_json_sha256": "0" * 64}, sort_keys=True) + "\n").encode())
        outputs = {role: {"path": str(self.authority / name), "sha256": hashlib.sha256(self.raws[role]).hexdigest()} for role, name in MOD.ROLE_NAMES.items()}
        provenance = {"schema": "hermternal.issue-397.candidate-five-provenance.v1", "issue": 397, "candidate": "five", "generation": {}, "repository_boundary": {"integrated_commit": O40, "integrated_tree": "2" * 40, "base_commit": "3" * 40, "base_tree": "4" * 40, "protected_main_commit": "5" * 40, "source_commit": "6" * 40}, "dependencies": [], "source_inputs": [], "outputs": outputs, "cross_format_authority": {}, "publication": {}, "safety_claims": {}}
        write(self.authority / "provenance-manifest.json", (json.dumps(provenance, sort_keys=True) + "\n").encode())
        self.provenance_sha = hashlib.sha256((self.authority / "provenance-manifest.json").read_bytes()).hexdigest()
        self.run_parent = self.base / "fresh-run"

    def tearDown(self) -> None: self.temp.cleanup()

    @staticmethod
    def observed(repository: Path) -> object:
        st = os.lstat(repository)
        return MOD.RepositoryObservation({"st_dev": st.st_dev, "st_ino": st.st_ino, "st_uid": st.st_uid, "st_mode": 0o700, "st_nlink": st.st_nlink}, "a" * 40, "b" * 40, "c" * 40)

    def runner(self, calls: list[tuple[tuple[str, ...], dict[str, object]]]):
        def run(argv, **kwargs):
            calls.append((argv, kwargs)); return SimpleNamespace(returncode=0, stdout=b"ok\nreplay-complete-retained\n", stderr=b"")
        return run

    def publish(self):
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
        with mock.patch.object(MOD, "observe_repository", side_effect=self.observed):
            publication = MOD.publish_retained_result(self.run_parent, self.authority, self.provenance_sha, runner=self.runner(calls))
        return publication, calls

    def test_exact_authority_process_and_retention(self) -> None:
        publication, calls = self.publish()
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(argv, ("/usr/bin/env", "-i", "/bin/bash", "-s"))
        self.assertEqual(kwargs["input"], self.raws["shell"])
        self.assertEqual(kwargs["env"], {})
        self.assertEqual(kwargs["cwd"], str(self.run_parent / "repository"))
        self.assertTrue(publication.result.path.exists() and publication.completion.path.exists())
        self.assertEqual(oct(publication.result.path.stat().st_mode & 0o777), "0o600")

    def test_preexisting_parent_and_authority_mismatch_reject_before_process(self) -> None:
        self.run_parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(MOD.Reject, "already exists"):
            MOD.publish_retained_result(self.run_parent, self.authority, self.provenance_sha, runner=lambda *_a, **_k: self.fail("must not run"))
        with self.assertRaisesRegex(MOD.Reject, "approved provenance hash differs"):
            MOD.publish_retained_result(self.base / "other", self.authority, "0" * 64, runner=lambda *_a, **_k: self.fail("must not run"))

    def test_fabricated_caller_values_are_not_an_api(self) -> None:
        self.assertNotIn("facts", MOD.publish_retained_result.__annotations__)
        self.assertNotIn("repository", MOD.publish_retained_result.__annotations__)
        with self.assertRaises(TypeError):
            MOD.publish_retained_result(self.run_parent, self.authority, self.provenance_sha, facts=object())

    def test_repository_semantic_mutation_rejects(self) -> None:
        publication, _ = self.publish()
        changed = MOD.RepositoryObservation(dict(publication.repository.identity), "f" * 40, publication.repository.parent, publication.repository.tree)
        with mock.patch.object(MOD, "observe_repository", return_value=changed):
            with self.assertRaisesRegex(MOD.Reject, "semantic evidence"):
                MOD.verify_publication(publication)

    def test_failed_or_markerless_process_creates_no_record(self) -> None:
        for result in (SimpleNamespace(returncode=7, stdout=b"", stderr=b""), SimpleNamespace(returncode=0, stdout=b"missing\n", stderr=b"")):
            target = self.base / ("failure-" + str(result.returncode) + str(len(result.stdout)))
            with mock.patch.object(MOD, "observe_repository", side_effect=self.observed):
                with self.assertRaises(MOD.Reject): MOD.publish_retained_result(target, self.authority, self.provenance_sha, runner=lambda *_a, **_k: result)
            self.assertFalse((target / "replay-root" / MOD.RESULT_NAME).exists())

    def test_cleanup_is_disabled(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "implementation"): MOD.request_cleanup()
        with self.assertRaisesRegex(MOD.Reject, "disabled"): MOD.request_cleanup(enable_cleanup=True)

if __name__ == "__main__": unittest.main(verbosity=2)
