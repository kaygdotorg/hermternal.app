"""Regression tests for the local P0-01 source-review validator."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import validate


class PlanningReviewValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.repo_root = self.root / "repo"
        self.source_root = self.root / "source"
        self.repo_root.mkdir()
        self.source_root.mkdir()
        (self.repo_root / "README.md").write_text(
            "synthetic planning document\n", encoding="utf-8"
        )
        (self.source_root / "src").mkdir()
        self.source_file = self.source_root / "src" / "module.py"
        self.source_file.write_text("ANCHOR\n", encoding="utf-8")
        self._git("init", "-q")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "P0-01 validator test")
        self._git("add", ".")
        self._git("commit", "-qm", "synthetic pinned source")
        self.source_sha = self._git("rev-parse", "HEAD").stdout.strip()
        self.review_path = self.root / "review.json"
        review = {
            "format_version": 1,
            "operation": "P0-01",
            "contract": validate.EXPECTED_CONTRACT,
            "source": {
                "repository": "NousResearch/hermes-agent",
                "sha": self.source_sha,
            },
            "planning_docs": ["README.md"],
            "required_links": [],
            "source_files": [
                {
                    "path": "src/module.py",
                    "sha256": hashlib.sha256(b"ANCHOR\n").hexdigest(),
                    "anchors": [{"id": "anchor", "literal": "ANCHOR", "line": 1}],
                    "absent": ["FORBIDDEN_FIELD"],
                }
            ],
        }
        self.review_path.write_text(json.dumps(review), encoding="utf-8")
        self._source_pin = mock.patch.object(validate, "EXPECTED_SOURCE_SHA", self.source_sha)
        self._source_pin.start()

    def tearDown(self) -> None:
        self._source_pin.stop()
        self.tempdir.cleanup()

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.source_root), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def _validate(self) -> list[str]:
        errors, head, _duration = validate.validate_review(
            self.repo_root, self.review_path, self.source_root
        )
        self.assertEqual(head, self.source_sha)
        return errors

    def test_valid_synthetic_source_passes(self) -> None:
        self.assertEqual(self._validate(), [])

    def test_changed_source_fails_digest_check(self) -> None:
        self.source_file.write_text("CHANGED\n", encoding="utf-8")
        errors = self._validate()
        self.assertTrue(any("digest mismatch" in error for error in errors))

    def test_missing_anchor_fails_closed(self) -> None:
        self.source_file.write_text("OTHER\n", encoding="utf-8")
        errors = self._validate()
        self.assertTrue(any("missing source anchor" in error for error in errors))

    def test_forbidden_source_field_fails_closed(self) -> None:
        self.source_file.write_text("ANCHOR\nFORBIDDEN_FIELD\n", encoding="utf-8")
        errors = self._validate()
        self.assertTrue(any("forbidden source field" in error for error in errors))

    def test_missing_source_root_fails_closed(self) -> None:
        errors, _head, _duration = validate.validate_review(
            self.repo_root, self.review_path, self.root / "missing-source"
        )
        self.assertTrue(any("source root is missing" in error for error in errors))

    def test_malformed_review_fails_closed(self) -> None:
        self.review_path.write_text("{not-json", encoding="utf-8")
        errors, head, _duration = validate.validate_review(
            self.repo_root, self.review_path, self.source_root
        )
        self.assertIsNone(head)
        self.assertTrue(any("cannot read review record" in error for error in errors))

    def test_document_only_mode_does_not_require_source_checkout(self) -> None:
        errors, head, _duration = validate.validate_review(
            self.repo_root,
            self.review_path,
            None,
            require_source=False,
        )
        self.assertEqual(errors, [])
        self.assertIsNone(head)


class CheckedInReviewMetadataTests(unittest.TestCase):
    def test_reserved_audits_are_explicitly_deferred(self) -> None:
        review_path = Path(__file__).with_name("planning_review.json")
        review = validate.load_review(review_path)
        deferred_text = json.dumps(review["deferred"])
        for marker in ("#200", "PR #216", "PR #218", "PR #219", "PR #220"):
            self.assertIn(marker, deferred_text)
        self.assertIn(
            "contracts/fixtures/source-audit/planning-reconciliation/README.md",
            review["planning_docs"],
        )


if __name__ == "__main__":
    unittest.main()
