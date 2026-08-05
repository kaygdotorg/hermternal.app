"""Regression tests for the local P0-01 source-review validator."""

from __future__ import annotations

import hashlib
import io
import json
import os
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
        self.synthetic_planning_docs = ["README.md"]
        self.synthetic_required_links = [{"path": "README.md", "target": "README.md"}]
        self.synthetic_source_files = [
            {
                "path": "src/module.py",
                "sha256": hashlib.sha256(b"ANCHOR\n").hexdigest(),
                "anchors": [{"id": "anchor", "literal": "ANCHOR", "line": 1}],
                "absent": ["FORBIDDEN_FIELD"],
            }
        ]
        self.synthetic_claims = [
            {
                "id": "synthetic-claim",
                "status": "verified",
                "source_files": ["src/module.py"],
                "evidence": [
                    {
                        "source_file": "src/module.py",
                        "sha256": hashlib.sha256(b"ANCHOR\n").hexdigest(),
                        "anchors": ["anchor"],
                    }
                ],
                "docs": ["README.md"],
                "summary": "Synthetic source evidence.",
            }
        ]
        self.synthetic_deferred = [
            {
                "owner": "synthetic owner",
                "scope": "synthetic scope",
                "reason": "synthetic boundary",
            }
        ]
        self._metadata_patches = [
            mock.patch.object(validate, "EXPECTED_PLANNING_DOCS", self.synthetic_planning_docs),
            mock.patch.object(validate, "EXPECTED_REQUIRED_LINKS", self.synthetic_required_links),
            mock.patch.object(validate, "EXPECTED_SOURCE_FILES", self.synthetic_source_files),
            mock.patch.object(validate, "EXPECTED_CLAIMS", self.synthetic_claims),
            mock.patch.object(validate, "EXPECTED_PURPOSE", "Synthetic planning review."),
            mock.patch.object(validate, "EXPECTED_DEFERRED", self.synthetic_deferred),
        ]
        for patcher in self._metadata_patches:
            patcher.start()
        (self.repo_root / "README.md").write_text(
            "[synthetic planning document](README.md)\n", encoding="utf-8"
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
            "purpose": validate.EXPECTED_PURPOSE,
            "planning_docs": validate.EXPECTED_PLANNING_DOCS,
            "required_links": validate.EXPECTED_REQUIRED_LINKS,
            "source_files": validate.EXPECTED_SOURCE_FILES,
            "claims": validate.EXPECTED_CLAIMS,
            "deferred": validate.EXPECTED_DEFERRED,
        }
        self.review_path.write_text(json.dumps(review), encoding="utf-8")
        self._source_pin = mock.patch.object(validate, "EXPECTED_SOURCE_SHA", self.source_sha)
        self._source_pin.start()

    def tearDown(self) -> None:
        self._source_pin.stop()
        for patcher in self._metadata_patches:
            patcher.stop()
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

    def _load_review(self) -> dict[str, object]:
        return json.loads(self.review_path.read_text(encoding="utf-8"))

    def _write_review(self, review: dict[str, object]) -> None:
        self.review_path.write_text(json.dumps(review), encoding="utf-8")

    def _validate_both_modes(self) -> tuple[list[str], list[str]]:
        full_errors, _head, _duration = validate.validate_review(
            self.repo_root, self.review_path, self.source_root
        )
        docs_errors, _head, _duration = validate.validate_review(
            self.repo_root,
            self.review_path,
            self.source_root,
            require_source=False,
        )
        return full_errors, docs_errors

    def test_valid_synthetic_source_passes(self) -> None:
        self.assertEqual(self._validate(), [])

    def test_dirty_source_fails_even_if_worktree_digest_is_updated(self) -> None:
        self.source_file.write_text("CHANGED\n", encoding="utf-8")
        review = self._load_review()
        review["source_files"][0]["sha256"] = hashlib.sha256(
            b"CHANGED\n"
        ).hexdigest()
        self._write_review(review)
        errors = self._validate()
        self.assertTrue(any("source checkout is dirty" in error for error in errors))

    def test_untracked_source_file_fails_closed(self) -> None:
        (self.source_root / "untracked.py").write_text("ANCHOR\n", encoding="utf-8")
        errors = self._validate()
        self.assertTrue(any("source checkout is dirty" in error for error in errors))

    def test_assume_unchanged_flag_fails_closed(self) -> None:
        self._git("update-index", "--assume-unchanged", "src/module.py")
        try:
            errors = self._validate()
        finally:
            self._git("update-index", "--no-assume-unchanged", "src/module.py")
        self.assertTrue(any("assume-unchanged" in error for error in errors))

    def test_skip_worktree_flag_fails_closed(self) -> None:
        self._git("update-index", "--skip-worktree", "src/module.py")
        try:
            errors = self._validate()
        finally:
            self._git("update-index", "--no-skip-worktree", "src/module.py")
        self.assertTrue(any("skip-worktree" in error for error in errors))

    def test_git_blob_disables_lazy_fetch(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout=b"ANCHOR\n", stderr=b""
        )
        with mock.patch.object(validate.subprocess, "run", return_value=completed) as run:
            self.assertEqual(validate._git_blob(self.source_root, self.source_sha, "src/module.py"), b"ANCHOR\n")
        self.assertEqual(run.call_args.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")

    def test_missing_git_blob_is_reported_without_fetch(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=1, stdout=b"", stderr=b"promisor remote unavailable"
        )
        with mock.patch.object(validate.subprocess, "run", return_value=completed) as run:
            self.assertIsNone(validate._git_blob(self.source_root, self.source_sha, "src/module.py"))
        self.assertEqual(run.call_args.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
        with mock.patch.object(validate, "_git_blob", return_value=None):
            errors = self._validate()
        self.assertTrue(any("missing pinned source blob" in error for error in errors))

    def test_parent_traversal_source_path_fails_in_both_modes(self) -> None:
        outside = self.root / "outside.py"
        outside.write_text("ANCHOR\n", encoding="utf-8")
        review = self._load_review()
        source_entry = review["source_files"][0]
        source_entry["path"] = "../outside.py"
        source_entry["sha256"] = hashlib.sha256(b"ANCHOR\n").hexdigest()
        self._write_review(review)

        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(
                any("source entry path" in error and ".." in error for error in errors)
            )

    def test_absolute_source_path_fails_in_both_modes(self) -> None:
        outside = self.root / "outside.py"
        outside.write_text("ANCHOR\n", encoding="utf-8")
        review = self._load_review()
        source_entry = review["source_files"][0]
        source_entry["path"] = str(outside)
        source_entry["sha256"] = hashlib.sha256(b"ANCHOR\n").hexdigest()
        self._write_review(review)

        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("source entry path" in error for error in errors))

    def test_source_symlink_outside_root_fails_closed(self) -> None:
        outside = self.root / "outside.py"
        outside.write_text("ANCHOR\n", encoding="utf-8")
        symlink = self.source_root / "src" / "link.py"
        os.symlink(outside, symlink)
        review = self._load_review()
        source_entry = review["source_files"][0]
        source_entry["path"] = "src/link.py"
        source_entry["sha256"] = hashlib.sha256(b"ANCHOR\n").hexdigest()
        self._write_review(review)

        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("resolves outside" in error for error in errors))

    def test_planning_document_paths_stay_under_repo_root(self) -> None:
        outside = self.root / "outside.md"
        outside.write_text("synthetic planning document\n", encoding="utf-8")
        link = self.repo_root / "link.md"
        os.symlink(outside, link)
        review = self._load_review()
        review["planning_docs"] = ["../outside.md"]
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("planning document path" in error for error in errors))

        review["planning_docs"] = ["link.md"]
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("resolves outside" in error for error in errors))

    def test_exact_coverage_and_required_metadata_are_frozen(self) -> None:
        review = self._load_review()
        mutations = {
            "format_version": (2, "format_version"),
            "operation": ("P0-99", "operation"),
            "purpose": ("mutated purpose", "purpose"),
            "deferred": ([], "deferred"),
            "planning_docs": ([], "planning_docs"),
            "source_files": ([], "source_files"),
        }
        for field, (value, fragment) in mutations.items():
            mutated = self._load_review()
            mutated[field] = value
            self._write_review(mutated)
            full_errors, docs_errors = self._validate_both_modes()
            for errors in (full_errors, docs_errors):
                self.assertTrue(any(fragment in error for error in errors), field)
        self._write_review(review)

        mutated = self._load_review()
        mutated["source_files"] = [{"path": ".git/HEAD"}]
        self._write_review(mutated)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("source_files" in error for error in errors))

    def test_markdown_substring_decoy_fails_closed(self) -> None:
        (self.repo_root / "README.md").write_text(
            "source-audit/planning-reconciliation/planning_review.json\n",
            encoding="utf-8",
        )
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("Markdown link target" in error for error in errors))

    def test_fenced_code_link_decoy_fails_full_mode(self) -> None:
        (self.repo_root / "README.md").write_text(
            "```markdown\n[decoy](README.md)\n```\n",
            encoding="utf-8",
        )
        errors = self._validate()
        self.assertTrue(any("Markdown link target" in error for error in errors))

    def test_fenced_code_link_decoy_fails_docs_only_mode(self) -> None:
        (self.repo_root / "README.md").write_text(
            "~~~markdown\n[decoy](README.md)\n~~~\n",
            encoding="utf-8",
        )
        _full_errors, docs_errors = self._validate_both_modes()
        self.assertTrue(any("Markdown link target" in error for error in docs_errors))

    def test_html_comment_link_decoy_fails_full_mode(self) -> None:
        (self.repo_root / "README.md").write_text(
            "<!-- [decoy](README.md) -->\n",
            encoding="utf-8",
        )
        errors = self._validate()
        self.assertTrue(any("Markdown link target" in error for error in errors))

    def test_html_comment_link_decoy_fails_docs_only_mode(self) -> None:
        (self.repo_root / "README.md").write_text(
            "<!--\n[decoy](README.md)\n-->\n",
            encoding="utf-8",
        )
        _full_errors, docs_errors = self._validate_both_modes()
        self.assertTrue(any("Markdown link target" in error for error in docs_errors))

    def test_missing_anchor_fails_closed(self) -> None:
        with mock.patch.object(validate, "_git_blob", return_value=b"OTHER\n"):
            errors = self._validate()
        self.assertTrue(any("missing source anchor" in error for error in errors))

    def test_invalid_utf8_source_blob_fails_closed(self) -> None:
        with mock.patch.object(validate, "_git_blob", return_value=b"\xff\xfe"):
            errors = self._validate()
        self.assertTrue(any("cannot decode pinned source blob" in error for error in errors))

    def test_missing_promisor_blob_is_structured(self) -> None:
        with mock.patch.object(validate, "_git_blob", return_value=None):
            errors = self._validate()
        self.assertTrue(errors)
        self.assertTrue(all(isinstance(error, str) for error in errors))
        self.assertTrue(any("missing pinned source blob" in error for error in errors))

    def test_forbidden_source_field_fails_closed(self) -> None:
        with mock.patch.object(
            validate, "_git_blob", return_value=b"ANCHOR\nFORBIDDEN_FIELD\n"
        ):
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

    def test_invalid_utf8_review_fails_closed(self) -> None:
        self.review_path.write_bytes(b"\xff\xfe")
        errors, head, _duration = validate.validate_review(
            self.repo_root, self.review_path, self.source_root
        )
        self.assertIsNone(head)
        self.assertTrue(any("cannot read review record" in error for error in errors))

    def test_invalid_utf8_markdown_fails_closed(self) -> None:
        (self.repo_root / "README.md").write_bytes(b"\xff\xfe")
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("cannot read required-link document" in error for error in errors))

    def test_null_and_wrong_type_collections_fail_without_traceback(self) -> None:
        for field, value in (
            ("planning_docs", None),
            ("required_links", {"path": "README.md"}),
            ("source_files", None),
            ("claims", {"id": "synthetic-claim"}),
        ):
            review = self._load_review()
            review[field] = value
            self._write_review(review)
            full_errors, docs_errors = self._validate_both_modes()
            self.assertTrue(full_errors, field)
            self.assertTrue(docs_errors, field)
            self.assertTrue(all(isinstance(error, str) for error in full_errors), field)
            self.assertTrue(all(isinstance(error, str) for error in docs_errors), field)

    def test_unexpected_cli_error_is_structured(self) -> None:
        output = io.StringIO()
        with mock.patch.object(validate, "validate_review", side_effect=RuntimeError("boom")):
            with mock.patch("sys.stdout", output):
                code = validate.main(["--check-docs-only"])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertFalse(result["ok"])
        self.assertTrue(any("unexpected validation error" in error for error in result["errors"]))

    def test_required_links_are_required_and_frozen(self) -> None:
        review = self._load_review()
        review.pop("required_links")
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("required_links is required" in error for error in errors))

        review["required_links"] = validate.EXPECTED_REQUIRED_LINKS[:-1]
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("exact expected links" in error for error in errors))

        review["required_links"] = validate.EXPECTED_REQUIRED_LINKS
        self._write_review(review)
        (self.repo_root / "README.md").write_text(
            "[decoy](README.txt)\n", encoding="utf-8"
        )
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("Markdown link target" in error for error in errors))
        (self.repo_root / "README.md").write_text(
            "[synthetic planning document](README.md)\n", encoding="utf-8"
        )

    def test_claims_are_required_and_content_is_frozen(self) -> None:
        review = self._load_review()
        review.pop("claims")
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("claims is required" in error for error in errors))

        review["claims"] = []
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("claims must be a non-empty list" in error for error in errors))

        review["claims"] = json.loads(json.dumps(validate.EXPECTED_CLAIMS))
        review["claims"][0]["status"] = "forbidden"
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("disallowed status" in error for error in errors))
            self.assertTrue(any("content does not match" in error for error in errors))

        review["claims"] = json.loads(json.dumps(validate.EXPECTED_CLAIMS))
        review["claims"][0]["source_files"] = ["missing.py"]
        review["claims"][0]["docs"] = ["missing.md"]
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("excluded source record" in error for error in errors))
            self.assertTrue(any("excluded planning document" in error for error in errors))

        review["claims"] = json.loads(json.dumps(validate.EXPECTED_CLAIMS))
        review["claims"][0]["evidence"] = []
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("evidence must be a non-empty list" in error for error in errors))

        review["claims"] = json.loads(json.dumps(validate.EXPECTED_CLAIMS))
        review["claims"][0]["evidence"][0]["sha256"] = "0" * 64
        review["claims"][0]["evidence"][0]["anchors"] = ["missing-anchor"]
        self._write_review(review)
        full_errors, docs_errors = self._validate_both_modes()
        for errors in (full_errors, docs_errors):
            self.assertTrue(any("evidence digest" in error for error in errors))
            self.assertTrue(any("evidence anchors" in error for error in errors))

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
        self.assertEqual(review["required_links"], validate.EXPECTED_REQUIRED_LINKS)
        self.assertEqual(review["claims"], validate.EXPECTED_CLAIMS)
        web_server = next(
            entry for entry in review["source_files"] if entry["path"] == "hermes_cli/web_server.py"
        )
        self.assertEqual(web_server["absent"], ["hermes_source_sha"])
        self.assertEqual(web_server["exceptions"][0]["status"], "blocked")
        self.assertEqual(web_server["exceptions"][0]["route"], "/api/ssh/ownership")


if __name__ == "__main__":
    unittest.main()
