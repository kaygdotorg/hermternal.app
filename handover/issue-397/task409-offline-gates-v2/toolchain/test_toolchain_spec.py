#!/usr/bin/env python3
"""Static tests for the authenticated offline toolchain specification."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ToolchainSpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((HERE / "staging-manifest.json").read_text(encoding="utf-8"))

    def test_build_output_is_exactly_pinned(self) -> None:
        self.assertEqual(self.manifest["status"], "authenticated-inputs")
        output = self.manifest["image_output"]
        self.assertEqual(output["image"], "localhost/hermternal-offline-gates:issue-406-v1")
        self.assertRegex(output["image_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(output["repo_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(output["status"], "verified-local-build")

    def test_runtime_contract_is_offline_and_read_only(self) -> None:
        contract = self.manifest["runtime_contract"]
        self.assertEqual(contract["network"], "none")
        self.assertEqual(contract["pull"], "never")
        self.assertEqual(contract["repository_mount"], "read-only")
        self.assertEqual(len(contract["tmpfs"]), len(set(contract["tmpfs"])))
        self.assertIn("/workspace/apps/web/node_modules", contract["tmpfs"])

    def test_package_manifest_is_closed(self) -> None:
        with (HERE / "debian-packages.tsv").open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source, delimiter="\t"))
        self.assertEqual(len(rows), self.manifest["debian"]["package_count"])
        self.assertEqual(len(rows), len({(row["package"], row["version"], row["architecture"]) for row in rows}))
        self.assertTrue(all(SHA256.fullmatch(row["sha256"]) for row in rows))
        self.assertTrue(all(row["architecture"] in {"all", "amd64"} for row in rows))

    def test_containerfile_has_no_fetch_instruction(self) -> None:
        text = (HERE / "Containerfile").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("FROM docker.io/library/node@sha256:"))
        self.assertNotRegex(text, r"(?im)^\s*RUN\s+.*\b(?:apt-get update|curl|wget|bun install|npm install|npx)\b")
        for value in (self.manifest["bun"]["archive"]["sha256"], self.manifest["playwright"]["headless_shell_archive"]["sha256"], self.manifest["dependencies"]["tree"]["sha256"]):
            self.assertIn(value, text)

    def test_final_verifier_requires_repo_digest(self) -> None:
        text = (HERE / "verify_staging.py").read_text(encoding="utf-8")
        self.assertIn('require((image is None) == (repo_digest is None)', text)
        self.assertIn('f"{repository}@{repo_digest}" in value.get("RepoDigests", [])', text)
        self.assertIn('value.get("Id", "")', text)


if __name__ == "__main__":
    unittest.main()
