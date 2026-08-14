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
GIT_PACKAGES = (
    "git", "git-man", "libcurl3t64-gnutls", "liberror-perl",
    "libgdbm-compat4t64", "libgdbm6t64", "libldap2", "libnghttp2-14",
    "libnghttp3-9", "libngtcp2-16", "libngtcp2-crypto-gnutls8",
    "libperl5.40", "libpsl5t64", "librtmp1", "libsasl2-2",
    "libsasl2-modules-db", "libssh2-1t64", "perl", "perl-modules-5.40",
)


class ToolchainSpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((HERE / "staging-manifest.json").read_text(encoding="utf-8"))

    def test_build_output_is_exactly_pinned(self) -> None:
        self.assertEqual(self.manifest["status"], "authenticated-inputs")
        output = self.manifest["image_output"]
        self.assertEqual(output["image"], "localhost/hermternal-offline-gates:issue-406-v6")
        self.assertRegex(output["image_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(output["repo_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(output["status"], "verified-local-build")

    def test_runtime_contract_is_offline_and_read_only(self) -> None:
        contract = self.manifest["runtime_contract"]
        self.assertEqual(contract["network"], "none")
        self.assertEqual(contract["pull"], "never")
        self.assertEqual(contract["container_user"], "1001:1001")
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

    def test_git_package_closure_is_exact(self) -> None:
        with (HERE / "debian-packages.tsv").open(newline="", encoding="utf-8") as source:
            rows = {row["package"]: row for row in csv.DictReader(source, delimiter="\t")}
        git = self.manifest["git"]
        self.assertEqual(tuple(git["packages"]), GIT_PACKAGES)
        self.assertEqual(git["version"], "2.47.3")
        self.assertEqual(git["debian_version"], "1:2.47.3-0+deb13u1")
        self.assertEqual(rows["git"]["version"], git["debian_version"])
        self.assertTrue(all(name in rows and SHA256.fullmatch(rows[name]["sha256"]) for name in GIT_PACKAGES))

    def test_python_runtime_is_exact_and_closed(self) -> None:
        python = self.manifest["python"]
        self.assertEqual(python["executable_path"], "/usr/bin/python3")
        self.assertEqual(python["source_path"], "/usr/bin/python3.13")
        self.assertEqual(python["canonical_path"], "/usr/bin/python3")
        self.assertEqual(python["selector_expected"], "/usr/bin/python3")
        self.assertEqual(python["executable_nlink"], 1)
        self.assertRegex(python["canonical_sha256"], SHA256)
        self.assertEqual(python["source_sha256"], python["canonical_sha256"])
        self.assertEqual(python["source_bytes"], python["canonical_bytes"])
        self.assertEqual(python["version"], "3.13.5")
        self.assertIn("python3", python["packages"])
        self.assertIn("python3-minimal", python["packages"])
        self.assertEqual(len(python["packages"]), len(set(python["packages"])))

    def test_playwright_selection_is_bound_to_the_owned_full_browser(self) -> None:
        playwright = self.manifest["playwright"]
        self.assertEqual(playwright["selected_executable"], playwright["chromium"]["executable_path"])
        verifier = (HERE / "verify_staging.py").read_text(encoding="utf-8")
        self.assertIn("chromium.executablePath()", verifier)

    def test_chromium_executable_has_exact_image_provenance(self) -> None:
        chromium = self.manifest["playwright"]["chromium"]
        self.assertEqual(chromium["executable_path"], "/ms-playwright/chromium-1234/chrome-linux64/chrome")
        self.assertEqual(chromium["uid"], 1001)
        self.assertEqual(chromium["gid"], 1001)
        self.assertEqual(chromium["mode"], "0755")
        self.assertRegex(chromium["executable_sha256"], SHA256)

    def test_bun_cache_is_bound_to_the_frozen_lockfile(self) -> None:
        cache = self.manifest["bun"]["cache"]
        self.assertEqual(cache["path"], "bun/image-cache")
        self.assertEqual(cache["image_path"], "/usr/local/install/cache")
        self.assertEqual(cache["source_commit"], "d36d68ab795608d2c96db0bcfe1d213e64081103")
        self.assertEqual(cache["source_lock_sha256"], self.manifest["dependencies"]["source"]["bun.lock"])
        self.assertRegex(cache["tree"]["sha256"], SHA256)

        verifier = (HERE / "verify_staging.py").read_text(encoding="utf-8")
        self.assertIn("bun install --silent --frozen-lockfile --ignore-scripts --prefer-offline", verifier)
        self.assertIn('--cache-dir="$PWD/cache" --registry=http://127.0.0.1:1', verifier)
        self.assertIn('cp -a /usr/local/install/cache/. cache-probe/cache/', verifier)

    def test_containerfile_has_no_fetch_instruction(self) -> None:
        text = (HERE / "Containerfile").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("FROM docker.io/library/node@sha256:"))
        self.assertNotRegex(text, r"(?im)^\s*RUN\s+.*\b(?:apt-get update|curl|wget|bun install|npm install|npx)\b")
        for value in (self.manifest["bun"]["archive"]["sha256"], self.manifest["playwright"]["headless_shell_archive"]["sha256"], self.manifest["dependencies"]["tree"]["sha256"]):
            self.assertIn(value, text)
        self.assertIn('org.hermternal.git="2.47.3"', text)
        self.assertIn('test "$(git --version)" = "git version 2.47.3"', text)
        self.assertIn('test "$(python3 --version)" = "Python 3.13.5"', text)
        self.assertIn("cp --remove-destination /usr/bin/python3.13 /usr/bin/python3", text)
        self.assertIn("USER 1001:1001", text)
        self.assertIn("COPY --chown=1001:1001 browser/chrome-linux64/ /ms-playwright/chromium-1234/chrome-linux64/", text)
        self.assertIn("COPY --chown=1001:1001 bun/image-cache/ /usr/local/install/cache/", text)

    def test_final_verifier_requires_repo_digest(self) -> None:
        text = (HERE / "verify_staging.py").read_text(encoding="utf-8")
        self.assertIn('require((image is None) == (repo_digest is None)', text)
        self.assertIn('f"{repository}@{repo_digest}" in value.get("RepoDigests", [])', text)
        self.assertIn('value.get("Id", "")', text)
        self.assertIn('get("User") == manifest["runtime_contract"]["container_user"]', text)

    def test_final_verifier_executes_offline_git_smoke(self) -> None:
        text = (HERE / "verify_staging.py").read_text(encoding="utf-8")
        self.assertIn('"--pull=never", "--network=none"', text)
        self.assertIn('"dpkg-query", "--show"', text)
        self.assertIn('type=tmpfs,dst=/tmp,tmpfs-size=805306368,tmpfs-mode=0700,U=true', text)
        self.assertIn('git -C repo archive HEAD | tar -tf -', text)
        self.assertIn('chrome-headless-shell --version', text)


if __name__ == "__main__":
    unittest.main()
