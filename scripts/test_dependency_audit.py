#!/usr/bin/env python3
"""Focused offline tests for the web dependency inventory.

The first tests read the checked-in manifest and lockfile. Mutation tests then
prove that the same audit fails closed for an unpinned declaration, missing
integrity, malformed bytes, and unsupported command input. No test contacts a
package registry, vulnerability service, Hermes, Paper, or a live proxy.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dependency_audit.py"
MANIFEST = ROOT / "apps" / "web" / "package.json"
LOCKFILE = ROOT / "apps" / "web" / "bun.lock"

spec = importlib.util.spec_from_file_location("dependency_audit", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


INTEGRITY = "sha512-" + ("A" * 86) + "=="


def synthetic_lock(
    dependencies: dict[str, str],
    dev_dependencies: dict[str, str],
    packages: dict[str, list[Any]],
) -> bytes:
    document = {
        "lockfileVersion": 1,
        "configVersion": 1,
        "workspaces": {
            "": {
                "name": "@fixture/web",
                "dependencies": dependencies,
                "devDependencies": dev_dependencies,
            }
        },
        "packages": packages,
    }
    return json.dumps(document, sort_keys=True).encode("utf-8")


def package_record(name: str, version: str, metadata: dict[str, Any] | None = None) -> list[Any]:
    return [f"{name}@{version}", "", metadata or {}, INTEGRITY]


class DependencyAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest_bytes = MANIFEST.read_bytes()
        cls.lockfile_bytes = LOCKFILE.read_bytes()
        cls.manifest = json.loads(cls.manifest_bytes)

    def real_result(self) -> dict[str, Any]:
        return audit.audit_bytes(
            self.manifest_bytes,
            self.lockfile_bytes,
            manifest_label="apps/web/package.json",
            lockfile_label="apps/web/bun.lock",
        )

    @staticmethod
    def finding_codes(result: dict[str, Any]) -> set[str]:
        return {str(item["code"]) for item in result["findings"]}

    def test_checked_in_web_inventory_is_real_and_complete(self) -> None:
        result = self.real_result()
        self.assertTrue(result["completed"], result)
        self.assertEqual(result["status"], "review", result)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["summary"]["direct_runtime"], 2, result)
        self.assertEqual(result["summary"]["direct_dev"], 16, result)
        self.assertEqual(result["summary"]["locked"], 199, result)
        self.assertEqual(result["summary"]["transitive"], 181, result)
        self.assertEqual(result["lockfile"]["integrity_missing"], [], result)
        self.assertEqual(result["lockfile"]["integrity_invalid"], [], result)
        self.assertEqual(result["lockfile"]["unpinned"], [], result)
        self.assertEqual(result["lockfile"]["unreachable"], [], result)
        self.assertFalse(any(item["severity"] == "blocking" for item in result["findings"]), result)

    def test_terminal_packages_are_pinned_web_runtime_entries(self) -> None:
        result = self.real_result()
        boundary = result["terminal_boundary"]
        self.assertEqual(boundary["boundary"], "web-only-terminal", result)
        self.assertEqual(boundary["assessment"], "pinned_web_runtime", result)
        self.assertEqual(boundary["transitive_support"], {"@wterm/core": True}, result)
        for name in ("@wterm/dom", "@wterm/ghostty"):
            package = boundary["packages"][name]
            self.assertTrue(package["declared"], result)
            self.assertTrue(package["web_runtime"], result)
            self.assertTrue(package["integrity_present"], result)
            self.assertEqual(package["requested"], "0.3.2", result)
            self.assertEqual(package["resolved_version"], "0.3.2", result)

    def test_current_review_gaps_are_not_online_claims(self) -> None:
        result = self.real_result()
        codes = self.finding_codes(result)
        self.assertIn("license-review-metadata-missing", codes, result)
        self.assertIn("privacy-review-metadata-missing", codes, result)
        self.assertIn("terminal-runtime-proof-not-inventory-scope", codes, result)
        self.assertEqual(result["online_vulnerability_scan"], "not_run", result)
        self.assertEqual(result["claims"], {"vulnerabilities": "none", "online_cve_audit": "not_run"}, result)
        self.assertFalse(any("CVE" in json.dumps(item) for item in result["findings"]), result)

    def test_report_is_deterministic_and_sorted(self) -> None:
        first = self.real_result()
        second = self.real_result()
        self.assertEqual(first, second)
        encoded = audit._serialise(first)
        self.assertEqual(encoded, audit._serialise(second))
        self.assertLessEqual(len(encoded.encode("utf-8")), audit.MAX_OUTPUT_BYTES)
        self.assertEqual(first["inventory"]["transitive"], sorted(first["inventory"]["transitive"], key=lambda item: item["name"]))

    def test_output_limit_is_nonzero_and_deterministic(self) -> None:
        result = self.real_result()
        outputs: list[str] = []
        statuses: list[int] = []
        with patch.object(audit, "MAX_OUTPUT_BYTES", 1), patch.object(audit, "audit_files", return_value=result):
            for _ in range(2):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    statuses.append(audit.main([]))
                outputs.append(stream.getvalue())
        self.assertEqual(statuses, [1, 1], outputs)
        self.assertEqual(outputs[0], outputs[1], outputs)
        report = json.loads(outputs[0])
        self.assertEqual(report["status"], "fail", report)
        self.assertEqual(report["findings"][0]["code"], "output-too-large", report)

    def test_cli_emits_one_sanitized_json_object(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), str(MANIFEST), str(LOCKFILE)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), 1, completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "review", result)
        self.assertNotIn(str(ROOT), completed.stdout)
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)

    def test_unpinned_manifest_spec_is_blocking(self) -> None:
        mutated = json.loads(self.manifest_bytes)
        mutated["dependencies"]["@wterm/dom"] = "^0.3.2"
        result = audit.audit_bytes(json.dumps(mutated).encode("utf-8"), self.lockfile_bytes)
        self.assertEqual(result["status"], "fail", result)
        self.assertFalse(result["ok"], result)
        self.assertIn("manifest-unpinned", self.finding_codes(result), result)

    def test_missing_integrity_is_blocking(self) -> None:
        mutated = re.sub(rb', "sha512-[^"]+"(?=\])', b"", self.lockfile_bytes, count=1)
        self.assertNotEqual(mutated, self.lockfile_bytes)
        result = audit.audit_bytes(self.manifest_bytes, mutated)
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("missing-integrity", self.finding_codes(result), result)
        self.assertGreaterEqual(len(result["lockfile"]["integrity_missing"]), 1, result)

    def test_config_version_is_shape_checked_before_output(self) -> None:
        lock_document = json.loads(synthetic_lock({"alpha": "1.0.0"}, {}, {"alpha": package_record("alpha", "1.0.0")}))
        lock_document["configVersion"] = {"unexpected": "object"}
        result = audit.audit_bytes(
            json.dumps({"name": "@fixture/web", "dependencies": {"alpha": "1.0.0"}, "devDependencies": {}}).encode("utf-8"),
            json.dumps(lock_document).encode("utf-8"),
            manifest_label="fixture/package.json",
            lockfile_label="fixture/bun.lock",
        )
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("invalid-config-version", self.finding_codes(result), result)
        self.assertIsNone(result["lockfile"]["config_version"], result)

    def test_invalid_integrity_is_blocking_and_sanitized(self) -> None:
        mutated = re.sub(
            rb', "sha512-[^"]+"(?=\])',
            rb', "bad\\u0000integrity"',
            self.lockfile_bytes,
            count=1,
        )
        self.assertNotEqual(mutated, self.lockfile_bytes)
        result = audit.audit_bytes(self.manifest_bytes, mutated)
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("invalid-integrity", self.finding_codes(result), result)
        encoded = audit._serialise(result)
        self.assertNotIn("\\u0000", encoded)

    def test_integrity_digest_length_is_enforced(self) -> None:
        short_sha512 = ("sha512-" + ("A" * 43) + "=").encode("ascii")
        mutated = re.sub(
            rb', "sha512-[^"]+"(?=\])',
            b', "' + short_sha512 + b'"',
            self.lockfile_bytes,
            count=1,
        )
        self.assertNotEqual(mutated, self.lockfile_bytes)
        result = audit.audit_bytes(self.manifest_bytes, mutated)
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("invalid-integrity", self.finding_codes(result), result)
        self.assertGreaterEqual(len(result["lockfile"]["integrity_invalid"]), 1, result)

    def test_transitive_dependency_is_inventoried_from_local_graph(self) -> None:
        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record("alpha", "1.0.0", {"dependencies": {"beta": "^2.0.0"}}),
                "beta": package_record("beta", "2.1.0"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        self.assertTrue(result["completed"], result)
        self.assertIn("beta", {item["name"] for item in result["inventory"]["transitive"]}, result)
        self.assertEqual(result["summary"]["transitive"], 1, result)

    def test_unsatisfied_transitive_and_peer_resolution_is_blocking(self) -> None:
        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record(
                    "alpha",
                    "1.0.0",
                    {
                        "dependencies": {"beta": "^2.0.0"},
                        "peerDependencies": {"peer": "workspace:*"},
                    },
                ),
                "beta": package_record("beta", "1.0.0"),
                "peer": package_record("peer", "1.0.0"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        self.assertEqual(result["status"], "fail", result)
        blocking = [item for item in result["findings"] if item["severity"] == "blocking"]
        self.assertEqual(
            {(item["code"], item.get("package")) for item in blocking},
            {("package-resolution-missing", "beta"), ("package-resolution-missing", "peer")},
            result,
        )
        self.assertEqual(
            result["lockfile"]["peer_dependency_gaps"],
            [
                {
                    "package": "alpha",
                    "dependency": "peer",
                    "optional": False,
                    "status": "package-resolution-missing",
                }
            ],
            result,
        )

    def test_npm_alias_binds_target_identity_and_version(self) -> None:
        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alias": "npm:target@1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        lockfile = synthetic_lock(
            {"alias": "npm:target@1.0.0"},
            {},
            {
                "alias": package_record("other", "1.0.0"),
                "target": package_record("target", "1.0.0"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("package-resolution-missing", self.finding_codes(result), result)
        self.assertEqual(result["inventory"]["direct"]["runtime"][0]["resolution"], "missing", result)

    def test_root_optional_dependencies_are_inventoried_and_pinned(self) -> None:
        manifest_document = {
            "name": "@fixture/web",
            "dependencies": {},
            "devDependencies": {},
            "optionalDependencies": {"optional": "^1.0.0"},
        }
        lock_document = json.loads(synthetic_lock({}, {}, {"optional": package_record("optional", "1.0.0")}))
        lock_document["workspaces"][""]["optionalDependencies"] = {"optional": "^1.0.0"}
        result = audit.audit_bytes(
            json.dumps(manifest_document).encode("utf-8"),
            json.dumps(lock_document).encode("utf-8"),
            manifest_label="fixture/package.json",
            lockfile_label="fixture/bun.lock",
        )
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("manifest-unpinned", self.finding_codes(result), result)
        self.assertEqual(result["summary"]["direct_optional"], 1, result)
        self.assertEqual(result["inventory"]["direct"]["optional"][0]["name"], "optional", result)
        self.assertFalse(result["inventory"]["direct"]["optional"][0]["pinned"], result)

    def test_json5_virtual_records_are_supported_by_real_lockfile(self) -> None:
        result = self.real_result()
        names = {item["name"] for item in result["inventory"]["transitive"]}
        self.assertIn("@testing-library/dom/aria-query", names, result)
        self.assertIn("data-urls/whatwg-url", names, result)
        self.assertEqual(result["status"], "review", result)

    def test_invalid_and_oversized_inputs_fail_closed(self) -> None:
        invalid = audit.audit_bytes(b"{\xff", self.lockfile_bytes)
        self.assertEqual(invalid["status"], "fail", invalid)
        self.assertIn("manifest-invalid-utf8", self.finding_codes(invalid), invalid)
        oversized = audit.audit_bytes(b"{}" + b"x" * audit.MAX_INPUT_BYTES, self.lockfile_bytes)
        self.assertEqual(oversized["status"], "fail", oversized)
        self.assertIn("manifest-too-large", self.finding_codes(oversized), oversized)

    def test_file_inputs_reject_repository_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            link = Path(directory) / "package.json"
            link.symlink_to(MANIFEST)
            result = audit.audit_files(link, LOCKFILE)
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("manifest-path-invalid", self.finding_codes(result), result)

    def test_file_inputs_reject_special_files_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fifo = Path(directory) / "manifest.fifo"
            os.mkfifo(fifo)
            started = time.monotonic()
            result = audit.audit_files(fifo, LOCKFILE)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0, result)
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("manifest-not-regular", self.finding_codes(result), result)

    def test_unknown_cli_argument_has_stable_json_failure(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--unexpected"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), 1, completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual(result["findings"][0]["code"], "cli-error", result)
        self.assertNotIn("usage:", completed.stdout.lower())
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)


if __name__ == "__main__":
    raise SystemExit(unittest.main(verbosity=2))
