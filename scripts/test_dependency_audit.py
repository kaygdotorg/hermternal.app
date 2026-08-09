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
import shutil
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


def npm_semver_satisfies(version: str, specification: str) -> bool | None:
    """Use a locally installed npm semver package as an optional test oracle."""

    node = shutil.which("node")
    npm = shutil.which("npm")
    if node is None or npm is None:
        return None
    roots = [ROOT / "node_modules"]
    try:
        global_root = Path(
            subprocess.check_output([npm, "root", "-g"], text=True, stderr=subprocess.DEVNULL).strip()
        )
    except (OSError, subprocess.CalledProcessError, ValueError):
        global_root = None
    if global_root is not None:
        roots.extend((global_root, global_root / "npm" / "node_modules"))
    module_roots = [root for root in roots if (root / "semver").is_dir()]
    if not module_roots:
        return None
    script = (
        "const semver = require('semver'); "
        "process.stdout.write(String(semver.satisfies(process.argv[1], process.argv[2])));"
    )
    environment = os.environ.copy()
    environment["NODE_PATH"] = os.pathsep.join(str(root) for root in module_roots)
    try:
        completed = subprocess.run(
            [node, "-e", script, version, specification],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
    except OSError:
        return None
    if completed.returncode != 0 or completed.stdout.strip() not in {"true", "false"}:
        return None
    return completed.stdout.strip() == "true"


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
        self.assertEqual(result["lockfile"]["dependency_edges"], 292, result)
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
        self.assertEqual(
            result["claims"],
            {"vulnerabilities": "not_assessed_offline", "online_cve_audit": "not_run"},
            result,
        )
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

    def test_lockfile_version_requires_exact_integer_one(self) -> None:
        manifest = json.dumps({"name": "@fixture/web", "dependencies": {}, "devDependencies": {}}).encode("utf-8")
        for invalid_version in (True, 1.0):
            lock_document = json.loads(synthetic_lock({}, {}, {}))
            lock_document["lockfileVersion"] = invalid_version
            result = audit.audit_bytes(
                manifest,
                json.dumps(lock_document).encode("utf-8"),
                manifest_label="fixture/package.json",
                lockfile_label="fixture/bun.lock",
            )
            self.assertEqual(result["status"], "fail", (invalid_version, result))
            self.assertIn("unsupported-lock-version", self.finding_codes(result), (invalid_version, result))
            self.assertIsNone(result["lockfile"]["lockfile_version"], (invalid_version, result))

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

    def test_optional_dependency_specs_are_sanitized_in_lock_output(self) -> None:
        unsafe_spec = '^1.0.0\n"raw-optional-spec'
        manifest_document = {
            "name": "@fixture/web",
            "dependencies": {},
            "devDependencies": {},
            "optionalDependencies": {"optional": unsafe_spec},
        }
        lock_document = json.loads(synthetic_lock({}, {}, {"optional": package_record("optional", "1.0.0")}))
        lock_document["workspaces"][""]["optionalDependencies"] = {"optional": unsafe_spec}
        result = audit.audit_bytes(
            json.dumps(manifest_document).encode("utf-8"),
            json.dumps(lock_document).encode("utf-8"),
            manifest_label="fixture/package.json",
            lockfile_label="fixture/bun.lock",
        )
        expected = audit._safe_token(unsafe_spec, max_length=audit.MAX_SPEC_LENGTH)
        self.assertEqual(result["lockfile"]["optional_dependencies"], {"optional": expected}, result)
        self.assertNotIn(unsafe_spec, json.dumps(result, sort_keys=True), result)

    def test_edge_budget_counts_unreachable_lock_graph_edges(self) -> None:
        manifest = json.dumps(
            {"name": "@fixture/web", "dependencies": {"alpha": "1.0.0"}, "devDependencies": {}}
        ).encode("utf-8")
        lock_document = json.loads(
            synthetic_lock(
                {"alpha": "1.0.0"},
                {},
                {
                    "alpha": package_record("alpha", "1.0.0"),
                    "orphan": package_record("orphan", "1.0.0", {"dependencies": {"child": "1.0.0"}}),
                    "child": package_record("child", "1.0.0"),
                },
            )
        )
        with patch.object(audit, "MAX_DEPENDENCY_EDGES", 0):
            result = audit.audit_bytes(
                manifest,
                json.dumps(lock_document).encode("utf-8"),
                manifest_label="fixture/package.json",
                lockfile_label="fixture/bun.lock",
            )
        self.assertEqual(result["status"], "fail", result)
        self.assertIn("dependency-edge-limit", self.finding_codes(result), result)

    def test_broader_bun_json5_forms_fail_with_explicit_reason(self) -> None:
        manifest = json.dumps({"name": "@fixture/web", "dependencies": {}, "devDependencies": {}}).encode("utf-8")
        standard_lock = synthetic_lock({}, {}, {})
        variants = (
            standard_lock.replace(b'"lockfileVersion"', b"lockfileVersion", 1),
            standard_lock.replace(b'"lockfileVersion"', b"'lockfileVersion'", 1),
            standard_lock.replace(b'"configVersion": 1', b'"configVersion": 1.', 1),
        )
        for lockfile in variants:
            result = audit.audit_bytes(
                manifest,
                lockfile,
                manifest_label="fixture/package.json",
                lockfile_label="fixture/bun.lock",
            )
            codes = self.finding_codes(result)
            self.assertEqual(result["status"], "fail", result)
            self.assertIn("lockfile-json5-unsupported", codes, result)
            if b'"configVersion": 1.' in lockfile:
                self.assertNotIn("lockfile-json-invalid", codes, result)

    def test_comparator_partial_operands_expand_and_reject(self) -> None:
        cases = (
            ("1.2.3", ">1", False),
            ("1.2.3", ">1.2.x", False),
            ("1.2.3", ">*", False),
            ("0.9.9", "<1", True),
            ("1.1.9", "<1.2.x", True),
            ("1.5.0", "<=1", True),
            ("1.2.5", "<=1.2.x", True),
            ("1.2.3", ">=1", True),
            ("1.2.3", ">=1.2.x", True),
        )
        oracle = [npm_semver_satisfies(version, specification) for version, specification, _ in cases]
        if all(value is not None for value in oracle):
            self.assertEqual(oracle, [expected for _, _, expected in cases])
        self.assertEqual(
            [audit._range_matches(version, specification) for version, specification, _ in cases],
            [expected for _, _, expected in cases],
        )

        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        metadata = {
            "dependencies": {
                "gt-major": ">1",
                "gt-minor": ">1.2.x",
                "gt-wildcard": ">*",
                "lt-major": "<1",
                "lt-minor": "<1.2.x",
                "le-major": "<=1",
                "le-minor": "<=1.2.x",
                "ge-major": ">=1",
                "ge-minor": ">=1.2.x",
            },
            "peerDependencies": {"required-peer": ">=1.2.x"},
        }
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record("alpha", "1.0.0", metadata),
                "gt-major": package_record("gt-major", "1.2.3"),
                "gt-minor": package_record("gt-minor", "1.2.3"),
                "gt-wildcard": package_record("gt-wildcard", "1.2.3"),
                "lt-major": package_record("lt-major", "0.9.9"),
                "lt-minor": package_record("lt-minor", "1.1.9"),
                "le-major": package_record("le-major", "1.5.0"),
                "le-minor": package_record("le-minor", "1.2.5"),
                "ge-major": package_record("ge-major", "1.2.3"),
                "ge-minor": package_record("ge-minor", "1.2.3"),
                "required-peer": package_record("required-peer", "1.2.3"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        blocking = {
            item.get("package")
            for item in result["findings"]
            if item["severity"] == "blocking" and item["code"] == "package-resolution-missing"
        }
        self.assertEqual(blocking, {"gt-major", "gt-minor", "gt-wildcard"}, result)
        self.assertEqual(result["lockfile"]["peer_dependency_gaps"], [], result)

    def test_tilde_wildcard_ranges_match_npm_wildcard_semantics(self) -> None:
        cases = (
            ("1.2.3", "~*"),
            ("1.2.3", "~x"),
            ("1.2.3", "~X"),
        )
        oracle = [npm_semver_satisfies(version, specification) for version, specification in cases]
        if all(value is not None for value in oracle):
            self.assertEqual(oracle, [True, True, True])
        self.assertEqual([audit._range_matches(version, specification) for version, specification in cases], [True, True, True])

        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        metadata = {
            "dependencies": {
                "tilde-star": "~*",
                "tilde-x": "~x",
                "tilde-X": "~X",
            },
            "peerDependencies": {"required-peer-tilde": "~*"},
        }
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record("alpha", "1.0.0", metadata),
                "tilde-star": package_record("tilde-star", "1.2.3"),
                "tilde-x": package_record("tilde-x", "1.2.3"),
                "tilde-X": package_record("tilde-X", "1.2.3"),
                "required-peer-tilde": package_record("required-peer-tilde", "1.2.3"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        self.assertEqual(result["status"], "review", result)
        self.assertEqual(result["lockfile"]["peer_dependency_gaps"], [], result)
        self.assertEqual(
            {item["name"] for item in result["inventory"]["transitive"]},
            {"tilde-star", "tilde-x", "tilde-X", "required-peer-tilde"},
            result,
        )

    def test_prerelease_tuple_admission_is_per_and_arm_before_or_aggregation(self) -> None:
        cases = (
            ("0.0.0-alpha.1", ">=0.0.0 <0.0.0-beta.1", True),
            ("0.0.0-alpha.1", "<0.0.0-beta.1 || >=0.0.0", False),
        )
        oracle = [npm_semver_satisfies(version, specification) for version, specification, _ in cases]
        if all(value is not None for value in oracle):
            self.assertEqual(oracle, [expected for _, _, expected in cases])
        self.assertEqual(
            [audit._range_matches(version, specification) for version, specification, _ in cases],
            [expected for _, _, expected in cases],
        )

        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")

        def peer_result(specification: str) -> dict[str, Any]:
            metadata = {"peerDependencies": {"peer": specification}}
            lockfile = synthetic_lock(
                {"alpha": "1.0.0"},
                {},
                {
                    "alpha": package_record("alpha", "1.0.0", metadata),
                    "peer": package_record("peer", "0.0.0-alpha.1"),
                },
            )
            return audit.audit_bytes(
                manifest,
                lockfile,
                manifest_label="fixture/package.json",
                lockfile_label="fixture/bun.lock",
            )

        admitted_peer = peer_result(">=0.0.0 <0.0.0-beta.1")
        self.assertEqual(admitted_peer["status"], "review", admitted_peer)
        self.assertFalse(
            any(item["code"] == "package-resolution-missing" for item in admitted_peer["findings"]),
            admitted_peer,
        )
        self.assertEqual(admitted_peer["lockfile"]["peer_dependency_gaps"], [], admitted_peer)

        rejected_peer = peer_result("<0.0.0-beta.1 || >=0.0.0")
        self.assertEqual(rejected_peer["status"], "fail", rejected_peer)
        self.assertIn("package-resolution-missing", self.finding_codes(rejected_peer), rejected_peer)
        self.assertEqual(
            rejected_peer["lockfile"]["peer_dependency_gaps"],
            [
                {
                    "package": "alpha",
                    "dependency": "peer",
                    "optional": False,
                    "status": "package-resolution-missing",
                }
            ],
            rejected_peer,
        )

        metadata = {
            "dependencies": {
                "admitted": ">=0.0.0 <0.0.0-beta.1",
                "rejected": "<0.0.0-beta.1 || >=0.0.0",
            },
            "peerDependencies": {
                "required-peer-admitted": ">=0.0.0 <0.0.0-beta.1",
                "required-peer-rejected": "<0.0.0-beta.1 || >=0.0.0",
            },
        }
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record("alpha", "1.0.0", metadata),
                "admitted": package_record("admitted", "0.0.0-alpha.1"),
                "rejected": package_record("rejected", "0.0.0-alpha.1"),
                "required-peer-admitted": package_record("required-peer-admitted", "0.0.0-alpha.1"),
                "required-peer-rejected": package_record("required-peer-rejected", "0.0.0-alpha.1"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        self.assertEqual(result["status"], "fail", result)
        blocking = {
            item.get("package")
            for item in result["findings"]
            if item["severity"] == "blocking" and item["code"] == "package-resolution-missing"
        }
        self.assertEqual(blocking, {"rejected", "required-peer-rejected"}, result)
        self.assertEqual(
            result["lockfile"]["peer_dependency_gaps"],
            [
                {
                    "package": "alpha",
                    "dependency": "required-peer-rejected",
                    "optional": False,
                    "status": "package-resolution-missing",
                }
            ],
            result,
        )

    def test_prerelease_admission_requires_an_exact_comparator_core(self) -> None:
        cases = (
            ("1.2.3-beta.1", "^1.0.0-beta.1", False),
            ("1.2.3-beta.1", ">=1.0.0-beta.1", False),
            ("2.0.0-beta.1", ">=1.0.0-beta.1 <2.0.0", False),
            ("1.0.0-beta.2", "^1.0.0-beta.1", True),
            ("1.0.0-beta.2", ">=1.0.0-beta.1", True),
            ("2.0.0-beta.0", ">=1.0.0 <2.0.0-beta.1", True),
        )
        oracle = [npm_semver_satisfies(version, specification) for version, specification, _ in cases]
        if all(value is not None for value in oracle):
            self.assertEqual(oracle, [expected for _, _, expected in cases])
        self.assertEqual(
            [audit._range_matches(version, specification) for version, specification, _ in cases],
            [expected for _, _, expected in cases],
        )

        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        metadata = {
            "dependencies": {
                "mismatch-caret": "^1.0.0-beta.1",
                "mismatch-comparator": ">=1.0.0-beta.1",
                "mismatch-set": ">=1.0.0-beta.1 <2.0.0",
                "admitted-caret": "^1.0.0-beta.1",
                "admitted-comparator": ">=1.0.0-beta.1",
                "admitted-set": ">=1.0.0 <2.0.0-beta.1",
            },
            "peerDependencies": {
                "required-peer-mismatch": ">=1.0.0-beta.1",
                "required-peer-admitted": ">=1.0.0-beta.1",
            },
        }
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record("alpha", "1.0.0", metadata),
                "mismatch-caret": package_record("mismatch-caret", "1.2.3-beta.1"),
                "mismatch-comparator": package_record("mismatch-comparator", "1.2.3-beta.1"),
                "mismatch-set": package_record("mismatch-set", "2.0.0-beta.1"),
                "admitted-caret": package_record("admitted-caret", "1.0.0-beta.2"),
                "admitted-comparator": package_record("admitted-comparator", "1.0.0-beta.2"),
                "admitted-set": package_record("admitted-set", "2.0.0-beta.0"),
                "required-peer-mismatch": package_record("required-peer-mismatch", "1.2.3-beta.1"),
                "required-peer-admitted": package_record("required-peer-admitted", "1.0.0-beta.2"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        blocking = {
            item.get("package")
            for item in result["findings"]
            if item["severity"] == "blocking" and item["code"] == "package-resolution-missing"
        }
        self.assertEqual(
            blocking,
            {"mismatch-caret", "mismatch-comparator", "mismatch-set", "required-peer-mismatch"},
            result,
        )
        self.assertEqual(
            result["lockfile"]["peer_dependency_gaps"],
            [
                {
                    "package": "alpha",
                    "dependency": "required-peer-mismatch",
                    "optional": False,
                    "status": "package-resolution-missing",
                }
            ],
            result,
        )

    def test_partial_caret_ranges_use_npm_lower_and_upper_bounds(self) -> None:
        cases = (
            ("0.2.0", "^0", True),
            ("0.2.0", "^0.x", True),
            ("0.0.1", "^0.0", True),
            ("0.0.1", "^0.0.x", True),
            ("0.999.999", "^0", True),
            ("1.0.0", "^0", False),
            ("0.1.0", "^0.0", False),
            ("0.2.0", "^0.0", False),
            ("0.2.0", "^0.2", True),
            ("0.3.0", "^0.2", False),
        )
        oracle = [npm_semver_satisfies(version, specification) for version, specification, _ in cases]
        if all(value is not None for value in oracle):
            self.assertEqual(oracle, [expected for _, _, expected in cases])
        self.assertEqual(
            [audit._range_matches(version, specification) for version, specification, _ in cases],
            [expected for _, _, expected in cases],
        )

        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        metadata = {
            "dependencies": {
                "caret-zero": "^0",
                "caret-zero-x": "^0.x",
                "caret-zero-zero": "^0.0",
                "caret-zero-zero-x": "^0.0.x",
            },
            "peerDependencies": {"required-peer-caret": "^0.0"},
        }
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record("alpha", "1.0.0", metadata),
                "caret-zero": package_record("caret-zero", "0.2.0"),
                "caret-zero-x": package_record("caret-zero-x", "0.2.0"),
                "caret-zero-zero": package_record("caret-zero-zero", "0.0.1"),
                "caret-zero-zero-x": package_record("caret-zero-zero-x", "0.0.1"),
                "required-peer-caret": package_record("required-peer-caret", "0.0.1"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        self.assertEqual(result["status"], "review", result)
        self.assertEqual(
            {item["name"] for item in result["inventory"]["transitive"]},
            {
                "caret-zero",
                "caret-zero-x",
                "caret-zero-zero",
                "caret-zero-zero-x",
                "required-peer-caret",
            },
            result,
        )
        self.assertEqual(result["lockfile"]["peer_dependency_gaps"], [], result)

    def test_semver_ranges_are_strict_and_prerelease_safe(self) -> None:
        manifest = json.dumps(
            {
                "name": "@fixture/web",
                "dependencies": {"alpha": "1.0.0"},
                "devDependencies": {},
            }
        ).encode("utf-8")
        metadata = {
            "dependencies": {
                "leading-zero": "^01.2.3",
                "extra-v": "vv1.2.3",
                "union-junk": "^1.0.0 || junk",
                "caret-pre": "^1.0.0",
                "tilde-pre": "~1.0.0",
                "comparator-pre": ">=1.0.0",
                "wildcard-pre": "1.x",
                "admitted-pre": "^1.0.0-beta.1",
            },
            "peerDependencies": {"required-peer-pre": ">=1.0.0"},
        }
        lockfile = synthetic_lock(
            {"alpha": "1.0.0"},
            {},
            {
                "alpha": package_record("alpha", "1.0.0", metadata),
                "leading-zero": package_record("leading-zero", "1.2.3"),
                "extra-v": package_record("extra-v", "1.2.3"),
                "union-junk": package_record("union-junk", "1.2.3"),
                "caret-pre": package_record("caret-pre", "1.2.3-beta.1"),
                "tilde-pre": package_record("tilde-pre", "1.0.5-beta.1"),
                "comparator-pre": package_record("comparator-pre", "1.2.3-beta.1"),
                "wildcard-pre": package_record("wildcard-pre", "1.2.3-beta.1"),
                "admitted-pre": package_record("admitted-pre", "1.0.0-beta.1"),
                "required-peer-pre": package_record("required-peer-pre", "1.2.3-beta.1"),
            },
        )
        result = audit.audit_bytes(manifest, lockfile, manifest_label="fixture/package.json", lockfile_label="fixture/bun.lock")
        self.assertEqual(result["status"], "fail", result)
        blocking = {
            item.get("package")
            for item in result["findings"]
            if item["severity"] == "blocking" and item["code"] == "package-resolution-missing"
        }
        self.assertEqual(
            blocking,
            {
                "leading-zero",
                "extra-v",
                "union-junk",
                "caret-pre",
                "tilde-pre",
                "comparator-pre",
                "wildcard-pre",
                "required-peer-pre",
            },
            result,
        )
        self.assertIn("admitted-pre", {item["name"] for item in result["inventory"]["transitive"]}, result)
        self.assertEqual(
            result["lockfile"]["peer_dependency_gaps"],
            [
                {
                    "package": "alpha",
                    "dependency": "required-peer-pre",
                    "optional": False,
                    "status": "package-resolution-missing",
                }
            ],
            result,
        )

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
