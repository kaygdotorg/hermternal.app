#!/usr/bin/env python3
"""Focused regression tests for the checked-in Paper artboard manifest."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


REPO_ROOT = Path(__file__).resolve().parents[3]
VALIDATOR_PATH = Path(__file__).resolve().with_name("validate.py")


class StrictJsonTests(unittest.TestCase):
    def _write_bytes(self, payload: bytes) -> Path:
        handle = tempfile.NamedTemporaryFile(prefix="web-paper-validator-", suffix=".json", delete=False)
        path = Path(handle.name)
        try:
            handle.write(payload)
            handle.close()
        except Exception:
            handle.close()
            path.unlink(missing_ok=True)
            raise
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def test_duplicate_object_keys_fail_before_overwrite(self) -> None:
        with self.assertRaises(validate.DuplicateKeyError):
            validate.load_json(self._write_bytes(b'{"schema":"first","schema":"second"}'))

    def test_non_finite_numbers_and_invalid_utf8_fail(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write_bytes(b'{"value":NaN}'))
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write_bytes(b'{"value":1e999}'))
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write_bytes(b'{"value":"\xff"}'))

    def test_bounded_input_rejects_oversized_integer_depth_and_nul(self) -> None:
        oversized = b"{" + b"a" * validate.MAX_JSON_BYTES + b"}"
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write_bytes(oversized))

        integer = ("{\"value\":" + "9" * (validate.MAX_INTEGER_DIGITS + 1) + "}").encode()
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write_bytes(integer))

        nested = "0"
        for _ in range(validate.MAX_JSON_DEPTH + 2):
            nested = "[" + nested + "]"
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write_bytes(("{\"value\":" + nested + "}").encode()))

        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write_bytes(b'{"value":"\\u0000"}'))


class ManifestMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = validate.load_json(validate.MANIFEST_PATH)

    def _write_manifest(self, document: dict[str, object]) -> Path:
        handle = tempfile.NamedTemporaryFile(prefix="web-paper-manifest-", suffix=".json", mode="w", encoding="utf-8", delete=False)
        path = Path(handle.name)
        try:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.close()
        except Exception:
            handle.close()
            path.unlink(missing_ok=True)
            raise
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def test_checked_in_manifest_is_exactly_complete(self) -> None:
        counts = validate.validate_manifest(copy.deepcopy(self.manifest))
        self.assertEqual(counts, (15, 7, 7))
        self.assertEqual(len(self.manifest["states"]), 29)
        self.assertEqual(sum(len(state["variants"]) for state in self.manifest["states"]), 102)
        self.assertEqual(len(self.manifest["paper_tokens"]), 84)
        self.assertEqual(len(self.manifest["terminal"]["states"]), 15)
        self.assertEqual(sum(len(state["boards"]) for state in self.manifest["terminal"]["states"]), 78)
        self.assertFalse(self.manifest["live_claim"])
        self.assertTrue(self.manifest["terminal"]["paper_static_only"])

    def test_stale_paper_token_hash_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["paper"]["token_content_hash"] = "stale-token-hash"
        self._assert_cli_failure(mutated)

    def test_missing_terminal_page_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["paper"]["pages"] = [page for page in mutated["paper"]["pages"] if page["id"] != "F-0"]
        self._assert_cli_failure(mutated)

    def test_missing_terminal_state_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["terminal"]["states"].pop()
        self._assert_cli_failure(mutated)

    def test_duplicate_terminal_board_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        boards = mutated["terminal"]["states"][0]["boards"]
        boards[1]["id"] = boards[0]["id"]
        self._assert_cli_failure(mutated)

    def test_incomplete_terminal_coverage_fails_closed(self) -> None:
        mutations = (
            ("terminal.fresh", ("light.desktop", "light.narrow", "dark.desktop")),
            ("terminal.fresh", ("light.desktop", "dark.desktop", "dark.narrow")),
            ("terminal.fresh", ("light.desktop", "light.narrow", "dark.narrow")),
            ("terminal.accessibility", ("keyboard-focus", "narrow-focus", "200-percent-zoom")),
        )
        for state_id, coverage in mutations:
            with self.subTest(state_id=state_id, coverage=coverage):
                mutated = copy.deepcopy(self.manifest)
                state = next(item for item in mutated["terminal"]["states"] if item["id"] == state_id)
                state["coverage"] = list(coverage)
                self._assert_cli_failure(mutated)

    def test_unknown_artboard_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["states"][0]["variants"][0]["artboard_id"] = "unknown-paper-board"
        self._assert_cli_failure(mutated)

    def test_duplicate_artboard_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["states"][0]["variants"][1]["artboard_id"] = mutated["states"][0]["variants"][0]["artboard_id"]
        self._assert_cli_failure(mutated)

    def test_duplicate_variant_id_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["states"][0]["variants"][1]["id"] = "light.desktop"
        self._assert_cli_failure(mutated)

    def test_missing_ready_variant_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["states"][0]["variants"].pop()
        self._assert_cli_failure(mutated)

    def test_missing_blocked_variant_must_be_documented(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["states"][11]["missing_variants"] = []
        self._assert_cli_failure(mutated)

    def test_deferred_state_cannot_be_claimed_for_v0_0_1(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        deferred = next(state for state in mutated["states"] if state["status"] == "deferred")
        deferred["release"] = "v0.0.1"
        self._assert_cli_failure(mutated)

    def test_wrong_artboard_name_or_dimensions_fails_closed(self) -> None:
        for field, value in (("name", "forged Paper name"), ("width", 1441), ("height", 959)):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.manifest)
                mutated["states"][0]["variants"][0][field] = value
                self._assert_cli_failure(mutated)

    def test_unknown_or_reordered_token_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["tokens"][0]["name"] = "--unknown-token"
        self._assert_cli_failure(mutated)

        mutated = copy.deepcopy(self.manifest)
        mutated["tokens"][0], mutated["tokens"][1] = mutated["tokens"][1], mutated["tokens"][0]
        self._assert_cli_failure(mutated)

    def test_unknown_top_level_key_and_reordered_state_fail_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["unexpected"] = "not part of the contract"
        self._assert_cli_failure(mutated)

        mutated = copy.deepcopy(self.manifest)
        mutated["states"][0], mutated["states"][1] = mutated["states"][1], mutated["states"][0]
        self._assert_cli_failure(mutated)

    def _assert_cli_failure(self, document: dict[str, object]) -> None:
        path = self._write_manifest(document)
        for optimized in (False, True):
            completed = self._run(path, optimized=optimized)
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(len(completed.stdout.splitlines()), 1)
            self.assertLessEqual(len(completed.stdout.strip()), validate.MAX_ERROR_LENGTH)
            payload = json.loads(completed.stdout)
            self.assertFalse(payload["ok"])
            self.assertFalse(payload["live_claim"])
            self.assertEqual(payload["evidence_status"], "blocked")

    @staticmethod
    def _run(path: Path, *, optimized: bool) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(VALIDATOR_PATH), "--manifest", str(path)])
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )


class CliParityTests(unittest.TestCase):
    def _run(self, *args: str, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(VALIDATOR_PATH), *args])
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_normal_and_optimized_success_have_same_boundary(self) -> None:
        normal = self._run()
        optimized = self._run(optimized=True)
        self.assertEqual(normal.returncode, 0)
        self.assertEqual(optimized.returncode, 0)
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")
        self.assertEqual(json.loads(normal.stdout), json.loads(optimized.stdout))

    def test_unknown_flag_is_bounded_and_redacted(self) -> None:
        for optimized in (False, True):
            completed = self._run("--unknown-flag=synthetic-secret", optimized=optimized)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            self.assertNotIn("synthetic-secret", completed.stdout)
            self.assertLessEqual(len(completed.stdout.strip()), validate.MAX_ERROR_LENGTH)
            self.assertFalse(json.loads(completed.stdout)["live_claim"])

    def test_missing_manifest_path_fails_closed(self) -> None:
        missing = str(REPO_ROOT / "contracts/design-tokens/web/does-not-exist.json")
        for optimized in (False, True):
            completed = self._run("--manifest", missing, optimized=optimized)
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stderr, "")
            self.assertFalse(json.loads(completed.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
