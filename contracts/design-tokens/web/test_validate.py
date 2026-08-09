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

# These seven families are the focused Authentication registration contract.
# Their approved board IDs are all on Paper page C-0; this direct parser keeps
# the source-page correction independent from the validator's full page gate.
AUTHENTICATION_RECORDS = (
    ("auth.password-sign-in", "auth", ("3JK-0", "HJO-0", "3OH-0", "HKK-0")),
    ("auth.oauth-callback", "auth", ("3JL-0", "HLG-0", "3P1-0", "HLT-0")),
    ("auth.authentication-failure", "auth-gate", ("3JM-0", "HM6-0", "3PE-0", "HMM-0")),
    ("auth.session-expired", "auth-gate", ("HN2-0", "3JO-0", "HNR-0", "3QO-0")),
    ("auth.interaction-states", "auth", ("69V-0", "HOG-0", "69W-0", "HRD-0")),
    ("auth.provider-selection-200-percent-zoom", "auth", ("HUA-0", "6G3-0", "HUX-0", "6HR-0")),
    ("auth.provider-localization-growth", "auth", ("HVK-0", "6GX-0", "HW7-0", "6IL-0")),
)
EXPECTED_POPULATED_PAGES = (
    ("A-0", "Chat workspace", 34),
    ("C-0", "Authentication", 48),
    ("D-0", "Runtime and recovery", 40),
    ("B-0", "Shared Chat–Terminal workspace", 25),
    ("E-0", "Terminal desktop lifecycle", 22),
    ("F-0", "Terminal narrow and mobile", 28),
    ("G-0", "Accessibility", 3),
)
OBSOLETE_EMPTY_PAGES = (
    ("3-0", "Web states — Authentication", 48),
    ("4-0", "Web states — Runtime", 68),
)


def read_manifest_direct() -> dict:
    return json.loads(Path(__file__).with_name("artboards.json").read_text(encoding="utf-8"))


class AuthenticationPaperSourceTests(unittest.TestCase):
    def test_authentication_families_use_c0_not_obsolete_web_pages(self) -> None:
        manifest = read_manifest_direct()
        pages = tuple(
            tuple(page[field] for field in ("id", "name", "artboard_count"))
            for page in manifest["paper"]["pages"]
        )
        self.assertEqual(pages, EXPECTED_POPULATED_PAGES)
        for obsolete_page in OBSOLETE_EMPTY_PAGES:
            self.assertNotIn(obsolete_page, pages)

        states = {state["id"]: state for state in manifest["states"]}
        for state_id, _, expected_artboards in AUTHENTICATION_RECORDS:
            with self.subTest(state_id=state_id):
                self.assertEqual(states[state_id]["family"], "authentication")
                self.assertEqual(
                    [variant["artboard_id"] for variant in states[state_id]["variants"]],
                    list(expected_artboards),
                )


class AuthenticationRegistrationRegressionTests(unittest.TestCase):
    def test_seven_authentication_families_are_registered_ready(self) -> None:
        manifest = read_manifest_direct()
        states = {state["id"]: state for state in manifest["states"]}
        for state_id, token_set, expected_artboards in AUTHENTICATION_RECORDS:
            with self.subTest(state_id=state_id):
                state = states.get(state_id)
                self.assertIsNotNone(state, f"missing Authentication record: {state_id}")
                if state is None:
                    continue
                self.assertEqual(state["status"], "ready", f"Authentication record remains blocked: {state_id}")
                self.assertEqual(state["family"], "authentication")
                self.assertEqual(state["release"], "v0.0.1")
                self.assertEqual(state["token_set"], token_set)
                self.assertEqual(state["missing_variants"], [])
                self.assertEqual(
                    [variant["artboard_id"] for variant in state["variants"]],
                    list(expected_artboards),
                )


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
        self.assertEqual(counts, (23, 0, 7))
        self.assertEqual(len(self.manifest["states"]), 30)
        self.assertEqual(sum(len(state["variants"]) for state in self.manifest["states"]), 120)
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

    def test_authentication_source_page_negatives_fail_closed(self) -> None:
        mutations = (
            ("missing C-0", lambda doc: doc["paper"]["pages"].pop(1)),
            ("duplicate C-0", lambda doc: doc["paper"]["pages"].insert(1, copy.deepcopy(doc["paper"]["pages"][1]))),
            ("renamed C-0", lambda doc: doc["paper"]["pages"][1].update(name="Web states — Authentication")),
            ("wrong C-0 count", lambda doc: doc["paper"]["pages"][1].update(artboard_count=0)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                mutated = copy.deepcopy(self.manifest)
                mutate(mutated)
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

    def test_terminal_metadata_drift_fails_closed(self) -> None:
        def swap(items: list[object], first: int, second: int) -> None:
            items[first], items[second] = items[second], items[first]

        mutations = (
            ("page order", lambda doc: swap(doc["paper"]["pages"], 2, 3)),
            ("page name", lambda doc: doc["paper"]["pages"][2].update(name="renamed Terminal page")),
            ("page count", lambda doc: doc["paper"]["pages"][2].update(artboard_count=24)),
            ("state order", lambda doc: swap(doc["terminal"]["states"], 0, 1)),
            ("state id", lambda doc: doc["terminal"]["states"][0].update(id="terminal.fresh-renamed")),
            ("board name", lambda doc: doc["terminal"]["states"][0]["boards"][0].update(name="renamed Terminal board")),
            ("board dimensions", lambda doc: doc["terminal"]["states"][0]["boards"][0].update(width=1441)),
            ("board page", lambda doc: doc["terminal"]["states"][0]["boards"][0].update(page_id="G-0")),
            ("static caveat", lambda doc: doc["terminal"]["states"][0].update(notes="Paper evidence only.")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                mutated = copy.deepcopy(self.manifest)
                mutate(mutated)
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

    def test_missing_authentication_record_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        states = mutated["states"]
        parent = next(state for state in states if state["id"] == "auth.password-sign-in")
        states.remove(parent)
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
