#!/usr/bin/env python3
"""Offline adversarial tests for the per-run ownership marker.

The fixtures are synthetic regular files and fake identities. No Podman,
credential service, endpoint, browser, or network operation is used.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "live_run_marker.py"
spec = importlib.util.spec_from_file_location("live_run_marker", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
marker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = marker
spec.loader.exec_module(marker)


class LiveRunMarkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.runs = self.root / "runs"
        self.runs.mkdir(mode=marker.RUNS_DIR_MODE)
        self.runs.chmod(marker.RUNS_DIR_MODE)
        self.marker_path = self.runs / "fixture.json"
        self.credential_path = self.runs / "fixture.credential"
        self.credential_path.write_bytes(b"a" * 48 + b"\n")
        self.credential_path.chmod(marker.CREDENTIAL_MODE)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_marker(self, *, status: str = marker.STATUS_RUNNING):
        identity = marker.credential_lstat(self.credential_path)
        value = marker.new_marker(
            self.marker_path,
            run_id="a" * 64,
            instance="fixture-one",
            container_id="b" * 64,
            container_name="hermternal-hermes-fixture-one",
            image="docker.io/nousresearch/hermes-agent:v1@sha256:" + "c" * 64,
            endpoint="http://127.0.0.1:19119",
            credential_identity=identity,
        )
        if status != marker.STATUS_RUNNING:
            value = value.with_status(status)
        return value

    def test_run_id_is_256_bit_lowercase_hex(self) -> None:
        value = marker.new_run_id()
        self.assertRegex(value, r"^[0-9a-f]{64}$")
        self.assertEqual(len(value), 64)

    def test_private_directory_and_exact_canonical_path_are_required(self) -> None:
        self.assertEqual(marker.ensure_private_runs_dir(self.runs), self.runs)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.marker_paths(Path("runs/fixture.json"))
        self.assertEqual(raised.exception.code, "marker_path_invalid")

        self.runs.chmod(0o755)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.marker_paths(self.marker_path)
        self.assertEqual(raised.exception.code, "runs_dir_not_private")
        self.runs.chmod(marker.RUNS_DIR_MODE)

    def test_marker_is_strict_closed_schema_and_round_trips_atomically(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        loaded = marker.load_marker(self.marker_path, selectable=True)
        self.assertEqual(loaded, value)
        self.assertEqual(stat.S_IMODE(self.marker_path.stat().st_mode), marker.MARKER_MODES)
        self.assertEqual(self.marker_path.stat().st_nlink, 1)

        with self.assertRaises(marker.MarkerError) as raised:
            marker.create_marker(value)
        self.assertEqual(raised.exception.code, "marker_already_exists")

        marker.replace_marker(marker.cleanup_failed(value))
        self.assertEqual(marker.load_marker(self.marker_path).status, marker.STATUS_CLEANUP_FAILED)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.load_marker(self.marker_path, selectable=True)
        self.assertEqual(raised.exception.code, "marker_not_selectable")

    def test_unknown_duplicate_and_malformed_keys_fail_closed(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        original = json.loads(self.marker_path.read_text(encoding="utf-8"))
        for mutation in (
            {**original, "unexpected": "value"},
            {key: value for key, value in original.items() if key != "run_id"},
            {**original, "status": "stopped"},
        ):
            self.marker_path.write_text(json.dumps(mutation), encoding="utf-8")
            self.marker_path.chmod(marker.MARKER_MODES)
            with self.subTest(mutation=mutation), self.assertRaises(marker.MarkerError):
                marker.load_marker(self.marker_path)

        duplicate = json.dumps(original)[:-1] + ',"status":"running"}\n'
        self.marker_path.write_text(duplicate, encoding="utf-8")
        self.marker_path.chmod(marker.MARKER_MODES)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.load_marker(self.marker_path)
        self.assertEqual(raised.exception.code, "marker_duplicate_key")

    def test_unhashable_status_values_fail_closed_without_type_error(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        original = json.loads(self.marker_path.read_text(encoding="utf-8"))
        for status in ([], {}):
            with self.subTest(status=status):
                document = {**original, "status": status}
                self.marker_path.write_text(json.dumps(document), encoding="utf-8")
                self.marker_path.chmod(marker.MARKER_MODES)
                with self.assertRaises(marker.MarkerError) as raised:
                    marker.load_marker(self.marker_path)
                self.assertEqual(raised.exception.code, "marker_status_invalid")

    def test_copied_hardlinked_symlink_and_nonregular_markers_fail_closed(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)

        copied = self.runs / "copied.json"
        copied.write_bytes(self.marker_path.read_bytes())
        copied.chmod(marker.MARKER_MODES)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.load_marker(copied)
        self.assertEqual(raised.exception.code, "marker_path_mismatch")

        hardlink = self.runs / "hardlink.json"
        os.link(self.marker_path, hardlink)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.load_marker(self.marker_path)
        self.assertEqual(raised.exception.code, "marker_invalid")
        hardlink.unlink()

        symlink = self.runs / "symlink.json"
        symlink.symlink_to(self.marker_path)
        with self.assertRaises(marker.MarkerError):
            marker.load_marker(symlink)

        self.marker_path.unlink()
        self.marker_path.mkdir(mode=marker.MARKER_MODES)
        with self.assertRaises(marker.MarkerError):
            marker.load_marker(self.marker_path)

    def test_credential_identity_is_lstat_only_and_replacement_fails(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("credential value read")):
            identity = marker.verify_credential_identity(marker.load_marker(self.marker_path))
        self.assertEqual(identity, value.credential_identity)

        replacement = self.runs / "replacement"
        replacement.write_bytes(self.credential_path.read_bytes())
        replacement.chmod(marker.CREDENTIAL_MODE)
        self.credential_path.unlink()
        replacement.rename(self.credential_path)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.verify_credential_identity(marker.load_marker(self.marker_path))
        self.assertEqual(raised.exception.code, "credential_identity_mismatch")

        self.credential_path.unlink()
        self.credential_path.symlink_to(replacement)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.verify_credential_identity(marker.load_marker(self.marker_path))
        self.assertIn(raised.exception.code, {"credential_identity_invalid", "credential_path_invalid"})

    def test_marker_copy_cannot_change_pinned_state_or_credential_paths(self) -> None:
        value = self.make_marker()
        for field, alternate in (
            ("state_path", self.runs / "alternate.state.json"),
            ("credential_path", self.runs / "alternate.credential"),
        ):
            with self.subTest(field=field):
                document = value.document()
                document[field] = str(alternate)
                self.marker_path.write_text(json.dumps(document), encoding="utf-8")
                self.marker_path.chmod(marker.MARKER_MODES)
                with self.assertRaises(marker.MarkerError) as raised:
                    marker.load_marker(self.marker_path)
                self.assertEqual(raised.exception.code, "marker_path_mismatch")

        document = value.document()
        document["state_path"] = str(self.root / "other.state.json")
        self.marker_path.write_text(json.dumps(document), encoding="utf-8")
        self.marker_path.chmod(marker.MARKER_MODES)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.load_marker(self.marker_path)
        self.assertEqual(raised.exception.code, "marker_path_invalid")

    def test_loading_one_marker_never_enumerates_the_runs_directory(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        with mock.patch.object(Path, "iterdir", side_effect=AssertionError("enumerated")), mock.patch.object(
            Path, "glob", side_effect=AssertionError("enumerated")
        ):
            self.assertEqual(marker.load_marker(self.marker_path, selectable=True), value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
