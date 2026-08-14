#!/usr/bin/env python3
"""Offline adversarial tests for the per-run ownership marker.

The fixtures are synthetic regular files and fake identities. No Podman,
credential service, endpoint, browser, or network operation is used.
"""

from __future__ import annotations

import importlib.util
import json
import multiprocessing
import os
import select
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


def _lifecycle_worker(runs_path: str, acquired_fd: int, release_fd: int) -> None:
    parent_fd = -1
    try:
        parent_fd = marker.open_runs_parent(Path(runs_path))
        with marker.exclusive_lifecycle_lease(parent_fd):
            os.write(acquired_fd, b"acquired\n")
            os.read(release_fd, 1)
    except BaseException as error:
        os.write(acquired_fd, f"error:{type(error).__name__}\n".encode("ascii"))
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(acquired_fd)
        os.close(release_fd)


def _quarantine_worker(runs_path: str, acquired_fd: int, release_fd: int) -> None:
    parent_fd = -1
    try:
        parent_fd = marker.open_runs_parent(Path(runs_path))
        with marker.quarantine_exclusive(parent_fd):
            os.write(acquired_fd, b"acquired\n")
            os.read(release_fd, 1)
    except BaseException as error:
        os.write(acquired_fd, f"error:{type(error).__name__}\n".encode("ascii"))
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(acquired_fd)
        os.close(release_fd)


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

    def test_marker_endpoint_requires_exact_canonical_spelling_and_surrogate_safe_text(self) -> None:
        identity = marker.credential_lstat(self.credential_path)
        rejected = (
            "HTTP://127.0.0.1:19119",
            "http://127.0.0.1:01",
            "http://127.0.0.1:001",
            "http://127.0.0.1:00080",
            "http://127.0.0.1:019119",
            "http://127.0.0.1:19119/",
            "http://127.0.0.1:19119?",
            "http://127.0.0.1:19119#",
            "http://localhost:19119",
            "http://127.0.0.1:\ud800",
        )
        for endpoint in rejected:
            with self.subTest(endpoint=repr(endpoint)), self.assertRaises(marker.MarkerError) as raised:
                marker.new_marker(
                    self.marker_path,
                    run_id="a" * 64,
                    instance="fixture-one",
                    container_id="b" * 64,
                    container_name="hermternal-hermes-fixture-one",
                    image="docker.io/nousresearch/hermes-agent:v1@sha256:" + "c" * 64,
                    endpoint=endpoint,
                    credential_identity=identity,
                )
            self.assertEqual(raised.exception.code, "marker_schema_invalid")

    def test_new_marker_validates_schema_before_credential_snapshot(self) -> None:
        identity = marker.credential_lstat(self.credential_path)
        with mock.patch.object(
            marker,
            "credential_snapshot",
            side_effect=AssertionError("credential snapshot accessed before schema validation"),
        ) as snapshot:
            with self.assertRaises(marker.MarkerError) as raised:
                marker.new_marker(
                    self.marker_path,
                    run_id="a" * 64,
                    instance="fixture-one",
                    container_id="b" * 64,
                    container_name="hermternal-hermes-fixture-one",
                    image="docker.io/nousresearch/hermes-agent:v1@sha256:" + "c" * 64,
                    endpoint="http://127.0.0.1:\ud800",
                    credential_identity=identity,
                )
        self.assertEqual(raised.exception.code, "marker_schema_invalid")
        snapshot.assert_not_called()

    def test_secure_marker_capabilities_fail_closed_before_any_marker_or_lock_boundary(self) -> None:
        value = self.make_marker()
        for capability in ("O_NOFOLLOW", "O_DIRECTORY"):
            with self.subTest(capability=capability), mock.patch.object(marker.os, capability, 0):
                with self.assertRaises(marker.MarkerError) as raised:
                    marker.ensure_private_runs_dir(self.runs)
                self.assertEqual(raised.exception.code, "runs_dir_invalid")
                with self.assertRaises(marker.MarkerError) as raised:
                    marker.create_marker(value)
                self.assertEqual(raised.exception.code, "marker_invalid")
                with self.assertRaises(marker.MarkerError) as raised:
                    marker._open_runs_parent(self.runs, code="parent_invalid")
                self.assertEqual(raised.exception.code, "parent_invalid")
                self.assertFalse(self.marker_path.exists())
                self.assertFalse((self.runs / marker.LIFECYCLE_LOCK_NAME).exists())

        supports_dir_fd = set(marker.os.supports_dir_fd)
        supports_dir_fd.discard(marker.os.open)
        with mock.patch.object(marker.os, "supports_dir_fd", supports_dir_fd):
            with self.assertRaises(marker.MarkerError) as raised:
                marker.ensure_private_runs_dir(self.runs)
            self.assertEqual(raised.exception.code, "runs_dir_invalid")
            with self.assertRaises(marker.MarkerError) as raised:
                marker.create_marker(value)
            self.assertEqual(raised.exception.code, "marker_invalid")
            with self.assertRaises(marker.MarkerError) as raised:
                marker._open_runs_parent(self.runs, code="parent_invalid")
            self.assertEqual(raised.exception.code, "parent_invalid")
        self.assertFalse(self.marker_path.exists())
        self.assertFalse((self.runs / marker.LIFECYCLE_LOCK_NAME).exists())

        parent_fd = marker.open_runs_parent(self.marker_path)
        try:
            with mock.patch.object(marker.os, "O_NOFOLLOW", 0):
                with self.assertRaises(marker.MarkerError) as raised:
                    with marker.exclusive_lifecycle_lease(parent_fd):
                        pass
            self.assertEqual(raised.exception.code, "lifecycle_lease_failed")
            self.assertFalse((self.runs / marker.LIFECYCLE_LOCK_NAME).exists())
        finally:
            os.close(parent_fd)

    def test_private_directory_and_exact_canonical_path_are_required(self) -> None:
        self.assertEqual(marker.ensure_private_runs_dir(self.runs), self.runs)
        with self.assertRaises(marker.MarkerError) as raised:
            marker.marker_paths(Path("runs/fixture.json"))
        self.assertEqual(raised.exception.code, "marker_path_invalid")
        with self.assertRaises(marker.MarkerError) as raised:
            marker.marker_paths(self.runs / "\ud800.json")
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

    def test_darwin_clone_gates_staging_before_final_marker_path_exists(self) -> None:
        value = self.make_marker()
        content = marker._marker_bytes(value)
        source_path = self.runs / "source.json"
        source_path.write_bytes(content)
        source_path.chmod(marker.MARKER_MODES)
        parent_fd = marker.open_runs_parent(self.marker_path)
        source_fd = -1
        clone_targets: list[str] = []
        boundary_modes: list[int] = []
        try:
            source_fd = os.open(
                source_path.name,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
            source_identity = marker._marker_file_identity(os.fstat(source_fd))

            def synthetic_clone(source_descriptor: int, destination_parent: int, target_name: str) -> None:
                clone_targets.append(target_name)
                destination = os.open(
                    target_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    marker.MARKER_MODES,
                    dir_fd=destination_parent,
                )
                try:
                    os.lseek(source_descriptor, 0, os.SEEK_SET)
                    raw = os.read(source_descriptor, len(content))
                    self.assertEqual(raw, content)
                    self.assertEqual(os.write(destination, raw), len(raw))
                    os.fsync(destination)
                finally:
                    os.close(destination)
                if target_name == self.marker_path.name:
                    observed = os.open(
                        target_name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=destination_parent,
                    )
                    try:
                        boundary_modes.append(stat.S_IMODE(os.fstat(observed).st_mode))
                    finally:
                        os.close(observed)
                    raise AssertionError("final marker was readable at clone boundary")
                with self.assertRaises(FileNotFoundError):
                    os.open(
                        self.marker_path.name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=destination_parent,
                    )

            with (
                mock.patch.object(marker.sys, "platform", "darwin"),
                mock.patch.object(marker, "_fclonefileat", side_effect=synthetic_clone),
            ):
                published = marker._publish_marker_from_descriptor(
                    parent_fd,
                    self.marker_path.name,
                    source_fd,
                    source_identity,
                    content,
                )
            self.assertEqual(len(clone_targets), 1)
            self.assertIn(clone_targets[0], marker.quarantine_slot_names("replace-tmp"))
            self.assertNotEqual(clone_targets[0], self.marker_path.name)
            self.assertEqual(boundary_modes, [])
            self.assertEqual(published, marker._marker_file_identity(os.stat(self.marker_path)))
            self.assertEqual(self.marker_path.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(self.marker_path.stat().st_mode), marker.MARKER_MODES)
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            os.close(parent_fd)

    def test_normal_replace_publishes_new_inode_and_retains_old_evidence(self) -> None:
        original = self.make_marker()
        marker.create_marker(original)
        _, old_identity = marker.load_marker_with_identity(self.marker_path)
        old_content = self.marker_path.read_bytes()
        replacement = original.with_status(marker.STATUS_CLEANUP_FAILED)
        new_identity = marker.replace_marker(replacement, expected=old_identity)
        self.assertNotEqual(new_identity[1], old_identity[1])
        _, loaded_identity = marker.load_marker_with_identity(self.marker_path)
        self.assertEqual(loaded_identity, new_identity)
        old_evidence = [
            self.runs / name
            for name in marker.quarantine_slot_names("replace")
            if (self.runs / name).exists()
        ]
        self.assertTrue(old_evidence)
        self.assertTrue(any(path.read_bytes() == old_content for path in old_evidence))

    def test_marker_rewrite_rolls_back_after_partial_write(self) -> None:
        original = self.make_marker()
        marker.create_marker(original)
        _, expected = marker.load_marker_with_identity(self.marker_path)
        old_content = self.marker_path.read_bytes()
        replacement = original.with_status(marker.STATUS_CLEANUP_FAILED)
        real_write = os.write
        calls = 0

        def flaky_write(descriptor, content):
            nonlocal calls
            if calls == 0:
                calls += 1
                return real_write(descriptor, content[:1])
            if calls == 1:
                calls += 1
                raise OSError("synthetic partial write")
            return real_write(descriptor, content)

        with mock.patch.object(marker.os, "write", side_effect=flaky_write):
            with self.assertRaises(marker.MarkerError) as raised:
                marker.rewrite_marker_exact(replacement, expected)
        self.assertEqual(raised.exception.code, "marker_write_failed")
        self.assertEqual(self.marker_path.read_bytes(), old_content)
        self.assertEqual(stat.S_IMODE(self.marker_path.stat().st_mode), marker.MARKER_MODES)

    def test_marker_size_limit_fails_before_publication(self) -> None:
        value = self.make_marker()
        with mock.patch.object(marker, "MAX_MARKER_BYTES", 1):
            with self.assertRaises(marker.MarkerError) as raised:
                marker.create_marker(value)
        self.assertEqual(raised.exception.code, "marker_too_large")
        self.assertFalse(self.marker_path.exists())

    def test_fixed_quarantine_quota_preserves_foreign_slots_and_stops_growth(self) -> None:
        parent_fd = marker.open_runs_parent(self.marker_path)
        try:
            foreign = b"foreign"
            for name in marker.quarantine_slot_names("cleanup"):
                path = self.runs / name
                path.write_bytes(foreign)
                path.chmod(marker.MARKER_MODES)
            count, total = marker.quarantine_usage(parent_fd)
            self.assertEqual(count, marker.QUARANTINE_SLOT_COUNT)
            self.assertEqual(total, marker.QUARANTINE_SLOT_COUNT * len(foreign))
            with self.assertRaises(marker.MarkerError) as raised:
                marker.reserve_quarantine_slot(parent_fd, "cleanup", 1)
            self.assertEqual(raised.exception.code, "quarantine_quota_exceeded")
            self.assertEqual((self.runs / ".cleanup-00").read_bytes(), foreign)

            for name in marker.quarantine_slot_names("cleanup"):
                (self.runs / name).unlink()
            saturated = self.runs / ".cleanup-00"
            saturated.write_bytes(b"x" * marker.QUARANTINE_MAX_BYTES)
            saturated.chmod(marker.MARKER_MODES)
            with self.assertRaises(marker.MarkerError) as raised:
                marker.reserve_quarantine_slot(parent_fd, "cleanup", 1)
            self.assertEqual(raised.exception.code, "quarantine_quota_exceeded")
            self.assertEqual(saturated.stat().st_size, marker.QUARANTINE_MAX_BYTES)
        finally:
            os.close(parent_fd)

    def test_parent_lease_rejects_replaced_marker_directory(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        parent_fd = marker.open_runs_parent(self.marker_path)
        expected = marker.parent_identity(parent_fd)
        moved = self.root / "runs-original"
        try:
            self.runs.rename(moved)
            self.runs.mkdir(mode=marker.RUNS_DIR_MODE)
            self.runs.chmod(marker.RUNS_DIR_MODE)
            with self.assertRaises(marker.MarkerError) as raised:
                marker.revalidate_runs_parent_path(self.marker_path, parent_fd, expected=expected)
            self.assertEqual(raised.exception.code, "runs_dir_replaced")
            self.assertTrue((moved / "fixture.json").exists())
            self.assertFalse((self.runs / "fixture.json").exists())
        finally:
            os.close(parent_fd)

    def test_lifecycle_lease_serializes_separate_processes(self) -> None:
        context = multiprocessing.get_context("fork")
        first_ready, first_ready_write = os.pipe()
        first_release_read, first_release_write = os.pipe()
        second_ready, second_ready_write = os.pipe()
        second_release_read, second_release_write = os.pipe()
        first = context.Process(
            target=_lifecycle_worker,
            args=(str(self.runs), first_ready_write, first_release_read),
        )
        second = context.Process(
            target=_lifecycle_worker,
            args=(str(self.runs), second_ready_write, second_release_read),
        )
        try:
            first.start()
            os.close(first_ready_write)
            os.close(first_release_read)
            self.assertEqual(os.read(first_ready, 32), b"acquired\n")

            second.start()
            os.close(second_ready_write)
            os.close(second_release_read)
            readable, _, _ = select.select([second_ready], [], [], 0.1)
            self.assertEqual(readable, [])

            os.write(first_release_write, b"release")
            self.assertEqual(os.read(second_ready, 32), b"acquired\n")
            os.write(second_release_write, b"release")
        finally:
            for descriptor in (
                first_ready,
                first_release_write,
                second_ready,
                second_release_write,
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            first.join(timeout=2)
            second.join(timeout=2)
            if first.is_alive():
                first.terminate()
                first.join()
            if second.is_alive():
                second.terminate()
                second.join()
        self.assertEqual(first.exitcode, 0)
        self.assertEqual(second.exitcode, 0)

    def test_lock_unlock_failure_is_bounded_and_visible_after_success(self) -> None:
        parent_fd = marker.open_runs_parent(self.marker_path)
        try:
            real_flock = marker.fcntl.flock

            def fail_unlock(descriptor: int, operation: int) -> None:
                if operation == marker.fcntl.LOCK_UN:
                    raise OSError("synthetic unlock failure")
                real_flock(descriptor, operation)

            with mock.patch.object(marker.fcntl, "flock", side_effect=fail_unlock):
                with self.assertRaises(marker.MarkerError) as raised:
                    with marker.exclusive_lifecycle_lease(parent_fd):
                        pass
            self.assertEqual(raised.exception.code, "lifecycle_lease_failed_cleanup_failed")
            self.assertTrue((self.runs / marker.LIFECYCLE_LOCK_NAME).exists())
        finally:
            os.close(parent_fd)

    def test_lock_close_failure_is_bounded_and_primary_body_error_remains_primary(self) -> None:
        parent_fd = marker.open_runs_parent(self.marker_path)
        try:
            with mock.patch.object(marker.os, "close", side_effect=OSError("synthetic close failure")):
                with self.assertRaises(marker.MarkerError) as raised:
                    with marker.exclusive_lifecycle_lease(parent_fd):
                        pass
            self.assertEqual(raised.exception.code, "lifecycle_lease_failed_cleanup_failed")
        finally:
            os.close(parent_fd)

        parent_fd = marker.open_runs_parent(self.marker_path)
        try:
            with mock.patch.object(marker.os, "close", side_effect=OSError("synthetic close failure")):
                with self.assertRaises(marker.MarkerError) as raised:
                    with marker.exclusive_lifecycle_lease(parent_fd):
                        raise marker.MarkerError("primary_marker_failure")
            self.assertEqual(raised.exception.code, "primary_marker_failure")
            self.assertIsNotNone(raised.exception.secondary)
            assert raised.exception.secondary is not None
            self.assertEqual(raised.exception.secondary.code, "lifecycle_lease_failed_cleanup_failed")
        finally:
            os.close(parent_fd)

    def test_quarantine_lease_serializes_separate_processes(self) -> None:
        context = multiprocessing.get_context("fork")
        first_ready, first_ready_write = os.pipe()
        first_release_read, first_release_write = os.pipe()
        second_ready, second_ready_write = os.pipe()
        second_release_read, second_release_write = os.pipe()
        first = context.Process(
            target=_quarantine_worker,
            args=(str(self.runs), first_ready_write, first_release_read),
        )
        second = context.Process(
            target=_quarantine_worker,
            args=(str(self.runs), second_ready_write, second_release_read),
        )
        try:
            first.start()
            os.close(first_ready_write)
            os.close(first_release_read)
            self.assertEqual(os.read(first_ready, 32), b"acquired\n")

            second.start()
            os.close(second_ready_write)
            os.close(second_release_read)
            readable, _, _ = select.select([second_ready], [], [], 0.1)
            self.assertEqual(readable, [])

            os.write(first_release_write, b"release")
            self.assertEqual(os.read(second_ready, 32), b"acquired\n")
            os.write(second_release_write, b"release")
        finally:
            for descriptor in (
                first_ready,
                first_release_write,
                second_ready,
                second_release_write,
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            first.join(timeout=2)
            second.join(timeout=2)
            if first.is_alive():
                first.terminate()
                first.join()
            if second.is_alive():
                second.terminate()
                second.join()
        self.assertEqual(first.exitcode, 0)
        self.assertEqual(second.exitcode, 0)

    def test_replace_marker_preserves_a_concurrent_same_name_replacement(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        replacement = marker.new_marker(
            self.marker_path,
            run_id="f" * 64,
            instance=value.instance,
            container_id=value.container_id,
            container_name=value.container_name,
            image=value.image,
            endpoint=value.endpoint,
            credential_identity=value.credential_identity,
        )
        replaced = False

        def race(parent_fd: int, source_name: str, source_fd: int) -> None:
            del source_fd
            nonlocal replaced
            if source_name == self.marker_path.name and not replaced:
                replaced = True
                os.unlink(source_name, dir_fd=parent_fd)
                marker.create_marker(replacement, parent_fd=parent_fd)

        with mock.patch.object(marker, "_before_marker_commit", side_effect=race):
            with self.assertRaises(marker.MarkerError) as raised:
                marker.replace_marker(value.with_status(marker.STATUS_CLEANUP_FAILED))
        self.assertEqual(raised.exception.code, "marker_replaced")
        self.assertTrue(replaced)
        self.assertEqual(marker.load_marker(self.marker_path).run_id, "f" * 64)

    def test_replace_marker_source_swap_between_validation_and_publication_does_not_publish_foreign(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        swapped = False
        foreign = b"foreign source pathname"

        def race(parent_fd: int, source_name: str, source_fd: int) -> None:
            del source_fd
            nonlocal swapped
            if not swapped:
                swapped = True
                os.unlink(source_name, dir_fd=parent_fd)
                replacement = self.runs / source_name
                replacement.write_bytes(foreign)
                replacement.chmod(marker.MARKER_MODES)

        with mock.patch.object(marker, "_before_marker_commit", side_effect=race):
            with self.assertRaises(marker.MarkerError) as raised:
                marker.replace_marker(value.with_status(marker.STATUS_CLEANUP_FAILED))

        self.assertEqual(raised.exception.code, "marker_replaced")
        self.assertTrue(swapped)
        self.assertEqual(self.marker_path.read_bytes(), foreign)

    def test_replace_marker_preserves_a_raced_foreign_target(self) -> None:
        value = self.make_marker()
        marker.create_marker(value)
        foreign = value.with_status(marker.STATUS_CLEANUP_FAILED)
        raced = False

        def race(parent_fd: int, source_name: str, source_fd: int) -> None:
            del source_fd
            nonlocal raced
            if not raced:
                raced = True
                os.unlink(source_name, dir_fd=parent_fd)
                marker.create_marker(foreign, parent_fd=parent_fd)

        with mock.patch.object(marker, "_before_marker_commit", side_effect=race):
            with self.assertRaises(marker.MarkerError) as raised:
                marker.replace_marker(value.with_status(marker.STATUS_CLEANUP_FAILED))
        self.assertEqual(raised.exception.code, "marker_replaced")
        self.assertTrue(raced)
        self.assertEqual(marker.load_marker(self.marker_path).run_id, foreign.run_id)

    def test_replace_marker_rejects_a_replacement_present_before_first_open(self) -> None:
        original = self.make_marker()
        marker.create_marker(original)
        _, original_identity = marker.load_marker_with_identity(self.marker_path)
        replacement = original.with_status(marker.STATUS_CLEANUP_FAILED)
        self.marker_path.unlink()
        marker.create_marker(original.with_status(marker.STATUS_CLEANUP_FAILED))

        with self.assertRaises(marker.MarkerError) as raised:
            marker.replace_marker(replacement, expected=original_identity)
        self.assertEqual(raised.exception.code, "marker_replaced")
        self.assertEqual(marker.load_marker(self.marker_path).status, marker.STATUS_CLEANUP_FAILED)

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
