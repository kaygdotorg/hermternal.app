#!/usr/bin/env python3
"""Test the one shared ROOT_PY parent-binding transform without replay."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent; sys.path.insert(0, os.fspath(HERE))
import linux_parent_binding_authority_v3 as AUTHORITY  # noqa: E402
import linux_retained_driver_v5 as DRIVER  # noqa: E402
import platform_successor  # noqa: E402


class ParentBindingAuthorityV3Tests(unittest.TestCase):
    def setUp(self):
        self.shell = AUTHORITY.generate()["shell"]

    def _root_program(self, label: str) -> str:
        match = re.search(rb'identity="\$\(\$PYTHON - "' + re.escape(label.encode()) + rb'".*?<<\'PY\'\n(.*?)\nPY\n\)"', self.shell, re.S)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def _run(self, label: str, program: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="issue397-parent-binding-") as temporary:
            parent = Path(temporary) / "parent"; parent.mkdir(mode=0o700)
            source = Path(temporary) / "source"; source.mkdir(mode=0o700)
            subprocess.run(["/usr/bin/git", "init", "-q", os.fspath(source)], check=True)
            root = parent / ("clean-root" if label == "create clean primary root" else "replay-root")
            child = root / ("repository" if label == "create clean primary root" else "replay")
            return subprocess.run([sys.executable, "-B", "-c", program, label, os.fspath(root), os.fspath(child), os.fspath(source), os.fspath(Path(temporary) / "unused-clean"), "0"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_deterministic_parity_and_fixed_point(self):
        first, second = AUTHORITY.generate(), AUTHORITY.generate()
        self.assertEqual(first, second)
        for role, name in (("json", "candidate-five.json"), ("markdown", "candidate-five.md"), ("shell", "candidate-five.sh")):
            self.assertEqual(first[role], (AUTHORITY.AUTHORITY_ROOT / name).read_bytes())
        authority = platform_successor.load_approved()[2]
        self.assertEqual(authority.extract_shell(first["markdown"]), first["shell"])
        restored = first["shell"].replace(AUTHORITY.NEW_PARENT_COMPARISON, AUTHORITY.OLD_PARENT_COMPARISON)
        self.assertEqual(AUTHORITY.transform_parent_binding(restored).count(AUTHORITY.NEW_PARENT_COMPARISON), 2)

    def test_exact_one_shared_source_transform(self):
        programs = [self._root_program("create clean primary root"), self._root_program("create replay root")]
        self.assertEqual(programs[0], programs[1])
        self.assertEqual(self.shell.count(AUTHORITY.NEW_PARENT_COMPARISON), 2)
        self.assertNotIn(AUTHORITY.OLD_PARENT_COMPARISON, self.shell)
        source = re.search(r'def stable_parent_identity\(st\):(.*?)if stable_parent_identity', programs[0], re.S).group(0).rsplit('if ', 1)[0]
        namespace = {"stat": stat}; exec(source, namespace)
        baseline = SimpleNamespace(st_dev=1, st_ino=2, st_uid=3, st_mode=0o40700, st_nlink=2, st_mtime_ns=1, st_ctime_ns=1)
        self.assertEqual(namespace["stable_parent_identity"](baseline), ("1", "2", "3", "0700"))
        for field, value in (("st_dev", 9), ("st_ino", 9), ("st_uid", 9), ("st_mode", 0o40755)):
            candidate = SimpleNamespace(**{**baseline.__dict__, field: value})
            self.assertNotEqual(namespace["stable_parent_identity"](baseline), namespace["stable_parent_identity"](candidate))

    def test_runtime_authenticates_the_parent_binding_manifest(self):
        driver = DRIVER.load_driver(); original = driver.stable_read
        def altered(path, label, **kwargs):
            snapshot = original(path, label, **kwargs)
            if path.name == "parent-binding-adaptation-manifest.json":
                return driver.Snapshot(snapshot.path, snapshot.raw, "0" * 64, snapshot.identity)
            return snapshot
        driver.stable_read = altered
        with self.assertRaises(driver.Reject): driver.load_frozen_authority()

    def test_clean_and_replay_accept_parent_link_count_churn(self):
        for label in ("create clean primary root", "create replay root"):
            result = self._run(label, self._root_program(label))
            self.assertEqual(result.returncode, 0, result.stderr)
            fields = result.stdout.strip().split("\t")
            self.assertGreaterEqual(int(fields[6]), 3, result.stdout)

    def test_root_child_and_parent_replacements_or_mode_attacks_reject(self):
        label = "create clean primary root"; program = self._root_program(label)
        root_line = "os.mkdir(name, 0o700, dir_fd=parent_fd)"
        child_line = "os.mkdir(os.path.basename(child), 0o700, dir_fd=root_fd)"
        attacks = (
            program.replace(root_line, root_line + "\nos.rmdir(name, dir_fd=parent_fd)\nos.symlink('/tmp', name, dir_fd=parent_fd)", 1),
            program.replace(child_line, child_line + "\nos.chmod(os.path.basename(child), 0o755, dir_fd=root_fd)", 1),
            program.replace(child_line, child_line + "\nos.rename(name, name + '-old', src_dir_fd=parent_fd, dst_dir_fd=parent_fd)\nos.mkdir(name, 0o700, dir_fd=parent_fd)", 1),
            program.replace(child_line, child_line + "\nos.chmod(parent, 0o755)", 1),
        )
        for attacked in attacks:
            result = self._run(label, attacked)
            self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__": unittest.main(verbosity=2)
