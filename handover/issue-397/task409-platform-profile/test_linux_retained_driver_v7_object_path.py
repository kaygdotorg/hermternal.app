#!/usr/bin/env python3
"""Test replay corrections against disposable and frozen local inputs."""
from __future__ import annotations

import os
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import linux_retained_driver_v7 as DRIVER

REPOSITORY = Path(__file__).resolve().parents[3]
MATRIX = REPOSITORY / "handover/issue-397/task409-matrix/hermternal-task409-final-execution-matrix.json"
TERMINAL_README = "apps/web/src/lib/terminal/README.md"
OLD = b"objects = os.path.realpath(out('rev-parse', '--git-path', 'objects'))"
NEW = b"""objects_value = out('rev-parse', '--git-path', 'objects')
objects = os.path.realpath(
    objects_value if os.path.isabs(objects_value) else os.path.join(repo, objects_value)
)"""
ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/dev/null",
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
}


class ReplayObjectPathTests(unittest.TestCase):
    def test_every_commit_uses_one_active_operation_post_state_per_path(self) -> None:
        data = json.loads(MATRIX.read_bytes())
        operations = []
        for lane in data["ordered_lanes"]:
            for source in lane.get("range", {}).get("source_commits", []):
                states = source["target_states"]
                self.assertEqual(len(source["changed_paths"]), len(set(source["changed_paths"])))
                self.assertEqual(set(states), set(source["changed_paths"]))
                operations.append((f"range:{lane['id']}:{source['commit']}", states))

            semantic = lane.get("semantic_delta")
            if semantic:
                paths = semantic["delta_paths"]
                target = semantic["child"]
            elif lane.get("kind") == "single-semantic-commit":
                paths = lane["source_commit"]["changed_paths"]
                target = lane["source_commit"]["commit"]
            else:
                continue
            self.assertEqual(len(paths), len(set(paths)))
            states = {}
            for path in paths:
                raw = subprocess.run(
                    ["/usr/bin/git", "-C", os.fspath(REPOSITORY), "ls-tree", target, "--", path],
                    cwd="/", env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ).stdout.decode("utf-8").strip()
                mode, kind, blob, recorded = raw.replace("\t", " ", 1).split(" ", 3)
                self.assertEqual((kind, recorded), ("blob", path))
                states[path] = {"blob": blob, "mode": mode, "type": "file"}
            operations.append((f"semantic:{lane['id']}", states))

        for stage, enabled, blob_key, mode_key in (
            ("launcher", "launcher_mechanical", "d3_launcher_blob", "d3_launcher_mode"),
            ("live", "live_mechanical", "80fe_live_blob", "80fe_live_mode"),
        ):
            rows = [row for row in data["live_overlap"]["blob_matrix"] if row[enabled]]
            self.assertEqual(len(rows), len({row["path"] for row in rows}))
            states = {
                row["path"]: {"blob": row[blob_key], "mode": row[mode_key], "type": "file"}
                for row in rows
            }
            operations.append((f"matrix:{stage}", states))
        operations.append(("merge:scripts-readme", {
            "scripts/README.md": {
                "blob": "d74f0c1431901f83e736389395a122c48e521a32",
                "mode": "100644", "type": "file",
            },
        }))

        self.assertEqual(len(operations), 79)
        for label, states in operations:
            with self.subTest(operation=label):
                self.assertTrue(states)
                self.assertEqual(len(states), len(set(states)))
                for path, state in states.items():
                    self.assertTrue(path)
                    self.assertRegex(state["blob"], r"^[0-9a-f]{40}$")
                    self.assertRegex(state["mode"], r"^[0-9]{6}$")
                    self.assertEqual(state["type"], "file")

        stdin = DRIVER.derive_contract().stdin
        self.assertNotIn(b'target_state="$(target_state_record "$target_path")"', stdin)
        self.assertEqual(stdin.count(b"active operation target row count mismatch"), 1)
        self.assertEqual(stdin.count(b"EXPECTED_OPERATION_TARGET_ROWS+=("), 3)
        self.assertIn(b"local EXPECTED_OPERATION_TARGET_ROWS=(\"scripts/README.md\"", stdin)
        self.assertEqual(stdin.count(DRIVER.PACK_OBJECTS_WITHOUT_REVERSE_INDEX), 1)
        self.assertNotIn(DRIVER.PACK_OBJECTS, stdin)

    def test_relative_git_path_is_resolved_from_replay_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            replay = Path(directory) / "repository"
            subprocess.run(
                ["/usr/bin/git", "init", os.fspath(replay)], cwd="/", env=ENV,
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            value = subprocess.run(
                ["/usr/bin/git", "-C", os.fspath(replay), "rev-parse", "--git-path", "objects"],
                cwd="/", env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout.decode("utf-8").strip()
            self.assertEqual(value, ".git/objects")
            self.assertNotEqual(os.path.realpath(value), os.fspath(replay / ".git/objects"))
            self.assertEqual(os.path.realpath(replay / value), os.fspath(replay / ".git/objects"))

        stdin = DRIVER.derive_contract().stdin
        self.assertEqual(stdin.count(OLD), 0)
        self.assertEqual(stdin.count(NEW), 1)

    def test_ordered_range_state_matches_current_staged_blob(self) -> None:
        data = json.loads(MATRIX.read_bytes())
        declared = []
        for lane in data["ordered_lanes"]:
            for commit in lane.get("range", {}).get("source_commits", []):
                state = commit.get("target_states", {}).get(TERMINAL_README)
                if state:
                    declared.append((lane["order"], commit["commit"], state))
        self.assertEqual(
            [(order, commit, state["blob"]) for order, commit, state in declared],
            [
                (1, "013ea2ef992bc309290efe6f8d899a4c85381f80", "9a14f7add8200e90fadee740a27647ea4de4e0fe"),
                (1, "4b2ca9df19f42f332ef726017af6682108ab7a66", "e4f9814aa3ec4d7dbecd9fed4c680a9963ab4a88"),
                (1, "5559e9ad4cf78debc98e8935c47cdc956535f96c", "8690ed844473cf8db70a7953a8dce3ea746a3da7"),
            ],
        )
        staged = f"100644 {declared[0][2]['blob']} 0\t{TERMINAL_README}"
        mode, blob, stage_path = staged.split(" ", 2)
        self.assertEqual((mode, blob, stage_path), ("100644", declared[0][2]["blob"], f"0\t{TERMINAL_README}"))
        matches = {
            (state.get("blob"), state.get("mode"), state.get("type"))
            for _order, _commit, state in declared
            if state.get("blob") == blob and state.get("mode") == mode
        }
        self.assertEqual(matches, {(blob, mode, "file")})

        stdin = DRIVER.derive_contract().stdin
        self.assertNotIn(b'target_state="$(target_state_record "$target_path")"', stdin)
        self.assertEqual(stdin.count(b"active operation target path order mismatch"), 1)

    def test_cherry_signs_bind_prior_and_current_range_members(self) -> None:
        sources = [
            "013ea2ef992bc309290efe6f8d899a4c85381f80",
            "4b2ca9df19f42f332ef726017af6682108ab7a66",
            "5559e9ad4cf78debc98e8935c47cdc956535f96c",
        ]
        for prior, current in zip(sources, sources[1:]):
            parent = subprocess.run(
                ["/usr/bin/git", "-C", os.fspath(REPOSITORY), "rev-parse", f"{current}^"],
                cwd="/", env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout.decode("ascii").strip()
            self.assertEqual(parent, prior)
        stdin = DRIVER.derive_contract().stdin
        self.assertNotIn(b'duplicate source patch rejected by git cherry: $record', stdin)
        self.assertEqual(stdin.count(b'expected_cherry+="- $prior_source"$\'\\n\''), 1)

    def test_semantic_ls_tree_uses_space_and_tab_fields(self) -> None:
        row = subprocess.run(
            ["/usr/bin/git", "-C", os.fspath(REPOSITORY),
             "ls-tree", "befb8c7e673157932f5f13242d863e64806cffac", "--", TERMINAL_README.replace("README.md", "renderer.test.ts")],
            cwd="/", env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        self.assertTrue(row.startswith(b"100644 blob 8d489b746e2dc0f6c15b32b0174f62db58c308e3\t"))
        stdin = DRIVER.derive_contract().stdin
        self.assertNotIn(b'read -r new_mode target_type new_blob _ <<< "$target_line"', stdin)
        self.assertEqual(stdin.count(b'IFS=$\' \\t\' read -r new_mode target_type new_blob target_path'), 1)
        checkout = b'git_replay checkout-index --force -- "$path"'
        refresh = b'git_replay update-index --refresh -- "$path"'
        self.assertEqual(stdin.count(refresh), 1)
        self.assertLess(stdin.index(checkout), stdin.index(refresh))
        self.assertNotIn(b"from pathlib import Path\nmatrix, stage, output", stdin)
        self.assertNotIn(b"from pathlib import Path\ndata = json.loads(Path(sys.argv[1]).read_bytes())\nexpected = [value.encode()", stdin)
        self.assertNotIn(DRIVER.PARENT_IDENTITY_CHECK, stdin)
        self.assertEqual(stdin.count(DRIVER.STABLE_PARENT_IDENTITY_CHECK), 1)
        self.assertIn(b"if actual != wanted[:4]", stdin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
