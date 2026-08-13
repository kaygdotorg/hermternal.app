#!/usr/bin/env python3
"""Focused regression tests for the v3 Phase-A/Phase-B trust boundary.

These tests intentionally exercise the closed ED37/VC45 contract directly with
an immutable candidate-4 matrix fixture.  They do not execute the candidate
shell, run replay, mutate a real repository, or provision an approval anchor.
"""
from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path


BUNDLE = Path(__file__).resolve().parent
TEST32_JSON = Path("/private/tmp/task464-test32-json.json")
TEST32_SHELL = Path("/private/tmp/task464-test32-shell.sh")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PHASE_A = load_module("task409_phase_a_v3_tests", BUNDLE / "task409_execution_preflight_v3.py")
PHASE_B = load_module("task409_phase_b_v3_tests", BUNDLE / "task409_post_replay_identity_v3.py")


class ExecutionContractV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.json_path = TEST32_JSON.resolve()
        cls.shell_path = TEST32_SHELL.resolve()
        cls.document = json.loads(cls.json_path.read_text(encoding="utf-8"))
        cls.shell_raw = cls.shell_path.read_bytes()
        cls.shell_sha = PHASE_A.hashlib.sha256(cls.shell_raw).hexdigest()
        cls.shell_meta = {
            "body_bytes": len(cls.shell_raw),
            "body_lines": cls.shell_raw.count(b"\n"),
            "terminal_byte_hex": cls.shell_raw[-1:].hex(),
        }

    def _validate_contract(self, document: dict) -> None:
        PHASE_A._canonical_execution_contract(
            document,
            self.json_path,
            self.shell_raw,
            self.shell_sha,
            self.shell_meta,
        )

    def test_actual_lf_baseline_passes_closed_ed37_vc45_contract(self) -> None:
        self.assertEqual(self.shell_raw[-1:], b"\n")
        self.assertEqual(self.shell_raw.count(b"\n"), self.document["validation_contract"]["driver_shell_body_lines"])
        self.assertNotEqual(self.shell_raw.count(bytes((0x5C, 0x6E))), self.shell_raw.count(b"\n"))
        self._validate_contract(copy.deepcopy(self.document))

    def test_literal_backslash_n_line_count_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.document)
        literal_backslash_n_count = self.shell_raw.count(bytes((0x5C, 0x6E)))
        self.assertNotEqual(literal_backslash_n_count, self.shell_raw.count(b"\n"))
        mutated["validation_contract"]["driver_shell_body_lines"] = literal_backslash_n_count
        with self.assertRaises(PHASE_A.Reject):
            self._validate_contract(mutated)

    def test_candidate_derived_vc_authorities_are_pinned(self) -> None:
        mutations = {
            "ordered_lanes": (lambda value: value[:-1], "ordered lane authority differs"),
            "live_overlap": (
                lambda value: {
                    **value,
                    "stage_two_required_d3_overlap_paths": list(value["stage_two_required_d3_overlap_paths"])[:-1],
                },
                "live overlap authority differs",
            ),
            "forbidden_ancestry": (lambda value: {**value, "authentication_range": "tampered"}, "forbidden ancestry authority differs"),
        }
        for field, (mutate, message) in mutations.items():
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.document)
                mutated[field] = mutate(mutated[field])
                with self.assertRaisesRegex(PHASE_A.Reject, message):
                    self._validate_contract(mutated)

    def test_coordinated_lane_source_and_projection_count_still_rejects(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["ordered_lanes"][0].pop("source_parent_state")
        mutated["validation_contract"]["declared_projection_state_maps"] = 6
        with self.assertRaisesRegex(PHASE_A.Reject, "ordered lane authority differs"):
            self._validate_contract(mutated)

    def test_coordinated_stage_two_source_and_count_still_rejects(self) -> None:
        mutated = copy.deepcopy(self.document)
        stage_two = mutated["live_overlap"]["stage_two_required_d3_overlap_paths"]
        stage_two.append("zz-coordinated-source-mutation")
        mutated["validation_contract"]["stage_two_d3_overlap_paths"] = 4
        with self.assertRaisesRegex(PHASE_A.Reject, "live overlap authority differs"):
            self._validate_contract(mutated)

    def test_coordinated_blob_matrix_source_and_all_scope_counts_still_rejects(self) -> None:
        mutated = copy.deepcopy(self.document)
        row = mutated["live_overlap"]["blob_matrix"][0]
        row["path"] = "0-coordinated-source-mutation"
        row["live_scope"] = True
        row["live_mechanical"] = True
        mutated["validation_contract"].update({
            "launcher_paths": 11,
            "live_paths": 23,
            "launcher_mechanical_paths": 10,
            "live_mechanical_paths": 22,
            "union_paths": 29,
            "intersection_paths": 5,
        })
        with self.assertRaisesRegex(PHASE_A.Reject, "live overlap authority differs"):
            self._validate_contract(mutated)

    def test_all_vc45_derived_fields_reject_individual_mutation(self) -> None:
        mutations = {
            "declared_projection_state_maps": lambda value: value + 1,
            "range_target_postcondition_paths": lambda value: value + 1,
            "launcher_paths": lambda value: value + 1,
            "live_paths": lambda value: value + 1,
            "launcher_mechanical_paths": lambda value: value + 1,
            "live_mechanical_paths": lambda value: value + 1,
            "union_paths": lambda value: value + 1,
            "intersection_paths": lambda value: value + 1,
            "stage_two_d3_overlap_paths": lambda value: value + 1,
            "final_matrix_modes": lambda value: value + " (tampered)",
            "rejected_auth_endpoints": lambda value: list(value) + ["0" * 40],
            "swift_source_sha": lambda value: value[:-1] + ("0" if value[-1] != "0" else "1"),
            "live_readme_80fe_blob": lambda value: value[:-1] + ("0" if value[-1] != "0" else "1"),
            "expected_pre_replay_missing_local_object": lambda value: value[:-1] + ("0" if value[-1] != "0" else "1"),
            "scripts_readme_bytes": lambda value: value + 1,
            "scripts_readme_lines": lambda value: value + 1,
            "scripts_readme_sha256": lambda value: value[:-1] + ("0" if value[-1] != "0" else "1"),
            "scripts_readme_blob": lambda value: value[:-1] + ("0" if value[-1] != "0" else "1"),
        }
        self.assertEqual(set(mutations), {
            "declared_projection_state_maps", "range_target_postcondition_paths", "launcher_paths", "live_paths",
            "launcher_mechanical_paths", "live_mechanical_paths", "union_paths", "intersection_paths",
            "stage_two_d3_overlap_paths", "final_matrix_modes", "rejected_auth_endpoints", "swift_source_sha",
            "live_readme_80fe_blob", "expected_pre_replay_missing_local_object", "scripts_readme_bytes",
            "scripts_readme_lines", "scripts_readme_sha256", "scripts_readme_blob",
        })
        for field, mutate in mutations.items():
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.document)
                mutated["validation_contract"][field] = mutate(mutated["validation_contract"][field])
                with self.assertRaises(PHASE_A.Reject):
                    self._validate_contract(mutated)

    def test_mapped_ed_vc_field_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["validation_contract"]["driver_schema"] = "tampered.driver"
        with self.assertRaises(PHASE_A.Reject):
            self._validate_contract(mutated)

    def test_direct_canonical_mode_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["execution_driver"]["mode"] = "online"
        with self.assertRaises(PHASE_A.Reject):
            self._validate_contract(mutated)

    def test_mutation_contract_digest_is_independently_authenticated(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["execution_driver"]["mutation_contract"]["scope_rule"] = "candidate-controlled"
        with self.assertRaises(PHASE_A.Reject):
            self._validate_contract(mutated)

    def test_reproducible_hash_command_digest_is_independently_authenticated(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["execution_driver"]["reproducible_hash_commands"]["raw_sha256"] = "arbitrary command"
        with self.assertRaises(PHASE_A.Reject):
            self._validate_contract(mutated)

    def test_trusted_contract_digest_constants_match_embedded_objects(self) -> None:
        self.assertEqual(
            PHASE_A._trusted_contract_sha256(PHASE_A.EXPECTED_MUTATION_CONTRACT),
            PHASE_A.EXPECTED_MUTATION_CONTRACT_SHA256,
        )
        self.assertEqual(
            PHASE_A._trusted_contract_sha256(PHASE_A.EXPECTED_REPRODUCIBLE_HASH_COMMANDS),
            PHASE_A.EXPECTED_REPRODUCIBLE_HASH_COMMANDS_SHA256,
        )

    def _markdown_check(self, shell_raw: bytes, *, suffix: bytes = b"") -> None:
        shell_sha = PHASE_A.hashlib.sha256(shell_raw).hexdigest()
        shell_lines = shell_raw.count(b"\n")
        shell_meta = {
            "body_bytes": len(shell_raw),
            "body_lines": shell_lines,
            "terminal_byte_hex": shell_raw[-1:].hex(),
        }
        metadata = (
            f"Driver shell SHA-256: `{shell_sha}`\n"
            f"normalized JSON identity `{'0' * 64}`\n"
            f"Shell body bytes | `{len(shell_raw)}`\n"
            f"Shell body lines | `{shell_lines}`\n"
            f"terminal byte `{shell_raw[-1:].hex()}`\n"
        ).encode()
        markdown = b"# proof\n" + metadata + b"\n" + PHASE_A.REQUIRED_HEADING + b"```bash\n" + shell_raw + b"```\n" + suffix
        PHASE_A._check_markdown(markdown, shell_raw, shell_sha, "0" * 64, shell_meta)

    def test_runtime_final_head_placeholder_inside_fence_is_accepted(self) -> None:
        shell = b"#!/bin/bash\nprintf 'FINAL_HEAD=%s\\n' \"$CURRENT_HEAD\"\n"
        self._markdown_check(shell)

    def test_duplicate_standalone_closing_fence_is_rejected(self) -> None:
        shell_lines = self.shell_raw.count(b"\n")
        metadata = (
            f"Driver shell SHA-256: `{self.shell_sha}`\n"
            f"normalized JSON identity `{'0' * 64}`\n"
            f"Shell body bytes | `{len(self.shell_raw)}`\n"
            f"Shell body lines | `{shell_lines}`\n"
            f"terminal byte `{self.shell_raw[-1:].hex()}`\n"
        ).encode()
        markdown = metadata + PHASE_A.REQUIRED_HEADING + b"```bash\n" + self.shell_raw + b"```\ntrailing\n```\n"
        with self.assertRaises(PHASE_A.Reject):
            PHASE_A._check_markdown(markdown, self.shell_raw, self.shell_sha, "0" * 64, self.shell_meta)

    def test_inline_triple_backticks_inside_shell_body_are_accepted(self) -> None:
        shell = b"#!/bin/bash\nprintf '%s\\n' 'inline ``` marker'\n"
        self._markdown_check(shell)

    def test_concrete_final_head_inside_fence_is_rejected(self) -> None:
        shell = b"#!/bin/bash\nFINAL_HEAD=0123456789abcdef0123456789abcdef01234567\n"
        with self.assertRaises(PHASE_A.Reject):
            self._markdown_check(shell)

    def test_explicit_ref_inside_fence_is_rejected(self) -> None:
        shell = b"#!/bin/bash\nFINAL_HEAD=refs/heads/candidate-4\n"
        with self.assertRaises(PHASE_A.Reject):
            self._markdown_check(shell)

    def test_concrete_alias_boundaries_inside_fence_reject(self) -> None:
        values = ("0" * 40, "refs/heads/candidate-4")
        boundaries = (" ", "\t", "'", '"', "|", "&", ")", "\n")
        for value in values:
            for boundary in boundaries:
                with self.subTest(value=value[:4], boundary=repr(boundary)):
                    shell = f"#!/bin/bash\nFINAL_HEAD={value}{boundary}\n".encode()
                    with self.assertRaises(PHASE_A.Reject):
                        self._markdown_check(shell)

        for value in values:
            with self.subTest(value=value[:4], boundary="end-of-input"):
                shell = f"#!/bin/bash\nFINAL_HEAD={value}".encode()
                with self.assertRaises(PHASE_A.Reject):
                    self._markdown_check(shell)

    def test_oid_hex_continuation_does_not_false_match(self) -> None:
        shell = b"#!/bin/bash\nFINAL_HEAD=" + (b"0" * 40) + b"a\n"
        self._markdown_check(shell)

    def test_ref_continuation_is_a_complete_concrete_identity(self) -> None:
        shell = b"#!/bin/bash\nFINAL_HEAD=refs/heads/candidate-4-extra\n"
        with self.assertRaises(PHASE_A.Reject):
            self._markdown_check(shell)

    def test_alias_placeholder_outside_fence_is_rejected(self) -> None:
        with self.assertRaises(PHASE_A.Reject):
            self._markdown_check(self.shell_raw, suffix=b"\nfinal_head: %s\n")

    def test_concrete_aliases_outside_fence_are_rejected(self) -> None:
        for alias, value in (("final_head", "0" * 40), ("candidate_ref", "refs/heads/candidate-4")):
            with self.subTest(alias=alias):
                with self.assertRaises(PHASE_A.Reject):
                    self._markdown_check(self.shell_raw, suffix=f"\n{alias}: {value}\n".encode())

    def test_ed_and_vc_are_closed(self) -> None:
        unknown_ed = copy.deepcopy(self.document)
        unknown_ed["execution_driver"]["unexpected"] = True
        with self.assertRaises(PHASE_A.Reject):
            self._validate_contract(unknown_ed)

        unknown_vc = copy.deepcopy(self.document)
        unknown_vc["validation_contract"]["unexpected"] = True
        with self.assertRaises(PHASE_A.Reject):
            self._validate_contract(unknown_vc)


class PhaseBAnchorSignatureTests(unittest.TestCase):
    def test_authenticated_anchor_arguments_are_required_and_keyword_only(self) -> None:
        signature = inspect.signature(PHASE_B.validate_post_replay)
        parameters = signature.parameters
        for name in (
            "phase_a_manifest_path",
            "phase_a_manifest_sha256",
            "phase_a_approval_anchor_path",
            "phase_a_approval_digest",
        ):
            self.assertIn(name, parameters)
            self.assertEqual(parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)

    def test_current_anchor_signature_reaches_authentication_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            replay_root = base / "replay-root"
            repository = base / "repository"
            replay_root.mkdir(mode=0o700)
            repository.mkdir(mode=0o700)
            with self.assertRaises(PHASE_B.Reject):
                PHASE_B.validate_post_replay(
                    replay_root / "replay-result.json",
                    replay_root,
                    repository,
                    phase_a_manifest_path=base / "phase-a-manifest.json",
                    phase_a_manifest_sha256="0" * 64,
                    phase_a_approval_anchor_path=base / "phase-a-anchor.json",
                    phase_a_approval_digest="1" * 64,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
