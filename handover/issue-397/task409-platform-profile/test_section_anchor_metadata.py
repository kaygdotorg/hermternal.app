#!/usr/bin/env python3
"""Offline regression coverage for the section-anchor LF successor."""
from __future__ import annotations
import json, os, subprocess, sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent; sys.path.insert(0, os.fspath(HERE))
import linux_anchor_authority_v2 as AUTH  # noqa: E402
import linux_retained_driver_v4 as DRIVER  # noqa: E402
import section_anchor_metadata as POLICY  # noqa: E402


class SectionAnchorMetadataTests(unittest.TestCase):
    def test_exact_prefix_reproduction_and_one_field_repair(self):
        old = json.loads((HERE.parent / "task464-candidate5-linux-v1-final" / "candidate-five.json").read_bytes())
        self.assertEqual(old["live_overlap"]["scripts_readme"]["section_anchor"], POLICY.LEGACY_DOUBLE_ESCAPED_ANCHOR)
        with self.assertRaises(POLICY.Reject): POLICY.anchor_value(old, "pre-fix")
        fixed = POLICY.repair_legacy(old)
        POLICY.strict_one_field_diff(old, fixed)
        self.assertEqual(POLICY.anchor_value(fixed, "fixed").encode(), b"## Disposable Caddy proof renderer\n")

    def test_rejects_malformed_missing_duplicate_and_wrong_values(self):
        for raw in (b"{", b'{"live_overlap":{"live_overlap":{}}}', b'{"live_overlap":{"scripts_readme":{}}}', b'{"live_overlap":{"scripts_readme":{"section_anchor":"wrong"}}}'):
            with self.subTest(raw=raw), self.assertRaises(POLICY.Reject):
                value = POLICY.strict_document(raw, "bad"); POLICY.anchor_value(value, "bad")

    def test_deterministic_json_markdown_shell_parity_and_derived_syntax(self):
        left, right = AUTH.generate(), AUTH.generate()
        self.assertEqual(left, right)
        document = POLICY.strict_document(left["json"], "generated")
        self.assertEqual(POLICY.anchor_value(document, "generated"), POLICY.CANONICAL_ANCHOR)
        authority = AUTH.platform_successor.load_approved()[2]
        self.assertEqual(authority.extract_shell(left["markdown"]), left["shell"])
        self.assertEqual(document["execution_driver"]["shell"].encode(), left["shell"])
        contract = DRIVER.derive_contract()
        self.assertEqual(subprocess.run(["/bin/bash", "-n"], input=contract.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode, 0)
        DRIVER.load_driver().compile_derived(contract.stdin)


if __name__ == "__main__": unittest.main(verbosity=2)
