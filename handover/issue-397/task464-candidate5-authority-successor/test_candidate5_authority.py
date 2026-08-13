#!/usr/bin/env python3
"""Regressions for JSON, Markdown, and fresh CLI authority."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("candidate5_authority", HERE / "candidate5_authority.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="issue397-authority-")
        self.root = Path(self.temp.name).resolve(); os.chmod(self.root, 0o700)
        self.shell = b"#!/bin/bash\nprintf 'offline only\\n'\n"
        self.paths = {role: self.root / name for role, name in MODULE.ROLE_NAMES.items()}
        token = "0" * 64
        template_path = HERE.parent / "task409-matrix" / "hermternal-task409-final-execution-matrix.json"
        template = json.loads(template_path.read_bytes())
        while True:
            doc = copy.deepcopy(template)
            doc["artifact_paths"] = {"markdown": str(self.paths["markdown"]), "json": str(self.paths["json"])}
            execution = doc["execution_driver"]
            execution["source_of_truth"] = "/execution_driver/shell"
            execution["shell"] = self.shell.decode()
            execution["shell_sha256"] = hashlib.sha256(self.shell).hexdigest()
            execution["matrix_identity"]["expected_normalized_sha256"] = token
            execution["argv"] = list(MODULE.ARGV)
            execution["strict_git_environment"] = copy.deepcopy(MODULE.STRICT_ENV)
            execution["non_authoritative_standalone_scripts"] = [{"path": "/obsolete/stale.sh"}]
            raw = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode()
            nxt = MODULE.normalized_json_sha256(raw, token)
            if nxt == token: break
            token = nxt
        self.normalized = token; self.json_raw = raw
        self.markdown = b"# Candidate five\n\n" + MODULE.HEADING + MODULE.OPENING + self.shell + b"```\n"
        for role, raw_value in (("markdown", self.markdown), ("json", self.json_raw), ("shell", self.shell)):
            self.paths[role].write_bytes(raw_value); self.paths[role].chmod(0o600)
        self.descriptor = self.root / "authority.json"; self.write_descriptor()

    def tearDown(self): self.temp.cleanup()

    def descriptor_value(self):
        return {"schema": MODULE.SCHEMA, "roles": [{"role": role, "path": str(self.paths[role]), "sha256": hashlib.sha256(self.paths[role].read_bytes()).hexdigest()} for role in MODULE.ROLES], "normalized_json_sha256": self.normalized}

    def write_descriptor(self, value=None):
        raw = (json.dumps(value or self.descriptor_value(), sort_keys=True, indent=2) + "\n").encode(); self.descriptor.write_bytes(raw); self.descriptor.chmod(0o600); self.descriptor_sha = hashlib.sha256(raw).hexdigest()

    def validate(self): return MODULE.validate(self.descriptor, self.root, self.descriptor_sha)

    def rewrite_json(self, mutation):
        document = json.loads(self.json_raw)
        mutation(document)
        token = document["execution_driver"]["matrix_identity"]["expected_normalized_sha256"]
        while True:
            raw = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
            next_token = MODULE.normalized_json_sha256(raw, token)
            if next_token == token:
                break
            token = next_token
            document["execution_driver"]["matrix_identity"]["expected_normalized_sha256"] = token
        self.paths["json"].write_bytes(raw)
        self.normalized = token
        self.write_descriptor()

    def test_baseline_fresh_cli_uses_only_validated_shell(self):
        result = self.validate(); self.assertEqual(result.stdin, self.shell); self.assertEqual(result.argv, MODULE.ARGV); self.assertNotIn(str(self.paths["shell"]), result.argv)

    def test_closed_cli_and_environment_reject(self):
        mutations = (
            lambda doc: doc["execution_driver"].__setitem__("extra", True),
            lambda doc: doc["execution_driver"].pop("argv"),
            lambda doc: doc["execution_driver"]["argv"].reverse(),
            lambda doc: doc["execution_driver"]["argv"].__setitem__(-1, "-c"),
            lambda doc: doc["execution_driver"]["argv"].__setitem__(2, "PATH=/tmp"),
            lambda doc: doc["execution_driver"].__setitem__("source_of_truth", "/tmp/stale.sh"),
            lambda doc: doc["execution_driver"]["strict_git_environment"]["set"].__setitem__("GIT_CONFIG_GLOBAL", "/tmp/config"),
            lambda doc: doc["execution_driver"]["strict_git_environment"]["allowlist"].append("GIT_CONFIG_PARAMETERS"),
            lambda doc: doc["execution_driver"]["strict_git_environment"].__setitem__("extra", True),
            lambda doc: doc.__setitem__("extra", True),
        )
        for mutation in mutations:
            self.paths["json"].write_bytes(self.json_raw)
            self.normalized = self.descriptor_value()["normalized_json_sha256"]
            self.rewrite_json(mutation)
            with self.assertRaises(MODULE.Reject): self.validate()

        self.paths["json"].write_bytes(self.json_raw)
        duplicate = self.json_raw.replace(
            b'    "argv":', b'    "argv": ["/bin/false"],\n    "argv":', 1
        )
        self.paths["json"].write_bytes(duplicate)
        self.write_descriptor()
        with self.assertRaises(MODULE.Reject):
            self.validate()

    def test_duplicate_key_role_order_extra_and_path_swap_reject(self):
        raw = self.descriptor.read_text().replace('"schema":', '"schema": "duplicate",\n  "schema":', 1).encode(); self.descriptor.write_bytes(raw); self.descriptor_sha = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(MODULE.Reject): self.validate()
        for mutation in ("order", "extra", "path"):
            value = self.descriptor_value()
            if mutation == "order": value["roles"][0], value["roles"][1] = value["roles"][1], value["roles"][0]
            elif mutation == "extra": value["extra"] = True
            else: value["roles"][0]["path"] = str(self.root / "alternate.md")
            self.write_descriptor(value)
            with self.assertRaises(MODULE.Reject): self.validate()

    def test_hash_whitespace_normalization_and_declarations_reject(self):
        for mutation in ("hash", "whitespace", "normalized", "shell-declaration"):
            if mutation == "hash":
                value = self.descriptor_value(); value["roles"][2]["sha256"] = "f" * 64; self.write_descriptor(value)
            elif mutation == "whitespace":
                self.paths["json"].write_bytes(self.json_raw.replace(b"{\n", b"{ \n", 1)); self.write_descriptor()
            elif mutation == "normalized":
                value = self.descriptor_value(); value["normalized_json_sha256"] = "f" * 64; self.write_descriptor(value)
            else:
                changed = json.loads(self.json_raw); changed["execution_driver"]["shell_sha256"] = "f" * 64; self.paths["json"].write_text(json.dumps(changed, sort_keys=True, indent=2) + "\n"); self.write_descriptor()
            with self.assertRaises(MODULE.Reject): self.validate()
            self.paths["json"].write_bytes(self.json_raw); self.write_descriptor()

    def test_markdown_fence_lf_and_stale_shell_reject(self):
        for raw in (self.markdown + b"```\n", self.markdown.replace(self.shell, self.shell[:-1]), self.markdown.replace(b"\n```\n", b"\r\n```\r\n")):
            self.paths["markdown"].write_bytes(raw); self.write_descriptor()
            with self.assertRaises(MODULE.Reject): self.validate()
        self.paths["markdown"].write_bytes(self.markdown)
        changed = json.loads(self.json_raw); changed["execution_driver"]["non_authoritative_standalone_scripts"] = [{"path": str(self.paths["shell"])}]; self.paths["json"].write_text(json.dumps(changed, sort_keys=True, indent=2) + "\n"); self.write_descriptor()
        with self.assertRaises(MODULE.Reject): self.validate()

    def test_verified_module_executes_verified_bytes(self):
        source = self.root / "module.py"; source.write_bytes(b"VALUE = 'verified'\n"); source.chmod(0o600); digest = hashlib.sha256(source.read_bytes()).hexdigest()
        loaded = MODULE.verified_module(source, digest); source.write_bytes(b"VALUE = 'replacement'\n")
        self.assertEqual(loaded.VALUE, "verified")


if __name__ == "__main__": unittest.main(verbosity=2)
