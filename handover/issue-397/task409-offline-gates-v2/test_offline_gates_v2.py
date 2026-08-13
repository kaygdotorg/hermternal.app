#!/usr/bin/env python3
"""Offline checks for v3. Podman and final authorities are always faked."""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("offline_gates_v2", HERE / "offline_gates_v2.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MOD; SPEC.loader.exec_module(MOD)


class OfflineGatesV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name); os.chmod(self.root, 0o700)
        self.repository = self.root / "repository"; self.repository.mkdir(mode=0o700)
        files = {
            "apps/web/tests/e2e/ui-preview.spec.ts": "import AxeBuilder from 'axe'; test('native password activation clears live values', () => { if (activation === 'click') signIn.click(); if (activation === 'enter') password.press('Enter'); expect(x).toHaveValue(''); expect(y).toHaveValue(''); expect(z).toHaveValue(''); expect(q).toHaveValue(''); root.outerHTML; page.screenshot(); expect(value).not.toContain(passwordValue); expect(value).not.toContain(usernameValue); /* axe violations */ });\n",
            "apps/web/src/lib/live-artifact-policy.test.ts": "const LIVE_ARTIFACT_REDACTION = 'x'; const config = \"screenshot: 'off'\";\n",
            "apps/web/src/lib/live-screenshot-contract.test.ts": "blockedLiveScreenshotManifest({});\n",
        }
        for relative, content in files.items():
            path = self.repository / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content); os.chmod(path, 0o600)
        snap = lambda name: MOD.Snapshot(self.root / name, b"x", "a" * 64, (1, 2, os.getuid(), 0o600, 1, 1, 1, 1))
        self.chain = MOD.Chain(self.repository, MOD._identity(os.lstat(self.repository)), "4" * 40, "5" * 40, "6" * 40, "7" * 40, snap("result"), snap("completion"), snap("anchor"), snap("provenance"))
        self.pins = MOD.Pins(self.root / "profile.py", "0" * 64, self.root / "authority", self.root / "authority.py", "1" * 64, self.root / "wrapper.py", "2" * 64, self.root / "phase.py", "3" * 64, self.chain.expected_dev_base, "example.invalid/hermternal@sha256:" + "a" * 64, "a" * 64, "b" * 64)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def runner(self, argv, **_: object) -> subprocess.CompletedProcess[bytes]:
        command = tuple(argv[-1:])
        gate = next(gate for gate in MOD.GATES if gate.command == tuple(argv[-len(gate.command):]))
        output = {"git-head": self.chain.final_head, "git-tree": self.chain.final_tree, "git-main": self.chain.protected_main, "git-dev-base": self.chain.expected_dev_base, "git-clean": ""}.get(gate.gate_id, "PASS")
        return subprocess.CompletedProcess(argv, 0, (output + "\n").encode(), b"")

    def test_closed_podman_layout_and_dev_base_contract(self) -> None:
        argv = MOD.podman_argv(self.repository, MOD.GATES[0], self.pins)
        self.assertIn("--pull=never", argv); self.assertIn("--network=none", argv); self.assertIn("--read-only", argv)
        self.assertIn("--userns=keep-id", argv); self.assertIn("--cap-drop=ALL", argv); self.assertIn("--security-opt=no-new-privileges", argv)
        self.assertIn("type=bind,src=" + str(self.repository) + ",dst=/workspace,ro=true,relabel=private", argv)
        for path in MOD.WRITABLE_WEB_PATHS:
            self.assertIn(path + ":rw,nosuid,nodev,size=768m", argv)
        self.assertIn("/opt/hermternal/node_modules", " ".join(argv))
        records = MOD.run_gates(self.chain, self.pins, self.runner, lambda _: None)
        self.assertEqual([item["id"] for item in records], [gate.gate_id for gate in MOD.GATES])

    def test_dev_base_mismatch_and_pre_staged_toolchain_failure_reject(self) -> None:
        def wrong_dev(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if tuple(argv[-len(MOD.GATES[3].command):]) == MOD.GATES[3].command:
                result.stdout = ("8" * 40 + "\n").encode()
            return result
        with self.assertRaisesRegex(MOD.Reject, "git-dev-base"):
            MOD.run_gates(self.chain, self.pins, wrong_dev, lambda _: None)
        def missing_bun(*_, **__):
            if "info" in _[0]:
                return subprocess.CompletedProcess([], 0, b"true\n", b"")
            return subprocess.CompletedProcess([], 0, b'[{"RepoDigests":["x@sha256:' + b"a" * 64 + b'"],"Labels":{"org.hermternal.node":"26.7.0"}}]', b"")
        with self.assertRaisesRegex(MOD.Reject, "toolchain"):
            MOD.attest_image(self.pins, missing_bun)

    def test_deferred_pins_reject_without_mac_fallback(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "not finalized"):
            MOD.load_pins()

    def test_load_chain_uses_linux_fixture_and_snapshot_field(self) -> None:
        authority_root = self.root / "authority"; authority_root.mkdir(mode=0o700)
        for name in ("authority-descriptor.json", "provenance-manifest.json"):
            path = authority_root / name; path.write_text('{"schema":"fixture"}\n'); os.chmod(path, 0o600)
        result = self.root / "replay-result.json"; completion = self.root / "replay-completion.json"
        result_value = {"schema":"result/v1", "phase":"phase", "lane":"linux", "phase_a_manifest_sha256":"a" * 64, "phase_a_approval_digest":"b" * 64, "replay_root":str(self.root / "replay-root"), "replay_root_identity":{}, "repository":str(self.repository), "repository_identity":{}, "head_state":"detached", "final_head":"4" * 40, "parent":"3" * 40, "tree":"5" * 40, "base_commit":"1" * 40, "base_tree":"2" * 40, "protected_main_commit":"6" * 40, "required_ancestors":["1" * 40], "forbidden_ancestors":["9" * 40]}
        result.write_text(json.dumps(result_value)); os.chmod(result, 0o600)
        result_snapshot = MOD.stable_read(result, "fixture", mode=0o600)
        completion_value = {"schema":"completion/v1", "completion_marker":"OK", "stderr_policy":"empty", "returncode":0, "result_path":str(result), "result_sha256":result_snapshot.sha256, "driver_module_sha256":"driver", "driver_source_sha256":"shell", "markdown_sha256":"md", "json_sha256":"json", "shell_sha256":"shell", "provenance_sha256":MOD.stable_read(authority_root / "provenance-manifest.json", "fixture", mode=0o600).sha256, "source_commit":"a" * 40, "phase_a_evidence_path":str(self.root / "anchor.json"), "phase_a_evidence_sha256":"c" * 64}
        completion.write_text(json.dumps(completion_value)); os.chmod(completion, 0o600)
        (self.root / "replay-root").mkdir(mode=0o700)
        profile = types.SimpleNamespace(load=lambda: types.SimpleNamespace(authority_root=str(authority_root)))
        artifacts = {"shell": types.SimpleNamespace(sha256="shell"), "markdown": types.SimpleNamespace(sha256="md"), "json": types.SimpleNamespace(sha256="json")}
        authority = types.SimpleNamespace(validate=lambda *_: types.SimpleNamespace(artifacts=artifacts))
        replay_authority = types.SimpleNamespace(base_commit="1" * 40, base_tree="2" * 40, protected_main_commit="6" * 40, required_ancestors=["1" * 40], forbidden_ancestors=["9" * 40], source_commit="a" * 40)
        evidence = types.SimpleNamespace(manifest_sha256="a" * 64, approval_digest="b" * 64, snapshot=MOD.Snapshot(self.root / "anchor.json", b"x", "c" * 64, (1, 2, 3, 0o600, 1, 1, 1, 1)))
        wrapper = types.SimpleNamespace(RESULT_KEYS=frozenset(result_value), RESULT_SCHEMA="result/v1", RESULT_PHASE="phase", RESULT_LANE="linux", COMPLETION_KEYS=frozenset(completion_value), COMPLETION_SCHEMA="completion/v1", SUCCESS_OUTPUT=b"OK\n", STDERR_POLICY="empty", DRIVER_SHA256="driver", load_authority=lambda: replay_authority, load_phase_a_evidence=lambda *_: evidence)
        phase = types.SimpleNamespace(EVIDENCE_SCHEMA="fixture.v3")
        modules = [profile, authority, wrapper, phase]
        old = MOD.verified_module; MOD.verified_module = lambda *_: modules.pop(0)
        try:
            chain = MOD._load_chain(result, completion, self.pins.__class__(self.pins.profile_path, self.pins.profile_sha256, authority_root, self.pins.authority_module, self.pins.authority_sha256, self.pins.wrapper_module, self.pins.wrapper_sha256, self.pins.phase_a_module, self.pins.phase_a_sha256, self.pins.expected_dev_base, self.pins.image, self.pins.image_digest, self.pins.dependencies_sha256))
        finally:
            MOD.verified_module = old
        self.assertEqual(chain.phase_anchor.sha256, "c" * 64)
        self.assertEqual(chain.expected_dev_base, self.chain.expected_dev_base)

    def test_main_rejects_final_reread_mutation(self) -> None:
        old_pins, old_chain, old_semantic, old_gates, old_report = MOD.load_pins, MOD._load_chain, MOD.semantic_evidence, MOD.run_gates, MOD.write_report
        altered = replace(self.chain, repository_identity=(9, *self.chain.repository_identity[1:]))
        calls = iter((self.chain, altered))
        try:
            MOD.load_pins = lambda: self.pins; MOD._load_chain = lambda *_: next(calls); MOD.semantic_evidence = lambda *_: {"same": True}; MOD.run_gates = lambda *_: []
            with self.assertRaisesRegex(MOD.Reject, "changed during offline gates"):
                MOD.main(["--result", str(self.root / "r"), "--completion", str(self.root / "c"), "--report", str(self.root / "out")])
        finally:
            MOD.load_pins, MOD._load_chain, MOD.semantic_evidence, MOD.run_gates, MOD.write_report = old_pins, old_chain, old_semantic, old_gates, old_report


if __name__ == "__main__":
    unittest.main(verbosity=2)
