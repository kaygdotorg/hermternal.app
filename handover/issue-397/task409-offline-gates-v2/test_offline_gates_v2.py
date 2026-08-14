#!/usr/bin/env python3
"""Offline-gate v3 checks with a real controlled Git and authority fixture.

Only the Podman subprocess and image discovery boundaries are replaced. The
pin parser, verified source loaders, #405 record parser, semantic Git binding,
and create-only report writer run against ordinary on-disk fixture bytes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("offline_gates_v2", HERE / "offline_gates_v2.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MOD; SPEC.loader.exec_module(MOD)


class OfflineGatesV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="issue397-offline-v3-")
        self.root = Path(self.temp.name).resolve(); os.chmod(self.root, 0o700)
        self.repository = self.root / "repository"; self.repository.mkdir(mode=0o700)
        self._write_checkout()
        self._write_authority_contract()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _sha(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _write(path: Path, raw: bytes, mode: int) -> str:
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); os.chmod(path, mode)
        return hashlib.sha256(raw).hexdigest()

    def _git(self, *args: str) -> str:
        result = subprocess.run(("/usr/bin/git", "-C", str(self.repository), *args), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode("ascii").strip()

    def _write_checkout(self) -> None:
        files = {
            "apps/web/tests/e2e/ui-preview.spec.ts": b"import AxeBuilder from 'axe'; test('native password activation clears live values', () => { if (activation === 'click') signIn.click(); if (activation === 'enter') password.press('Enter'); expect(x).toHaveValue(''); expect(y).toHaveValue(''); expect(z).toHaveValue(''); expect(q).toHaveValue(''); root.outerHTML; page.screenshot(); expect(value).not.toContain(passwordValue); expect(value).not.toContain(usernameValue); /* axe violations */ });\n",
            "apps/web/src/lib/live-artifact-policy.test.ts": b"const LIVE_ARTIFACT_REDACTION = 'x'; const config = \"screenshot: 'off'\";\n",
            "apps/web/src/lib/live-screenshot-contract.test.ts": b"blockedLiveScreenshotManifest({});\n",
        }
        for relative, raw in files.items():
            self._write(self.repository / relative, raw, 0o644)
        subprocess.run(("/usr/bin/git", "-C", str(self.repository), "init", "--quiet"), check=True)
        subprocess.run(("/usr/bin/git", "-C", str(self.repository), "add", "."), check=True)
        subprocess.run(("/usr/bin/git", "-C", str(self.repository), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture"), check=True)
        self.final_head = self._git("rev-parse", "HEAD^{commit}")
        self.final_tree = self._git("rev-parse", "HEAD^{tree}")

    def _write_authority_contract(self) -> None:
        handover = self.root / "handover" / "issue-397"
        final_root = handover / "task464-candidate5-linux-v1-final"; final_root.mkdir(parents=True, mode=0o700)
        descriptor = self._write(final_root / "authority-descriptor.json", b'{"schema":"fixture"}\n', 0o600)
        provenance = self._write(final_root / "provenance-manifest.json", b'{"schema":"fixture"}\n', 0o600)
        phase_schema = "hermternal.issue-397.phase-a-anchor-evidence.v11"
        anchor_raw = (json.dumps({"schema": phase_schema}, separators=(",", ":")) + "\n").encode()
        anchor = self.root / "anchor.json"; self._write(anchor, anchor_raw, 0o600)
        result_keys = ["schema", "phase", "lane", "phase_a_manifest_sha256", "phase_a_approval_digest", "replay_root", "replay_root_identity", "repository", "repository_identity", "head_state", "final_head", "parent", "tree", "base_commit", "base_tree", "protected_main_commit", "required_ancestors", "forbidden_ancestors"]
        completion_keys = ["schema", "completion_marker", "stderr_policy", "returncode", "result_path", "result_sha256", "driver_module_sha256", "driver_source_sha256", "markdown_sha256", "json_sha256", "shell_sha256", "provenance_sha256", "source_commit", "phase_a_evidence_path", "phase_a_evidence_sha256"]
        modules = {
            handover / "task409-platform-profile" / "profile.py": f"from types import SimpleNamespace as N\ndef load(): return N(authority_root={str(final_root)!r})\n".encode(),
            handover / "task464-candidate5-authority-successor" / "authority.py": b"from types import SimpleNamespace as N\ndef validate(*_): return N(artifacts={'shell':N(sha256='shell'),'markdown':N(sha256='markdown'),'json':N(sha256='json')})\n",
            handover / "task409-replay-result-successor" / "wrapper.py": ("from types import SimpleNamespace as N\nRESULT_KEYS=frozenset(" + repr(result_keys) + ")\nRESULT_SCHEMA='result/v1'\nRESULT_PHASE='phase'\nRESULT_LANE='linux'\nCOMPLETION_KEYS=frozenset(" + repr(completion_keys) + ")\nCOMPLETION_SCHEMA='completion/v1'\nSUCCESS_OUTPUT=b'OK\\n'\nSTDERR_POLICY='empty'\nDRIVER_SHA256='driver'\ndef load_authority(): return N(base_commit='1'*40,base_tree='2'*40,protected_main_commit='6'*40,required_ancestors=['1'*40],forbidden_ancestors=['9'*40],source_commit='a'*40)\ndef load_phase_a_evidence(*_): return N(manifest_sha256='b'*64,approval_digest='c'*64,snapshot=N(path=" + repr(str(anchor)) + ",raw=" + repr(anchor_raw) + ",sha256='d'*64,identity=(1,2,3,384,1,1,1,1)))\n").encode(),
            handover / "task409-phase-a-anchor-successor" / "phase.py": ("EVIDENCE_SCHEMA=" + repr(phase_schema) + "\n").encode(),
        }
        hashes = {path: self._write(path, raw, 0o644) for path, raw in modules.items()}
        replay_root = self.root / "replay-root"; replay_root.mkdir(mode=0o700)
        result = self.root / "replay-result.json"
        result_value = {"schema":"result/v1", "phase":"phase", "lane":"linux", "phase_a_manifest_sha256":"b" * 64, "phase_a_approval_digest":"c" * 64, "replay_root":str(replay_root), "replay_root_identity":{}, "repository":str(self.repository), "repository_identity":{}, "head_state":"detached", "final_head":self.final_head, "parent":"3" * 40, "tree":self.final_tree, "base_commit":"1" * 40, "base_tree":"2" * 40, "protected_main_commit":"6" * 40, "required_ancestors":["1" * 40], "forbidden_ancestors":["9" * 40]}
        self._write(result, json.dumps(result_value, sort_keys=True).encode(), 0o600)
        completion = self.root / "replay-completion.json"
        result_snapshot = MOD.stable_read(result, "fixture result", mode=0o600)
        completion_value = {"schema":"completion/v1", "completion_marker":"OK", "stderr_policy":"empty", "returncode":0, "result_path":str(result), "result_sha256":result_snapshot.sha256, "driver_module_sha256":"driver", "driver_source_sha256":"shell", "markdown_sha256":"markdown", "json_sha256":"json", "shell_sha256":"shell", "provenance_sha256":provenance, "source_commit":"a" * 40, "phase_a_evidence_path":str(anchor), "phase_a_evidence_sha256":"d" * 64}
        self._write(completion, json.dumps(completion_value, sort_keys=True).encode(), 0o600)
        task = handover / "task409-offline-gates-v2"; task.mkdir(mode=0o755)
        pins = {"schema":MOD.PINS_SCHEMA, "status":"final", "platform_profile":{"path":"../task409-platform-profile/profile.py", "sha256":hashes[handover / "task409-platform-profile" / "profile.py"]}, "linux_authority":{"root":"../task464-candidate5-linux-v1-final", "module_path":"../task464-candidate5-authority-successor/authority.py", "module_sha256":hashes[handover / "task464-candidate5-authority-successor" / "authority.py"]}, "replay":{"wrapper_path":"../task409-replay-result-successor/wrapper.py", "wrapper_sha256":hashes[handover / "task409-replay-result-successor" / "wrapper.py"], "phase_a_path":"../task409-phase-a-anchor-successor/phase.py", "phase_a_sha256":hashes[handover / "task409-phase-a-anchor-successor" / "phase.py"]}, "expected_dev_base":self.final_head, "toolchain":{"image":"example.invalid/hermternal@sha256:" + "e" * 64, "repo_digest":"e" * 64, "bun":"1.3.14", "node":"26.7.0", "playwright":"1.62.1", "dependencies_sha256":"f" * 64}}
        self.pins_path = task / "final-linux-pins.json"; self._write(self.pins_path, json.dumps(pins, sort_keys=True, separators=(",", ":")).encode(), 0o644)
        self.pins = MOD.load_pins(self.pins_path); self.result = result; self.completion = completion
        self.chain = MOD._load_chain(result, completion, self.pins)

    def runner(self, argv, **_: object) -> subprocess.CompletedProcess[bytes]:
        gate = next(item for item in MOD.GATES if item.command == tuple(argv[-len(item.command):]))
        output = {"git-head": self.chain.final_head, "git-tree": self.chain.final_tree, "git-main": self.chain.protected_main, "git-dev-base": self.chain.expected_dev_base, "git-clean": ""}.get(gate.gate_id, "PASS")
        return subprocess.CompletedProcess(argv, 0, (output + "\n").encode(), b"")

    def test_real_0644_checkout_semantic_binding(self) -> None:
        evidence = MOD.semantic_evidence(self.chain)
        self.assertTrue(all(item["git_mode"] == "100644" and len(item["git_blob"]) == 40 for item in evidence["sources"].values()))
        auth = self.repository / MOD.SEMANTIC_PATHS["auth"]
        self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o644)
        auth.write_bytes(auth.read_bytes() + b"// unstaged replacement\n")
        with self.assertRaisesRegex(MOD.Reject, "working bytes differ"):
            MOD.semantic_evidence(self.chain)

    def test_real_verified_loaders_parse_linux_and_405_fixtures(self) -> None:
        chain = MOD._load_chain(self.result, self.completion, self.pins)
        self.assertEqual(chain.repository, self.repository)
        self.assertEqual(chain.final_tree, self.final_tree)
        self.assertTrue(hasattr(self.pins, "wrapper_module"))

    def test_versioned_phase_schema_parser_is_closed(self) -> None:
        for value in (
            "hermternal.issue-397.phase-a-anchor-evidence.v11",
            "hermternal.issue-397.phase-a-anchor-evidence.v123",
        ):
            self.assertIsNotNone(MOD.PHASE_EVIDENCE_SCHEMA_RE.fullmatch(value))
        for value in (
            "fixture.v11",
            "hermternal.issue-397.phase-a-anchor-evidence.v0",
            "hermternal.issue-397.phase-a-anchor-evidence.v01",
            "hermternal.issue-397.phase-a-anchor-evidence.v11-extra",
        ):
            self.assertIsNone(MOD.PHASE_EVIDENCE_SCHEMA_RE.fullmatch(value))

    def test_closed_podman_layout_and_dev_base_contract(self) -> None:
        argv = MOD.podman_argv(self.repository, MOD.GATES[0], self.pins)
        for item in ("--pull=never", "--network=none", "--read-only", "--userns=keep-id", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
            self.assertIn(item, argv)
        self.assertIn("type=bind,src=" + str(self.repository) + ",dst=/workspace,ro=true,relabel=private", argv)
        for path in MOD.WRITABLE_WEB_PATHS:
            self.assertIn(path + ":rw,nosuid,nodev,size=768m", argv)
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
        def missing_bun(*args, **_: object):
            if "info" in args[0]: return subprocess.CompletedProcess([], 0, b"true\n", b"")
            return subprocess.CompletedProcess([], 0, b'[{"RepoDigests":["x@sha256:' + b"e" * 64 + b'"],"Labels":{"org.hermternal.node":"26.7.0"}}]', b"")
        with self.assertRaisesRegex(MOD.Reject, "toolchain"):
            MOD.attest_image(self.pins, missing_bun)

    def test_deferred_pins_reject_without_mac_fallback(self) -> None:
        with self.assertRaisesRegex(MOD.Reject, "not finalized"):
            MOD.load_pins(HERE / "final-linux-pins.json")

    def test_main_rereads_real_chain_and_semantic_sources(self) -> None:
        original = MOD.PINS_PATH; MOD.PINS_PATH = self.pins_path
        changed = False
        def mutate_after_container_boundary(argv, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                path = self.repository / MOD.SEMANTIC_PATHS["auth"]
                path.write_bytes(path.read_bytes() + b"// mutation during gates\n")
            return self.runner(argv, **kwargs)
        try:
            with self.assertRaisesRegex(MOD.Reject, "working bytes differ"):
                MOD.main(["--result", str(self.result), "--completion", str(self.completion), "--report", str(self.root / "offline-gates.json")], run=mutate_after_container_boundary, attest=lambda _: None)
        finally:
            MOD.PINS_PATH = original

    def test_create_only_report_is_private(self) -> None:
        report = self.root / "offline-gates.json"
        snapshot = MOD.write_report(report, self.chain, [], MOD.semantic_evidence(self.chain))
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(snapshot.sha256, self._sha(report.read_bytes()))
        with self.assertRaises(FileExistsError):
            MOD.write_report(report, self.chain, [], {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
