#!/usr/bin/env python3
"""Offline-gate v3 checks with a real controlled Git and authority fixture.

Only the host-Git, Podman, and image-discovery process boundaries are replaced.
The pin parser, verified source loaders, #405 record parser, semantic Git
binding, gate dispatcher, and create-only report writer use real fixture bytes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

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
            "apps/web/.bun-version": b"1.3.14\n",
            "apps/web/bun.lock": b"fixture lock\n",
            "apps/web/package.json": b'{"name":"fixture","private":true}\n',
            "apps/web/playwright.config.ts": b"export default {};\n",
            "apps/web/playwright.live.config.ts": b"export default {};\n",
            "apps/web/svelte.config.js": b"export default {};\n",
            "apps/web/tsconfig.json": b'{}\n',
            "apps/web/vite.config.ts": b"export default {};\n",
            "apps/web/vitest.config.ts": b"export default {};\n",
            "apps/web/tests/e2e/ui-preview.spec.ts": b"import AxeBuilder from 'axe'; test('native password activation clears live values', () => { if (activation === 'click') await signIn.click(); else { await signIn.focus(); await signIn.press('Enter'); } expect(x).toHaveValue(''); expect(y).toHaveValue(''); expect(z).toHaveValue(''); expect(q).toHaveValue(''); root.outerHTML; page.screenshot(); expect(value).not.toContain(passwordValue); expect(value).not.toContain(usernameValue); /* axe violations */ });\n",
            "apps/web/tests/setup.ts": b"// fixture\n",
            "apps/web/tests/live/safe-reporter.mjs": b"export default class SafeReporter {}\n",
            "apps/web/tests/static/static-host.mjs": b"// fixture\n",
            "apps/web/tests/bench/terminal-renderer.evidence.json": b"{}\n",
            "apps/web/static/favicon.svg": b"<svg/>\n",
            "apps/web/src/lib/live-artifact-policy.test.ts": b"const LIVE_ARTIFACT_REDACTION = 'x'; const config = \"screenshot: 'off'\";\n",
            "apps/web/src/lib/live-screenshot-contract.test.ts": b"blockedLiveScreenshotManifest({});\n",
            "contracts/fixtures/behavioral-probe/probe-fixtures.json": b"{}\n",
            "contracts/fixtures/compatibility-attestation/cases.json": b"{}\n",
            "contracts/fixtures/compatibility-attestation/revision_attestation.json": b"{}\n",
            "contracts/hermes-dashboard/manifest.md": b"# Fixture\n",
        }
        for relative, raw in files.items():
            self._write(self.repository / relative, raw, 0o644)
        subprocess.run(("/usr/bin/git", "-C", str(self.repository), "init", "--quiet"), check=True)
        subprocess.run(("/usr/bin/git", "-C", str(self.repository), "add", "."), check=True)
        subprocess.run(("/usr/bin/git", "-C", str(self.repository), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture"), check=True)
        # The retained replay checkout protects physical source bytes while Git
        # keeps the executable-independent source mode in the committed tree.
        for relative in files:
            os.chmod(self.repository / relative, 0o600)
        self.final_head = self._git("rev-parse", "HEAD^{commit}")
        self.final_tree = self._git("rev-parse", "HEAD^{tree}")

    def _write_authority_contract(self) -> None:
        handover = self.root / "handover" / "issue-397"
        final_root = handover / "task464-candidate5-linux-v3-root-shape-final"; final_root.mkdir(parents=True, mode=0o700)
        descriptor = self._write(final_root / "authority-descriptor.json", b'{"schema":"fixture"}\n', 0o600)
        provenance = self._write(final_root / "provenance-manifest.json", b'{"schema":"fixture"}\n', 0o600)
        phase_schema = "hermternal.issue-397.phase-a-anchor-evidence.v11"
        evidence_root = self.root / "evidence"; evidence_root.mkdir(mode=0o700)
        object_dir = (self.repository / ".git/objects").resolve()
        def binding(path: Path) -> dict[str, int]:
            value = os.lstat(path)
            return {"st_dev":value.st_dev, "st_ino":value.st_ino,
                    "st_uid":value.st_uid, "st_mode":stat.S_IMODE(value.st_mode)}
        phase_value = {"observations":{"guarded_worktree":{
            "path":str(self.repository), "binding":binding(self.repository),
            "detached":True, "head":self.final_head, "tree":self.final_tree,
            "git_object_dir":{"path":str(object_dir), "binding":binding(object_dir)},
        }}}
        phase_raw = (json.dumps(phase_value, separators=(",", ":")) + "\n").encode()
        phase_path = evidence_root / "phase-a.json"; phase_sha = self._write(phase_path, phase_raw, 0o600)
        anchor_raw = (json.dumps({"schema": phase_schema, "prior_sha256":phase_sha}, separators=(",", ":")) + "\n").encode()
        anchor = evidence_root / "anchor.json"; anchor_sha = self._write(anchor, anchor_raw, 0o600)
        result_keys = ["schema", "phase", "lane", "phase_a_manifest_sha256", "phase_a_approval_digest", "replay_root", "replay_root_identity", "repository", "repository_identity", "head_state", "final_head", "parent", "tree", "base_commit", "base_tree", "protected_main_commit", "required_ancestors", "forbidden_ancestors"]
        completion_keys = ["schema", "completion_marker", "stderr_policy", "returncode", "result_path", "result_sha256", "driver_module_sha256", "driver_source_sha256", "markdown_sha256", "json_sha256", "shell_sha256", "provenance_sha256", "source_commit", "phase_a_evidence_path", "phase_a_evidence_sha256"]
        modules = {
            handover / "task409-platform-profile" / "profile.py": f"from types import SimpleNamespace as N\ndef load(): return N(authority_root={str(final_root)!r})\n".encode(),
            handover / "task464-candidate5-authority-successor" / "authority.py": b"from types import SimpleNamespace as N\ndef validate(*_): return N(artifacts={'shell':N(sha256='shell'),'markdown':N(sha256='markdown'),'json':N(sha256='json')})\n",
            handover / "task409-replay-result-successor" / "wrapper.py": ("from types import SimpleNamespace as N\nRESULT_KEYS=frozenset(" + repr(result_keys) + ")\nRESULT_SCHEMA='result/v1'\nRESULT_PHASE='phase'\nRESULT_LANE='linux'\nCOMPLETION_KEYS=frozenset(" + repr(completion_keys) + ")\nCOMPLETION_SCHEMA='completion/v1'\nSUCCESS_OUTPUT=b'OK\\n'\nSTDERR_POLICY='empty'\nDRIVER_SHA256='driver'\ndef load_authority(): return N(base_commit='1'*40,base_tree='2'*40,protected_main_commit='6'*40,required_ancestors=['1'*40],forbidden_ancestors=['9'*40],source_commit='a'*40)\ndef load_phase_a_evidence(*_): return N(manifest_sha256='b'*64,approval_digest='c'*64,snapshot=N(path=" + repr(str(anchor)) + ",raw=" + repr(anchor_raw) + ",sha256=" + repr(anchor_sha) + ",identity=(1,2,3,384,1,1,1,1)))\n").encode(),
            handover / "task409-phase-a-anchor-successor" / "phase.py": ("EVIDENCE_SCHEMA=" + repr(phase_schema) + "\n").encode(),
        }
        hashes = {path: self._write(path, raw, 0o644) for path, raw in modules.items()}
        replay_root = self.root / "replay-root"; replay_root.mkdir(mode=0o700)
        result = replay_root / "replay-result.json"
        result_value = {"schema":"result/v1", "phase":"phase", "lane":"linux", "phase_a_manifest_sha256":"b" * 64, "phase_a_approval_digest":"c" * 64, "replay_root":str(replay_root), "replay_root_identity":{}, "repository":str(self.repository), "repository_identity":{}, "head_state":"detached", "final_head":self.final_head, "parent":"3" * 40, "tree":self.final_tree, "base_commit":"1" * 40, "base_tree":"2" * 40, "protected_main_commit":"6" * 40, "required_ancestors":["1" * 40], "forbidden_ancestors":["9" * 40]}
        self._write(result, json.dumps(result_value, sort_keys=True).encode(), 0o600)
        completion = replay_root / "replay-completion.json"
        result_snapshot = MOD.stable_read(result, "fixture result", mode=0o600)
        completion_value = {"schema":"completion/v1", "completion_marker":"OK", "stderr_policy":"empty", "returncode":0, "result_path":str(result), "result_sha256":result_snapshot.sha256, "driver_module_sha256":"driver", "driver_source_sha256":"shell", "markdown_sha256":"markdown", "json_sha256":"json", "shell_sha256":"shell", "provenance_sha256":provenance, "source_commit":"a" * 40, "phase_a_evidence_path":str(anchor), "phase_a_evidence_sha256":"d" * 64}
        completion_sha256 = self._write(completion, json.dumps(completion_value, sort_keys=True).encode(), 0o600)
        task = handover / "task409-offline-gates-v2"; task.mkdir(mode=0o755)
        pins = {"schema":MOD.PINS_SCHEMA, "status":"final", "platform_profile":{"path":"../task409-platform-profile/profile.py", "sha256":hashes[handover / "task409-platform-profile" / "profile.py"]}, "linux_authority":{"root":"../task464-candidate5-linux-v3-root-shape-final", "module_path":"../task464-candidate5-authority-successor/authority.py", "module_sha256":hashes[handover / "task464-candidate5-authority-successor" / "authority.py"]}, "replay":{"wrapper_path":"../task409-replay-result-successor/wrapper.py", "wrapper_sha256":hashes[handover / "task409-replay-result-successor" / "wrapper.py"], "phase_a_path":"../task409-phase-a-anchor-successor/phase.py", "phase_a_sha256":hashes[handover / "task409-phase-a-anchor-successor" / "phase.py"]}, "publication":{"result_path":str(result), "result_sha256":result_snapshot.sha256, "completion_path":str(completion), "completion_sha256":completion_sha256}, "expected_dev_base":self.final_head, "toolchain":{"image":"example.invalid/hermternal@sha256:" + "e" * 64, "repo_digest":"e" * 64, "bun":"1.3.14", "node":"26.7.0", "playwright":"1.62.1", "dependencies_sha256":"f" * 64}}
        self.pins_path = task / "final-linux-pins.json"; self._write(self.pins_path, json.dumps(pins, sort_keys=True, separators=(",", ":")).encode(), 0o644)
        self.pins = MOD.load_pins(self.pins_path); self.result = result; self.completion = completion
        self.chain = MOD._load_chain(result, completion, self.pins)
        object_dir = (self.repository / ".git/objects").resolve()
        repository_metadata, object_metadata = os.lstat(self.repository), os.lstat(object_dir)
        self.historical = MOD.HistoricalObjects(
            self.repository,
            (repository_metadata.st_dev, repository_metadata.st_ino, repository_metadata.st_uid,
             stat.S_IMODE(repository_metadata.st_mode)),
            object_dir,
            (object_metadata.st_dev, object_metadata.st_ino, object_metadata.st_uid,
             stat.S_IMODE(object_metadata.st_mode)),
            self.final_head, self.final_tree,
        )

    def runner(self, argv, **_: object) -> subprocess.CompletedProcess[bytes]:
        gate = next(item for item in MOD.GATES if item.command == tuple(argv[-len(item.command):]))
        output = {"git-head": self.chain.final_head, "git-tree": self.chain.final_tree, "git-main": self.chain.protected_main, "git-dev-base": self.chain.expected_dev_base, "git-clean": ""}.get(gate.gate_id, "PASS")
        return subprocess.CompletedProcess(argv, 0, (output + "\n").encode(), b"")

    def local_runner(self, repository: Path, *args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
        self.assertEqual(repository, self.repository)
        self.assertEqual(stdin, b"")
        output = {
            ("rev-parse", "HEAD^{commit}"): self.chain.final_head,
            ("rev-parse", "HEAD^{tree}"): self.chain.final_tree,
            ("rev-parse", "refs/remotes/origin/main^{commit}"): self.chain.protected_main,
            ("rev-parse", "refs/remotes/origin/dev^{commit}"): self.chain.expected_dev_base,
            ("status", "--porcelain=v1", "--untracked-files=all"): "",
            ("fsck", "--full", "--strict"): "",
        }[args]
        stdout = (output + ("\n" if output else "")).encode()
        return subprocess.CompletedProcess(MOD.local_git_argv(repository, *args), 0, stdout, b"")

    def test_private_checkout_keeps_git_semantic_binding(self) -> None:
        evidence = MOD.semantic_evidence(self.chain)
        self.assertTrue(all(item["git_mode"] == "100644" and len(item["git_blob"]) == 40 for item in evidence["sources"].values()))
        auth = self.repository / MOD.SEMANTIC_PATHS["auth"]
        self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o600)
        auth.write_bytes(auth.read_bytes() + b"// unstaged replacement\n")
        with self.assertRaisesRegex(MOD.Reject, "working bytes differ"):
            MOD.semantic_evidence(self.chain)

    def test_semantic_sources_reject_unsafe_physical_modes(self) -> None:
        auth = self.repository / MOD.SEMANTIC_PATHS["auth"]
        for unsafe in (0o400, 0o640, 0o644, 0o660):
            with self.subTest(mode=oct(unsafe)):
                os.chmod(auth, unsafe)
                with self.assertRaisesRegex(MOD.Reject, "metadata differs"):
                    MOD.semantic_evidence(self.chain)
        os.chmod(auth, 0o600)
        extra_link = self.root / "auth-hard-link"
        os.link(auth, extra_link)
        try:
            with self.assertRaisesRegex(MOD.Reject, "metadata differs"):
                MOD.semantic_evidence(self.chain)
        finally:
            extra_link.unlink()

    def test_direct_enter_semantic_binding_rejects_near_misses(self) -> None:
        auth = self.repository / MOD.SEMANTIC_PATHS["auth"]
        approved = auth.read_bytes()
        changes = {
            "password field": approved.replace(
                b"await signIn.focus(); await signIn.press('Enter');",
                b"await password.focus(); await password.press('Enter');",
            ),
            "wrong key": approved.replace(b"signIn.press('Enter')", b"signIn.press('Space')"),
        }
        for label, raw in changes.items():
            with self.subTest(change=label):
                auth.write_bytes(raw)
                subprocess.run(("/usr/bin/git", "-C", str(self.repository), "add", str(auth)), check=True)
                subprocess.run(("/usr/bin/git", "-C", str(self.repository), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", label), check=True)
                os.chmod(auth, 0o600)
                chain = replace(
                    self.chain,
                    final_head=self._git("rev-parse", "HEAD^{commit}"),
                    final_tree=self._git("rev-parse", "HEAD^{tree}"),
                )
                with self.assertRaisesRegex(MOD.Reject, "semantic privacy"):
                    MOD.semantic_evidence(chain)

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
        with MOD.workspace_archive(self.chain) as archive:
            argv = MOD.podman_argv(self.repository, archive, self.historical, MOD.GATES[6], self.pins)
            MOD.verify_workspace_archive(archive)
        for item in ("--init", "--pull=never", "--network=none", "--read-only", "--userns=keep-id", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
            self.assertIn(item, argv)
        self.assertEqual(argv.count("--init"), 1)
        self.assertLess(argv.index("--init"), argv.index("--rm"))
        self.assertIn("--security-opt=label=disable", argv)
        self.assertIn("type=bind,src=" + str(self.repository) + ",dst=/source,ro=true", argv)
        self.assertIn("type=bind,src=" + str(self.historical.object_dir) + ",dst=/authority-objects,ro=true", argv)
        self.assertTrue(any(item.startswith("type=bind,src=") and item.endswith(",dst=/workspace-input.tar,ro=true") for item in argv))
        self.assertFalse(any(item.endswith(",dst=/workspace,ro=true") for item in argv))
        self.assertTrue(all("relabel=" not in item for item in argv))
        expected_tmpfs = {
            f"type=tmpfs,destination={path},tmpfs-size=805306368,tmpfs-mode=0700,U=true,notmpcopyup"
            for path in ("/tmp",)
        }
        expected_tmpfs.add("type=tmpfs,destination=/workspace,tmpfs-size=4026531840,tmpfs-mode=0700,U=true,notmpcopyup")
        self.assertEqual({item for item in argv if item.startswith("type=tmpfs,")}, expected_tmpfs)
        self.assertNotIn("--tmpfs", argv)
        self.assertIn("PLAYWRIGHT_BROWSERS_PATH=/ms-playwright", argv)
        self.assertEqual(argv[argv.index("--workdir") + 1], "/workspace")
        self.assertNotIn("--workdir=/workspace/apps/web", argv)
        setup = argv[argv.index("-c") + 1]
        self.assertIn("tar --no-same-owner -xf /workspace-input.tar -C /workspace", setup)
        self.assertNotIn("tar -xf /workspace-input.tar", setup)
        self.assertIn("printf 'gitdir: /workspace/.gitdir\\n' > /workspace/.git", setup)
        self.assertIn(self.chain.final_head, setup)
        self.assertIn("/source/.git/objects\\n/authority-objects\\n", setup)
        self.assertIn("/usr/local/install/cache/*", setup)
        self.assertIn("/usr/local/install/cache/.[!.]*", setup)
        self.assertIn("/usr/local/install/cache/..?*", setup)
        self.assertIn("/tmp/home/.bun/install/cache/", setup)
        self.assertIn("bun x --no-install svelte-kit sync", setup)
        for pattern in ("node_modules/*", "node_modules/.[!.]*", "node_modules/..?*"):
            self.assertIn(pattern, setup)
        self.assertIn("cp -a --no-preserve=ownership --", setup)
        self.assertNotIn("node_modules/. /workspace", setup)
        self.assertNotIn("/source/apps/web", setup)
        self.assertNotIn("GIT_DIR=/workspace/.gitdir", argv)
        self.assertNotIn("GIT_WORK_TREE=/workspace", argv)
        self.assertIn("/workspace/.gitdir/refs/heads", setup)
        self.assertIn("HOME=/tmp/home", argv)
        self.assertIn("BUN_INSTALL_CACHE_DIR=/tmp/home/.bun/install/cache", argv)

    def test_private_workspace_command_adapts_only_the_exact_renderer_fixture(self) -> None:
        with MOD.workspace_archive(self.chain) as archive:
            argv = MOD.podman_argv(
                self.repository, archive, self.historical, MOD.GATES[6], self.pins,
            )
        setup = argv[argv.index("-c") + 1]
        expected = (
            "/workspace/apps/web/src/lib/terminal/renderer.test.ts",
            "100644",
            "8d489b746e2dc0f6c15b32b0174f62db58c308e3",
            "776a517e44dd274066e97d1f26a2be17a35793d9e556fc60f1e4391a18b6512f",
            "#!/opt/homebrew/bin/bun",
            "#!${process.execPath}",
            "47d78dc3e3390ae82528072af5ce09948a9c20190ec597996b5b9bcd8f7a2cce",
        )
        for value in expected:
            with self.subTest(value=value):
                self.assertIn(value, setup)
        self.assertIn("old_count != 3", setup)
        self.assertIn("updated.count(old) != 0", setup)
        self.assertIn("published result changed during verified load", setup)
        self.assertLess(setup.index("tar --no-same-owner"), setup.index("renderer.test.ts"))
        self.assertLess(setup.index("renderer.test.ts"), setup.index("svelte-kit sync"))
        self.assertNotIn("/source/apps/web/src/lib/terminal/renderer.test.ts", setup)
        self.assertNotIn("/workspace-input.tar apps/web/src/lib/terminal/renderer.test.ts", setup)

    def test_private_workspace_command_has_no_embedded_nul(self) -> None:
        with MOD.workspace_archive(self.chain) as archive:
            argv = MOD.podman_argv(
                self.repository, archive, self.historical, MOD.GATES[6], self.pins,
            )
        self.assertTrue(all("\0" not in value for value in argv))
        self.assertIn('b"\\0" + source', MOD.RENDERER_ADAPTATION_SCRIPT)
        statement = next(
            line for line in MOD.RENDERER_ADAPTATION_SCRIPT.splitlines()
            if line.startswith("git_object = ")
        )
        scope = {"source": b"fixture"}
        exec(compile(statement, "<renderer-adaptation-git-object>", "exec"), scope)
        self.assertEqual(scope["git_object"], b"blob 7\0fixture")
        self.assertEqual(hashlib.sha1(scope["git_object"]).hexdigest(),
                         "001f1993905d81b471eeaa840432cf35aedaea61")

    def test_private_workspace_adaptation_allows_reviewed_portable_literals(self) -> None:
        old = b"#!/opt/homebrew/bin/bun"
        new = b"#!${process.execPath}"
        source = old + b"\n" + new + b"\n" + old + b"\n" + old
        self.assertEqual(source.count(old), 3)
        updated = source.replace(old, new)
        self.assertEqual(updated.count(old), 0)
        self.assertEqual(updated.count(new), 4)
        self.assertNotIn("updated.count(new) != 3", MOD.RENDERER_ADAPTATION_SCRIPT)

    def test_private_workspace_post_read_rejects_a_trailing_byte(self) -> None:
        expected = b"reviewed-result"
        stored = expected + b"!"
        published = stored[:len(expected)]
        trailing = stored[len(expected):len(expected) + 1]
        self.assertEqual(published, expected)
        self.assertEqual(trailing, b"!")
        self.assertIn("published_final.st_size != len(updated)",
                      MOD.RENDERER_ADAPTATION_SCRIPT)
        self.assertIn("trailing = os.read(descriptor, 1)",
                      MOD.RENDERER_ADAPTATION_SCRIPT)
        self.assertIn("trailing != b\"\"", MOD.RENDERER_ADAPTATION_SCRIPT)

    def test_private_workspace_adaptation_rejects_contract_near_misses(self) -> None:
        contract = MOD.RENDERER_ADAPTATION_CONTRACT
        mutations = []
        for index, value in enumerate(contract):
            changed = list(contract)
            changed[index] = value + "-near-miss"
            mutations.append(tuple(changed))
        mutations.extend((contract[:-1], (*contract, "/workspace/extra-path")))
        with MOD.workspace_archive(self.chain) as archive:
            for changed in mutations:
                with self.subTest(contract=changed), \
                     mock.patch.object(MOD, "RENDERER_ADAPTATION_CONTRACT", changed):
                    with self.assertRaisesRegex(MOD.Reject, "adaptation contract differs"):
                        MOD.podman_argv(
                            self.repository, archive, self.historical,
                            MOD.GATES[6], self.pins,
                        )
            with mock.patch.object(
                MOD, "RENDERER_ADAPTATION_SCRIPT",
                MOD.RENDERER_ADAPTATION_SCRIPT + "\n# near miss\n",
            ):
                with self.assertRaisesRegex(MOD.Reject, "adaptation program differs"):
                    MOD.podman_argv(
                        self.repository, archive, self.historical,
                        MOD.GATES[6], self.pins,
                    )

    def test_workspace_archive_binds_exact_tracked_allowlist(self) -> None:
        untracked = self.repository / "apps/web/ignored-secret.txt"
        untracked.write_text("must not enter archive", encoding="utf-8")
        with MOD.workspace_archive(self.chain) as archive:
            self.assertEqual(archive.tree, self.chain.final_tree)
            self.assertEqual(stat.S_IMODE(archive.snapshot.path.stat().st_mode), 0o600)
            self.assertEqual(archive.snapshot.path.stat().st_nlink, 1)
            with tarfile.open(archive.snapshot.path, "r:") as handle:
                names = {item.name.rstrip("/") for item in handle.getmembers()}
            self.assertIn("apps/web/src/lib/live-artifact-policy.test.ts", names)
            self.assertIn("contracts/hermes-dashboard/manifest.md", names)
            self.assertNotIn("apps/web/ignored-secret.txt", names)
            self.assertNotIn("apps/web/README.md", names)
            self.assertFalse(any(name.startswith("apps/web/benchmarks/") for name in names))
            self.assertFalse(any(name == ".git" or name.startswith(".git/") for name in names))
            MOD.verify_workspace_archive(archive)
        self.assertFalse(archive.root.exists())

        for changed in (
            MOD.WORKSPACE_TRACKED_INPUTS[:-1],
            (*MOD.WORKSPACE_TRACKED_INPUTS, "apps/web/README.md"),
        ):
            with self.subTest(paths=len(changed)), mock.patch.object(MOD, "WORKSPACE_TRACKED_INPUTS", changed):
                with self.assertRaisesRegex(MOD.Reject, "allowlist differs"):
                    with MOD.workspace_archive(self.chain):
                        self.fail("changed workspace allowlist was accepted")
        with self.assertRaisesRegex(MOD.Reject, "workspace tree inventory"):
            with MOD.workspace_archive(replace(self.chain, final_tree="0" * 40)):
                self.fail("wrong final tree was accepted")

    def test_historical_git_dependency_set_is_closed_and_source_bound(self) -> None:
        self.assertEqual(len(MOD.GIT_REQUIREMENTS), 11)
        self.assertEqual(len({item.commit for item in MOD.GIT_REQUIREMENTS}), 9)
        self.assertEqual(
            {item.commit for item in MOD.GIT_REQUIREMENTS if item.guarded_only},
            {
                "a7d43f636424dcd02bf65743966db30e5aeb30f0",
                "4c1cd74f6d703a99a29ef85a08142df45234e9f5",
            },
        )
        self.assertEqual(MOD.digest(MOD._git_requirements_bytes()), MOD.GIT_REQUIREMENTS_SHA256)
        self.assertEqual(len(MOD.GIT_DECLARATIONS), 8)
        self.assertEqual(
            MOD.digest(json.dumps([list(item) for item in MOD.GIT_DECLARATIONS], separators=(",", ":")).encode()),
            MOD.GIT_DECLARATIONS_SHA256,
        )

        path = "apps/web/package.json"
        blob = self._git("rev-parse", f"{self.final_head}:{path}")
        requirement = MOD.GitRequirement(self.final_head, path, blob, "fixture parent")
        requirement_bytes = json.dumps(
            [[requirement.commit, requirement.path, requirement.blob, requirement.purpose, False]],
            separators=(",", ":"),
        ).encode()
        patches = (
            mock.patch.object(MOD, "GIT_REQUIREMENTS", (requirement,)),
            mock.patch.object(MOD, "GIT_REQUIREMENTS_SHA256", self._sha(requirement_bytes)),
            mock.patch.object(MOD, "GUARDED_SOURCE_HEAD", self.final_head),
            mock.patch.object(MOD, "GUARDED_SOURCE_TREE", self.final_tree),
            mock.patch.object(MOD, "GIT_DECLARATIONS", ()),
            mock.patch.object(MOD, "GIT_DECLARATIONS_SHA256", self._sha(b"[]")),
            mock.patch.object(MOD, "BENCHMARK_EVIDENCE_PATH", "apps/web/tests/bench/terminal-renderer.evidence.json"),
            mock.patch.object(MOD, "BENCHMARK_SOURCE_COMMIT", ""),
            mock.patch.object(MOD, "BENCHMARK_ANCHOR_COMMIT", self.final_head),
            mock.patch.object(MOD, "BENCHMARK_EVIDENCE_BLOB", self._git("rev-parse", f"{self.final_head}:apps/web/tests/bench/terminal-renderer.evidence.json")),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], \
             patches[6], patches[7], patches[8], patches[9]:
            source = MOD.historical_objects(self.chain)
            self.assertEqual(source, self.historical)
            MOD.verify_historical_objects(source)
            with mock.patch.object(MOD, "GIT_REQUIREMENTS", (replace(requirement, blob="0" * 40),)), \
                 mock.patch.object(MOD, "GIT_REQUIREMENTS_SHA256", self._sha(json.dumps(
                     [[requirement.commit, requirement.path, "0" * 40, requirement.purpose, False]],
                     separators=(",", ":"),
                 ).encode())):
                with self.assertRaisesRegex(MOD.Reject, "historical Git path differs"):
                    MOD.historical_objects(self.chain)
            guarded = replace(requirement, guarded_only=True)
            with mock.patch.object(MOD, "GIT_REQUIREMENTS", (guarded,)), \
                 mock.patch.object(MOD, "GIT_REQUIREMENTS_SHA256", self._sha(json.dumps(
                     [[guarded.commit, guarded.path, guarded.blob, guarded.purpose, True]],
                     separators=(",", ":"),
                 ).encode())):
                with self.assertRaisesRegex(MOD.Reject, "dependency set differs"):
                    MOD.historical_objects(self.chain)
        with self.assertRaisesRegex(MOD.Reject, "object directory changed"):
            MOD.verify_historical_objects(replace(self.historical, object_dir_identity=(0, 0, 0, 0)))

    def test_gate_dispatch_splits_local_git_from_pinned_podman(self) -> None:
        git_calls: list[tuple[Path, tuple[str, ...]]] = []
        podman_calls: list[tuple[str, ...]] = []
        expected = {
            ("rev-parse", "HEAD^{commit}"): self.chain.final_head,
            ("rev-parse", "HEAD^{tree}"): self.chain.final_tree,
            ("rev-parse", "refs/remotes/origin/main^{commit}"): self.chain.protected_main,
            ("rev-parse", "refs/remotes/origin/dev^{commit}"): self.chain.expected_dev_base,
            ("status", "--porcelain=v1", "--untracked-files=all"): "",
            ("fsck", "--full", "--strict"): "",
        }

        def local_git(repository: Path, *args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
            self.assertEqual(stdin, b"")
            git_calls.append((repository, args))
            stdout = (expected[args] + ("\n" if expected[args] else "")).encode()
            stderr = b"fsck observation\n" if args == ("fsck", "--full", "--strict") else b""
            return subprocess.CompletedProcess(MOD.local_git_argv(repository, *args), 0, stdout, stderr)

        def container(argv, **kwargs):
            podman_calls.append(tuple(argv))
            return self.runner(argv, **kwargs)

        environments: list[dict[str, str]] = []
        def capture_environment(argv, **kwargs):
            environments.append(kwargs["env"])
            return container(argv, **kwargs)
        records = MOD.run_gates(
            self.chain, self.pins, capture_environment, lambda _: None,
            local_git=local_git,
            historical=lambda _: self.historical,
        )
        self.assertEqual([item["id"] for item in records], [gate.gate_id for gate in MOD.GATES])
        self.assertTrue(all(set(item) == {"id", "argv", "exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes"} for item in records))
        self.assertEqual([args for _, args in git_calls], [gate.command[1:] for gate in MOD.GATES[:6]])
        self.assertTrue(all(repository == self.repository for repository, _ in git_calls))
        self.assertEqual(len(podman_calls), 7)
        self.assertTrue(all(tuple(call[-len(gate.command):]) == gate.command for call, gate in zip(podman_calls, MOD.GATES[6:])))
        self.assertTrue(all("--pull=never" in call and "--network=none" in call and "--read-only" in call for call in podman_calls))
        self.assertTrue(all(call[-len(MOD.GATES[0].command):] != MOD.GATES[0].command for call in podman_calls))
        self.assertTrue(environments)
        self.assertTrue(all(environment == MOD.rootless_podman_environment() for environment in environments))
        self.assertEqual(records[5]["stderr_bytes"], len(b"fsck observation\n"))
        self.assertEqual(records[5]["stderr_sha256"], self._sha(b"fsck observation\n"))
        self.assertEqual(records[0]["argv"], list(MOD.local_git_argv(self.repository, "rev-parse", "HEAD^{commit}")))

    def test_local_git_process_boundary_preserves_bounded_observation(self) -> None:
        expected_argv = MOD.local_git_argv(self.repository, "status", "--porcelain=v1")
        observed: dict[str, object] = {}

        def process(argv, **kwargs):
            observed["argv"] = tuple(argv)
            observed.update(kwargs)
            return subprocess.CompletedProcess(argv, 7, b"raw stdout\n", b"raw stderr\n")

        with mock.patch.object(MOD.subprocess, "run", process):
            result = MOD._run_local_git(self.repository, "status", "--porcelain=v1", stdin=b"input")
        self.assertEqual((result.args, result.returncode, result.stdout, result.stderr),
                         (expected_argv, 7, b"raw stdout\n", b"raw stderr\n"))
        self.assertEqual(observed, {
            "argv": expected_argv,
            "input": b"input",
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "env": MOD.LOCAL_GIT_ENV,
            "cwd": "/",
            "timeout": 30,
            "check": False,
        })

        with mock.patch.object(MOD.subprocess, "run", side_effect=subprocess.TimeoutExpired(expected_argv, 30)):
            with self.assertRaisesRegex(MOD.Reject, "semantic Git binding is unavailable"):
                MOD._run_local_git(self.repository, "status", "--porcelain=v1")

    def test_gate_dispatch_rejects_backend_near_misses(self) -> None:
        cases = (
            (0, MOD.Gate("git-head", "/workspace/apps/web", ("bun", "rev-parse", "HEAD^{commit}"))),
            (6, MOD.Gate("web-typecheck", "/workspace", ("git", "status"))),
        )
        for index, replacement in cases:
            with self.subTest(gate=replacement.gate_id):
                changed = list(MOD.GATES); changed[index] = replacement
                changed_tuple = tuple(changed)
                gate_hash = MOD.digest(json.dumps([[g.gate_id, g.workdir, list(g.command)] for g in changed_tuple], separators=(",", ":")).encode())
                with mock.patch.object(MOD, "GATES", changed_tuple), mock.patch.object(MOD, "GATE_LIST_SHA256", gate_hash):
                    with self.assertRaisesRegex(MOD.Reject, "backend command"):
                        MOD.run_gates(self.chain, self.pins, self.runner, lambda _: None,
                                      local_git=self.local_runner, historical=lambda _: self.historical)

        def substituted_argv(repository: Path, *args: str, stdin: bytes = b""):
            result = self.local_runner(repository, *args, stdin=stdin)
            result.args = ("/usr/bin/git", "status")
            return result
        with self.assertRaisesRegex(MOD.Reject, "git-head argv"):
            MOD.run_gates(self.chain, self.pins, self.runner, lambda _: None,
                          local_git=substituted_argv, historical=lambda _: self.historical)

    def test_dev_base_mismatch_and_pre_staged_toolchain_failure_reject(self) -> None:
        def wrong_dev(repository: Path, *args: str, stdin: bytes = b""):
            result = self.local_runner(repository, *args, stdin=stdin)
            if args == MOD.GATES[3].command[1:]:
                result.stdout = ("8" * 40 + "\n").encode()
            return result
        with self.assertRaisesRegex(MOD.Reject, "git-dev-base"):
            MOD.run_gates(self.chain, self.pins, self.runner, lambda _: None,
                          local_git=wrong_dev, historical=lambda _: self.historical)
        def missing_bun(*args, **_: object):
            if "info" in args[0]:
                home = Path.home().resolve()
                runtime = Path(f"/run/user/{os.getuid()}")
                output = f"true\n{home}/.local/share/containers/storage\n{runtime}/containers\n".encode()
                return subprocess.CompletedProcess([], 0, output, b"")
            return subprocess.CompletedProcess([], 0, b'[{"RepoDigests":["x@sha256:' + b"e" * 64 + b'"],"Config":{"User":"1001:1001"},"Labels":{"org.hermternal.node":"26.7.0"}}]', b"")
        with self.assertRaisesRegex(MOD.Reject, "toolchain"):
            MOD.attest_image(self.pins, missing_bun)

    def test_podman_uses_exact_rootless_user_storage(self) -> None:
        expected_home = str(Path.home().resolve())
        expected_runtime = f"/run/user/{os.getuid()}"
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def inspected(argv, **kwargs):
            calls.append((tuple(argv), kwargs["env"]))
            if "info" in argv:
                output = f"true\n{expected_home}/.local/share/containers/storage\n{expected_runtime}/containers\n".encode()
                return subprocess.CompletedProcess(argv, 0, output, b"")
            value = {"RepoDigests":["x@sha256:" + "e" * 64], "Config": {"User": f"{os.getuid()}:{os.getgid()}"}, "Labels": {
                "org.hermternal.bun":"1.3.14", "org.hermternal.node":"26.7.0",
                "org.hermternal.playwright":"1.62.1", "org.hermternal.dependencies-sha256":"f" * 64,
            }}
            return subprocess.CompletedProcess(argv, 0, json.dumps([value]).encode(), b"")

        MOD.attest_image(self.pins, inspected)
        self.assertTrue(all(set(env) == {"PATH", "HOME", "XDG_RUNTIME_DIR", "LANG", "LC_ALL"} for _, env in calls))
        self.assertTrue(all(env["HOME"] == expected_home and env["XDG_RUNTIME_DIR"] == expected_runtime for _, env in calls))
        with mock.patch.dict(os.environ, {"HOME": "/nonexistent"}, clear=False):
            with self.assertRaisesRegex(MOD.Reject, "Podman HOME"):
                MOD.attest_image(self.pins, inspected)
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/tmp"}, clear=False):
            with self.assertRaisesRegex(MOD.Reject, "runtime directory"):
                MOD.attest_image(self.pins, inspected)

        def wrong_user(argv, **kwargs):
            result = inspected(argv, **kwargs)
            if "image" in argv:
                value = json.loads(result.stdout)[0]
                value["Config"]["User"] = "0:0"
                result.stdout = json.dumps([value]).encode()
            return result

        with self.assertRaisesRegex(MOD.Reject, "image user"):
            MOD.attest_image(self.pins, wrong_user)

        def wrong_store(argv, **kwargs):
            if "info" in argv:
                return subprocess.CompletedProcess(argv, 0, b"true\n/tmp/wrong-graph\n/tmp/wrong-run\n", b"")
            return inspected(argv, **kwargs)
        with self.assertRaisesRegex(MOD.Reject, "storage boundary"):
            MOD.attest_image(self.pins, wrong_store)

    def test_final_linux_pins_bind_real_publication(self) -> None:
        pins = MOD.load_pins(HERE / "final-linux-pins.json")
        self.assertEqual(pins.expected_dev_base, "729f2613af2b78d58b07918478e9102d5716f367")
        self.assertEqual(pins.result_sha256, "533f63f7a35681043fa1b1240ff83fd206965e0e8aadafd38ed4221f9cb97a13")
        self.assertEqual(pins.completion_sha256, "13a3bf9fbd4338fe44ced2123100e2cacd35bef013a0ecbeda4df21ddaf2aab9")
        self.assertEqual(pins.authority_root.name, "task464-candidate5-linux-v3-root-shape-final")

    def test_runtime_publication_must_equal_final_pins(self) -> None:
        wrong_path = self.result.with_name("other-result.json")
        with self.assertRaisesRegex(MOD.Reject, "runtime publication paths"):
            MOD._load_chain(wrong_path, self.completion, self.pins)
        with self.assertRaisesRegex(MOD.Reject, "publication SHA-256"):
            MOD._load_chain(
                self.result, self.completion,
                replace(self.pins, result_sha256="0" * 64),
            )
        with self.assertRaisesRegex(MOD.Reject, "publication SHA-256"):
            MOD._load_chain(
                self.result, self.completion,
                replace(self.pins, completion_sha256="0" * 64),
            )
        with self.assertRaisesRegex(MOD.Reject, "v3 root-shape"):
            MOD._authority_root(
                "../task464-candidate5-linux-v2-parent-binding-final",
                self.pins_path, self.pins_path.parents[1],
            )

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
                MOD.main(["--result", str(self.result), "--completion", str(self.completion), "--report", str(self.root / "offline-gates.json")], run=mutate_after_container_boundary, attest=lambda _: None, local_git=self.local_runner, historical=lambda _: self.historical)
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
