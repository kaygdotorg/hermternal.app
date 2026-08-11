#!/usr/bin/env python3
"""Focused offline tests for the marker-bound live-proof credential handoff.

These tests use synthetic bytes only. They never contact Hermes, create a real
credential, start a browser, or retain authentication data.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import io
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MARKER_SCRIPT = ROOT / "scripts" / "live_run_marker.py"
marker_spec = importlib.util.spec_from_file_location("live_run_marker", MARKER_SCRIPT)
if marker_spec is None or marker_spec.loader is None:
    raise RuntimeError(f"Could not load {MARKER_SCRIPT}")
marker = importlib.util.module_from_spec(marker_spec)
sys.modules[marker_spec.name] = marker
marker_spec.loader.exec_module(marker)

SCRIPT = ROOT / "scripts" / "with_live_credential.py"
spec = importlib.util.spec_from_file_location("with_live_credential", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
helper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helper
spec.loader.exec_module(helper)

LAUNCHER_SCRIPT = ROOT / "scripts" / "hermes_agent.py"
launcher_spec = importlib.util.spec_from_file_location("hermes_agent", LAUNCHER_SCRIPT)
if launcher_spec is None or launcher_spec.loader is None:
    raise RuntimeError(f"Could not load {LAUNCHER_SCRIPT}")
launcher = importlib.util.module_from_spec(launcher_spec)
sys.modules[launcher_spec.name] = launcher
launcher_spec.loader.exec_module(launcher)

DOCUMENTED_HANDOFF_DOCS = (
    ROOT / "scripts" / "README.md",
    ROOT / "apps" / "web" / "tests" / "live" / "README.md",
)
README_PARSER_FIELDS = (
    ("endpoint", "endpoint"),
    ("marker_path", "marker-path"),
    ("run_id", "run-id"),
    ("credential_file", "credential-file"),
    ("credential_identity", "credential-identity"),
)
SKILL_DOC = ROOT / ".agents" / "skills" / "deploy-hermes-agent" / "SKILL.md"
DOCUMENTED_PARSER_FIELDS = {
    ROOT / "scripts" / "README.md": README_PARSER_FIELDS,
    ROOT / "apps" / "web" / "tests" / "live" / "README.md": README_PARSER_FIELDS,
    SKILL_DOC: README_PARSER_FIELDS,
}
EXPECTED_BUN_COMMAND = [
    "bun",
    "run",
    "--cwd",
    "apps/web",
    "test:e2e:live",
    "--grep",
    "browser UI reaches the official Hermes gateway through completion",
]
EXPECTED_SKILL_COMMAND = ["node", "/path/to/browser-smoke.mjs"]
EXPECTED_SKILL_OPERATIONS = [
    "start",
    "endpoint",
    "start-many",
    "endpoint",
    "stop",
    "stop",
    "stop",
]
START_GUARD_DOCS = (
    ROOT / "scripts" / "README.md",
    SKILL_DOC,
)
SYNTHETIC_ENDPOINT = "http://127.0.0.1:19119"
SYNTHETIC_MARKER = "/tmp/stale-marker.json"
def documented_shell_blocks(path: Path) -> list[str]:
    """Return shell fences as data without executing documentation commands."""

    blocks: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "```sh":
            continue
        end = next((candidate for candidate in range(index + 1, len(lines)) if lines[candidate].strip() == "```"), None)
        if end is not None:
            blocks.append("\n".join(lines[index + 1 : end]))
    return blocks


def documented_mutation_block(path: Path, operation: str) -> str:
    """Extract one documented positive mutation block for synthetic execution."""

    pattern = re.compile(
        rf"(?m)^(?:if )?\s*python3 scripts/hermes_agent\.py {re.escape(operation)}(?:\s|\\)"
    )
    for block in documented_shell_blocks(path):
        if pattern.search(block):
            return block
    raise AssertionError(f"No {operation} block found in {path}")


def synthetic_handoff() -> str:
    """Append a fake-only proof handoff; no repository helper or credential runs."""

    return """
HERMES_LIVE_TARGET="$endpoint" \\
  python3 scripts/with_live_credential.py \\
    --marker "$marker_path" \\
    --run-id "$run_id" \\
    --credential-file "$credential_file" \\
    --credential-identity "$credential_identity" \\
    -- \\
    node synthetic-child
""".strip()


def synthetic_batch_handoff() -> str:
    """Model each documented per-marker endpoint loop with fake commands only."""

    return """
for MARKER_PATH in "$HERMES_MARKER_1" "$HERMES_MARKER_2"; do
  launcher_output="$(python3 scripts/hermes_agent.py endpoint --marker "$MARKER_PATH")"
  endpoint="$(printf '%s\\n' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
  marker_path="$(printf '%s\\n' "$launcher_output" | python3 scripts/read_launcher_result.py marker-path)"
  run_id="$(printf '%s\\n' "$launcher_output" | python3 scripts/read_launcher_result.py run-id)"
  credential_file="$(printf '%s\\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
  credential_identity="$(printf '%s\\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-identity)"
  HERMES_LIVE_TARGET="$endpoint" \\
    python3 scripts/with_live_credential.py \\
      --marker "$marker_path" \\
      --run-id "$run_id" \\
      --credential-file "$credential_file" \\
      --credential-identity "$credential_identity" \\
      -- \\
      node synthetic-child
 done
""".strip()


def legacy_unchecked_mutation(block: str, operation: str) -> str:
    """Recreate the pre-fix unguarded command for the regression baseline."""

    if operation == "start":
        start = block.index('if launcher_output="$(')
        end = block.index("\nfi", start) + len("\nfi")
        command_start = block.index("\n", start) + 1
        command_end = block.index('\n)"; then', command_start)
        command = block[command_start:command_end]
        return block[:start] + 'launcher_output="$(\n' + command + '\n)"' + block[end:]
    start = block.index("if python3 scripts/hermes_agent.py start-many")
    end = block.index("\nfi", start) + len("\nfi")
    command = block[start:end]
    command_line = command[command.index("python3 scripts/hermes_agent.py") : command.index("; then")]
    return block[:start] + command_line + block[end:]


def canonical_parser_line(variable: str, field: str) -> str:
    """Return the shell line that restores one LF for canonical parsing."""

    return (
        f'{variable}="$(printf \'%s\\n\' "$launcher_output" | '
        f"python3 scripts/read_launcher_result.py {field})\""
    )


def assert_canonical_parser_handoff(path: Path, fields: tuple[tuple[str, str], ...]) -> None:
    """Require docs to restore the LF stripped by shell command substitution."""

    lines = {line.strip() for line in path.read_text(encoding="utf-8").splitlines()}
    expected = {canonical_parser_line(variable, field) for variable, field in fields}
    missing = sorted(expected - lines)
    if missing:
        raise AssertionError(f"Missing canonical parser handoff in {path}: {missing}")


def documented_launcher_commands(path: Path) -> list[list[str]]:
    """Extract every documented launcher argv without executing the launcher."""

    # Join only shell continuation lines. This keeps command substitutions and
    # quoted variable expansions intact for shlex, including marker identities.
    source = re.sub(r"\\\n[ \\t]*", " ", path.read_text(encoding="utf-8"))
    commands: list[list[str]] = []
    prefix = "python3 scripts/hermes_agent.py "
    for line in source.splitlines():
        if prefix not in line:
            continue
        fragment = line[line.index(prefix) :].strip()
        if fragment.endswith("; then"):
            fragment = fragment[: -len("; then")].rstrip()
        for suffix in (')"', ")"):
            if fragment.endswith(suffix):
                fragment = fragment[: -len(suffix)].rstrip()
                break
        commands.append(shlex.split(fragment))
    return commands


def documented_skill_handoff_script(path: Path) -> str:
    """Extract the complete skill credential handoff for a shell test."""

    lines = path.read_text(encoding="utf-8").splitlines()
    handoff_line = 'HERMES_LIVE_TARGET="$endpoint" \\'
    expected_lines = [
        'python3 scripts/with_live_credential.py \\',
        '--marker "$marker_path" \\',
        '--run-id "$run_id" \\',
        '--credential-file "$credential_file" \\',
        '--credential-identity "$credential_identity" \\',
        '-- \\',
        'node /path/to/browser-smoke.mjs',
    ]
    for index, line in enumerate(lines[:-len(expected_lines)]):
        if line.strip() != handoff_line:
            continue
        block = lines[index + 1 : index + 1 + len(expected_lines)]
        if [candidate.strip() for candidate in block] == expected_lines:
            return "\n".join([line.strip(), *expected_lines])
    raise AssertionError(f"No complete skill handoff found in {path}")


def documented_bun_command(path: Path) -> list[str]:
    """Extract one documented handoff command without executing README text."""

    lines = path.read_text(encoding="utf-8").splitlines()
    handoff_line = 'HERMES_LIVE_TARGET="$endpoint" \\'
    expected_lines = [
        'python3 scripts/with_live_credential.py \\',
        '--marker "$marker_path" \\',
        '--run-id "$run_id" \\',
        '--credential-file "$credential_file" \\',
        '--credential-identity "$credential_identity" \\',
        '-- \\',
    ]
    for index, line in enumerate(lines[:-len(expected_lines) - 1]):
        if line.strip() != handoff_line:
            continue
        if [candidate.strip() for candidate in lines[index + 1 : index + 1 + len(expected_lines)]] != expected_lines:
            continue
        return shlex.split(lines[index + 1 + len(expected_lines)].strip())
    raise AssertionError(f"No documented live handoff found in {path}")


class LiveProofCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.runs = self.root / "runs"
        self.runs.mkdir(mode=marker.RUNS_DIR_MODE)
        self.runs.chmod(marker.RUNS_DIR_MODE)
        self.marker_path = self.runs / "fixture.json"
        self.credential_path = self.runs / "fixture.credential"
        self.value = b"a" * 48
        self._write_credential(self.value + b"\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_credential(self, raw: bytes) -> None:
        self.credential_path.write_bytes(raw)
        self.credential_path.chmod(marker.CREDENTIAL_MODE)
        identity = marker.credential_lstat(self.credential_path)
        binding = marker.new_marker(
            self.marker_path,
            run_id="a" * 64,
            instance="fixture-one",
            container_id="b" * 64,
            container_name="hermternal-hermes-fixture-one",
            image="docker.io/nousresearch/hermes-agent:v1@sha256:" + "c" * 64,
            endpoint="http://127.0.0.1:19119",
            credential_identity=identity,
        )
        if self.marker_path.exists():
            marker.replace_marker(binding)
        else:
            marker.create_marker(binding)
        self.binding = marker.load_marker(self.marker_path)

    def proof(self) -> dict[str, object]:
        """Return the exact machine-readable proof required by the helper."""

        return {
            "run_id": self.binding.run_id,
            "credential_file": str(self.binding.credential_path),
            "credential_identity": self.binding.credential_identity.document(),
        }

    def cli_args(self, *command: str) -> list[str]:
        """Build the proof-bearing helper CLI without selecting by pathname."""

        proof = self.proof()
        return [
            "--marker",
            str(self.marker_path),
            "--run-id",
            str(proof["run_id"]),
            "--credential-file",
            str(proof["credential_file"]),
            "--credential-identity",
            json.dumps(proof["credential_identity"], sort_keys=True, separators=(",", ":")),
            "--",
            *command,
        ]

    def run_synthetic_document(self, script: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        """Run a parsed doc block against fake start, proof, credential, and child boundaries."""

        bin_directory = self.root / "synthetic-bin"
        bin_directory.mkdir(exist_ok=True)
        log_path = self.root / "boundaries.log"
        log_path.unlink(missing_ok=True)
        stale_credential = self.root / "stale.credential"
        stale_credential.write_bytes(self.value + b"\n")
        stale_credential.chmod(marker.CREDENTIAL_MODE)
        fake_python = bin_directory / "python3"
        fake_python.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "log = Path(os.environ['BOUNDARY_LOG'])\n"
            "def record(value):\n"
            "    with log.open('a', encoding='ascii') as stream:\n"
            "        stream.write(value + '\\n')\n"
            "args = sys.argv[1:]\n"
            "if args[:2] == ['scripts/hermes_agent.py', 'start']:\n"
            "    record('start')\n"
            "    raise SystemExit(37)\n"
            "if args[:2] == ['scripts/hermes_agent.py', 'start-many']:\n"
            "    record('start-many')\n"
            "    raise SystemExit(37)\n"
            "if args[:2] == ['scripts/hermes_agent.py', 'endpoint']:\n"
            "    record('endpoint')\n"
            "    print(json.dumps({'ok': True, 'operation': 'endpoint', 'result': {\n"
            "        'status': 'running', 'endpoint': os.environ['STALE_ENDPOINT'],\n"
            "        'marker_path': os.environ['STALE_MARKER'], 'run_id': 'a' * 64,\n"
            "        'credential_file': os.environ['STALE_CREDENTIAL'],\n"
            "        'credential_identity': {'device': 1, 'generation': 'b' * 64,\n"
            "            'inode': 2, 'mode': 384, 'nlink': 1, 'size': 49}}},\n"
            "        sort_keys=True, separators=(',', ':')))\n"
            "    raise SystemExit(0)\n"
            "if args[:1] == ['scripts/read_launcher_result.py']:\n"
            "    field = args[-1]\n"
            "    record('parse:' + field)\n"
            "    values = {\n"
            "        'endpoint': os.environ['STALE_ENDPOINT'],\n"
            "        'marker-path': os.environ['STALE_MARKER'],\n"
            "        'run-id': 'a' * 64,\n"
            "        'credential-file': os.environ['STALE_CREDENTIAL'],\n"
            "        'credential-identity': json.dumps({'device': 1, 'generation': 'b' * 64,\n"
            "            'inode': 2, 'mode': 384, 'nlink': 1, 'size': 49},\n"
            "            sort_keys=True, separators=(',', ':')),\n"
            "    }\n"
            "    print(values[field])\n"
            "    raise SystemExit(0)\n"
            "if args[:1] == ['scripts/with_live_credential.py']:\n"
            "    record('credential-read')\n"
            "    credential = args[args.index('--credential-file') + 1]\n"
            "    Path(credential).read_bytes()\n"
            "    child = args[args.index('--') + 1:]\n"
            "    environment = os.environ.copy()\n"
            "    environment['HERMES_TEST_PASSWORD'] = 'a' * 48\n"
            "    os.execvpe(child[0], child, environment)\n"
            "raise SystemExit(99)\n",
            encoding="utf-8",
        )
        fake_python.chmod(stat.S_IRWXU)
        fake_node = bin_directory / "node"
        fake_node.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "from pathlib import Path\n"
            "if os.environ.get('HERMES_TEST_PASSWORD') != 'a' * 48:\n"
            "    raise SystemExit(98)\n"
            "with Path(os.environ['BOUNDARY_LOG']).open('a', encoding='ascii') as stream:\n"
            "    stream.write('child\\n')\n",
            encoding="utf-8",
        )
        fake_node.chmod(stat.S_IRWXU)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                "BOUNDARY_LOG": str(log_path),
                "STALE_ENDPOINT": SYNTHETIC_ENDPOINT,
                "STALE_MARKER": str(self.root / SYNTHETIC_MARKER.lstrip('/')),
                "STALE_CREDENTIAL": str(stale_credential),
                "HERMES_RUNS_DIR": str(self.runs),
                "HERMES_MARKER_PATH": str(self.marker_path),
                "HERMES_INSTANCE": "synthetic-one",
                "HERMES_PORT": "19119",
                "HERMES_INSTANCE_PREFIX": "synthetic",
                "HERMES_INSTANCE_COUNT": "2",
                "HERMES_BASE_PORT": "19119",
                "HERMES_MARKER_1": str(self.marker_path),
                "HERMES_MARKER_2": str(self.runs / "fixture-two.json"),
            }
        )
        result = subprocess.run(
            ["/bin/sh", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=environment,
        )
        lines = log_path.read_text(encoding="ascii").splitlines() if log_path.exists() else []
        return result, lines

    def test_read_accepts_one_terminal_line_ending_and_preserves_file(self) -> None:
        for label, suffix in (
            ("bare", b""),
            ("lf", b"\n"),
            ("cr", b"\r"),
            ("crlf", b"\r\n"),
        ):
            with self.subTest(label=label):
                raw = self.value + suffix
                self._write_credential(raw)
                self.assertEqual(helper.read_credential_file(self.marker_path, **self.proof()), self.value.decode("ascii"))
                self.assertEqual(self.credential_path.read_bytes(), raw)

    def test_read_rejects_repeated_or_mixed_terminal_line_endings(self) -> None:
        for label, suffix in (
            ("lf-cr", b"\n\r"),
            ("crlf-lf", b"\r\n\n"),
            ("lf-lf", b"\n\n"),
            ("cr-cr", b"\r\r"),
        ):
            with self.subTest(label=label):
                raw = self.value + suffix
                self._write_credential(raw)
                with self.assertRaises(helper.LiveProofCredentialError) as raised:
                    helper.read_credential_file(self.marker_path, **self.proof())
                self.assertEqual(raised.exception.code, "credential_file_invalid")
                self.assertEqual(self.credential_path.read_bytes(), raw)

    def test_identity_is_revalidated_before_reading_credential_value(self) -> None:
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("credential value read")):
            self.assertEqual(helper.read_credential_file(self.marker_path, **self.proof()), self.value.decode("ascii"))

        replacement = self.runs / "replacement"
        replacement.write_bytes(self.value + b"\n")
        replacement.chmod(marker.CREDENTIAL_MODE)
        self.credential_path.unlink()
        replacement.rename(self.credential_path)
        with mock.patch.object(
            helper.live_run_marker,
            "verify_credential_identity",
            side_effect=helper.live_run_marker.MarkerError("credential_identity_mismatch"),
        ) as verify:
            with self.assertRaises(helper.LiveProofCredentialError) as raised:
                helper.read_credential_file(self.marker_path, **self.proof())
        self.assertEqual(raised.exception.code, "credential_identity_mismatch")
        verify.assert_called_once()

    def test_same_inode_same_size_credential_mutation_fails_generation_proof(self) -> None:
        original = self.credential_path.read_bytes()
        replacement = b"b" * (len(original) - 1) + b"\n"
        self.assertEqual(len(replacement), len(original))
        descriptor = os.open(self.credential_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            self.assertEqual(os.pwrite(descriptor, replacement, 0), len(replacement))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        before = self.credential_path.stat()
        self.assertEqual(before.st_size, len(original))
        with self.assertRaises(helper.LiveProofCredentialError) as raised:
            helper.read_credential_file(self.marker_path, **self.proof())
        self.assertEqual(raised.exception.code, "credential_identity_mismatch")

    def test_parent_swap_during_descriptor_relative_credential_read_fails_closed(self) -> None:
        moved = self.root / "runs-credential-original"
        swapped = False
        original_verify = helper.live_run_marker.verify_credential_identity

        def swap_after_identity(binding, *, parent_fd=None):
            nonlocal swapped
            result = original_verify(binding, parent_fd=parent_fd)
            if not swapped:
                swapped = True
                self.runs.rename(moved)
                self.runs.mkdir(mode=marker.RUNS_DIR_MODE)
                self.runs.chmod(marker.RUNS_DIR_MODE)
            return result

        with mock.patch.object(
            helper.live_run_marker,
            "verify_credential_identity",
            side_effect=swap_after_identity,
        ):
            with self.assertRaises(helper.LiveProofCredentialError) as raised:
                helper.read_credential_file(self.marker_path, **self.proof())
        self.assertEqual(raised.exception.code, "runs_dir_replaced")
        self.assertTrue(swapped)
        self.assertTrue((moved / "fixture.json").exists())
        self.assertEqual((moved / "fixture.credential").read_bytes(), self.value + b"\n")
        self.assertFalse(any(self.runs.iterdir()))

    def test_marker_replacement_during_credential_use_fails_closed(self) -> None:
        original = marker.load_marker(self.marker_path)
        replacement = marker.new_marker(
            self.marker_path,
            run_id="f" * 64,
            instance=original.instance,
            container_id=original.container_id,
            container_name=original.container_name,
            image=original.image,
            endpoint=original.endpoint,
            credential_identity=original.credential_identity,
        )
        original_read = helper._read_pinned_credential
        replaced = False

        def replace_after_read(binding, *, marker_identity=None, parent_fd=None):
            nonlocal replaced
            raw = original_read(binding, marker_identity=marker_identity, parent_fd=parent_fd)
            if not replaced:
                replaced = True
                marker.replace_marker(replacement, parent_fd=parent_fd)
            return raw

        with mock.patch.object(helper, "_read_pinned_credential", side_effect=replace_after_read):
            with self.assertRaises(helper.LiveProofCredentialError) as raised:
                helper.read_credential_file(self.marker_path, **self.proof())
        self.assertEqual(raised.exception.code, "marker_identity_mismatch")
        self.assertTrue(replaced)
        self.assertEqual(marker.load_marker(self.marker_path).run_id, "f" * 64)
        self.assertEqual(self.credential_path.read_bytes(), self.value + b"\n")

    def test_non_line_ending_whitespace_and_interior_line_endings_fail_closed(self) -> None:
        rejected = (
            ("space", self.value + b" "),
            ("tab-before-lf", self.value + b"\t\n"),
            ("interior-lf", self.value[:24] + b"\n" + self.value[24:]),
            ("trailing-bytes", self.value + b"\ntrailing"),
            ("uppercase", self.value.upper()),
            ("short", self.value[:-1]),
            ("long", self.value + b"0"),
        )
        for label, raw in rejected:
            with self.subTest(label=label):
                self._write_credential(raw)
                with self.assertRaises(helper.LiveProofCredentialError) as raised:
                    helper.read_credential_file(self.marker_path, **self.proof())
                self.assertEqual(raised.exception.code, "credential_file_invalid")

    def test_marker_status_and_credential_file_type_fail_before_child(self) -> None:
        tombstone = marker.cleanup_failed(marker.load_marker(self.marker_path))
        marker.replace_marker(tombstone)
        with self.assertRaises(helper.LiveProofCredentialError) as raised:
            helper.read_credential_file(self.marker_path, **self.proof())
        self.assertEqual(raised.exception.code, "marker_not_selectable")

        marker.replace_marker(tombstone.with_status(marker.STATUS_RUNNING))
        self.credential_path.unlink()
        self.credential_path.mkdir(mode=marker.CREDENTIAL_MODE)
        with self.assertRaises(helper.LiveProofCredentialError) as raised:
            helper.read_credential_file(self.marker_path, **self.proof())
        self.assertIn(raised.exception.code, {"credential_identity_invalid", "credential_file_invalid"})

    def test_bounded_invalid_value_fails_before_command_and_does_not_log_value(self) -> None:
        raw = self.value + (b"x" * (256 - len(self.value)))
        self._write_credential(raw)
        stderr = io.StringIO()
        with mock.patch.object(helper.os, "execvpe") as execvpe, contextlib.redirect_stderr(stderr):
            status = helper.main(self.cli_args("synthetic-proof"))

        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "credential_file_invalid\n")
        self.assertFalse(execvpe.called)
        self.assertNotIn(self.value.decode("ascii"), stderr.getvalue())

    def test_runner_debug_fails_before_loading_marker_or_starting_child(self) -> None:
        for debug_name in helper.LIVE_RUNNER_DEBUG_ENVS:
            with self.subTest(debug_name=debug_name):
                stderr = io.StringIO()
                with (
                    mock.patch.dict(
                        helper.os.environ,
                        {
                            helper.LIVE_RUNNER_DEBUG_ENV: "",
                            helper.LIVE_RUNNER_UI_DEBUG_ENV: "",
                            debug_name: "1",
                        },
                    ),
                    mock.patch.object(helper, "read_credential_file") as read_credential_file,
                    mock.patch.object(helper.live_run_marker, "open_runs_parent") as open_runs_parent,
                    mock.patch.object(helper.os, "execvpe") as execvpe,
                    contextlib.redirect_stderr(stderr),
                ):
                    status = helper.main(self.cli_args("synthetic-proof"))

                self.assertEqual(status, 1)
                self.assertEqual(stderr.getvalue(), "live_runner_debug_incompatible\n")
                read_credential_file.assert_not_called()
                open_runs_parent.assert_not_called()
                self.assertFalse(execvpe.called)
                self.assertNotIn(self.value.decode("ascii"), stderr.getvalue())

    def test_valid_value_is_only_passed_to_child_environment(self) -> None:
        raw = self.value + b"\r\n"
        self._write_credential(raw)
        safe_environment = {
            "PATH": "/synthetic/bin",
            "HERMES_LIVE_TARGET": "http://127.0.0.1:19119",
            "HERMES_TEST_USERNAME": "synthetic-user",
            "PLAYWRIGHT_LIVE_PORT": "4187",
            "HERMTERNAL_LIVE_RECONCILIATION": "0",
            "HERMTERNAL_LIVE_SCREENSHOT_CAPTURE": "1",
            "HERMTERNAL_PAPER_PARITY_APPROVED": "1",
            "HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA": "a" * 40,
            "HERMTERNAL_LIVE_SCREENSHOT_RETAIN": "1",
            "HERMTERNAL_LIVE_SCREENSHOT_REVIEW": "independent-approved",
            "HERMTERNAL_LIVE_SCREENSHOT_DESTINATION": "/synthetic/destination",
        }
        inherited_secrets = {
            "HERMES_TEST_PASSWORD": "inherited-password",
            "NODE_OPTIONS": "--require=/tmp/untrusted.cjs",
            "HTTP_PROXY": "http://proxy.invalid",
            "HTTPS_PROXY": "https://proxy.invalid",
            "ALL_PROXY": "socks5://proxy.invalid",
            "LD_PRELOAD": "/tmp/untrusted.so",
            "DYLD_INSERT_LIBRARIES": "/tmp/untrusted.dylib",
            "AWS_SECRET_ACCESS_KEY": "unrelated-secret",
            # Empty debug values keep this execution on the valid handoff path;
            # the separate debug test proves truthy values stop before reading.
            "PW_RUNNER_DEBUG": "",
            "PWDEBUG": "",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.dict(helper.os.environ, {**safe_environment, **inherited_secrets}, clear=True),
            mock.patch.object(helper.os, "execvpe", side_effect=OSError) as execvpe,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = helper.main(self.cli_args("synthetic-proof", "--flag"))

        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "live_proof_command_failed\n")
        call = execvpe.call_args
        self.assertIsNotNone(call)
        command, arguments, environment = call.args
        self.assertEqual(command, "synthetic-proof")
        self.assertEqual(arguments, ["synthetic-proof", "--flag"])
        self.assertEqual(
            environment,
            {**safe_environment, "HERMES_TEST_PASSWORD": self.value.decode("ascii")},
        )
        self.assertNotEqual(environment["HERMES_TEST_PASSWORD"], raw.decode("ascii"))
        self.assertNotIn(self.value.decode("ascii"), " ".join(arguments))
        self.assertEqual(self.credential_path.read_bytes(), raw)

    def test_invalid_shape_never_starts_child(self) -> None:
        self._write_credential(self.value + b"\n ")
        stderr = io.StringIO()
        with mock.patch.object(helper.os, "execvpe") as execvpe, contextlib.redirect_stderr(stderr):
            status = helper.main(self.cli_args("synthetic-proof"))

        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "credential_file_invalid\n")
        self.assertFalse(execvpe.called)

    def test_proof_json_rejects_duplicates_oversize_and_pathological_numbers_before_child(self) -> None:
        identity = json.dumps(
            self.proof()["credential_identity"],
            sort_keys=True,
            separators=(",", ":"),
        )
        duplicate = identity[:-1] + ',"device":1}'
        oversized = "{" + '"padding":"' + ("p" * 100_000) + '"}'
        pathological = (
            '{"device":' + ("9" * 5000)
            + ',"inode":2,"mode":384,"size":49,"nlink":1,"generation":"'
            + ("b" * 64) + '"}'
        )
        for label, proof_json in (
            ("duplicate", duplicate),
            ("oversized", oversized),
            ("pathological-number", pathological),
        ):
            with self.subTest(label=label):
                arguments = self.cli_args("synthetic-proof")
                proof_index = arguments.index("--credential-identity") + 1
                arguments[proof_index] = proof_json
                stderr = io.StringIO()
                with (
                    mock.patch.object(helper, "read_credential_file") as read_credential_file,
                    mock.patch.object(helper.os, "execvpe") as execvpe,
                    contextlib.redirect_stderr(stderr),
                ):
                    status = helper.main(arguments)
                self.assertEqual(status, 1)
                self.assertEqual(stderr.getvalue(), "proof_invalid\n")
                self.assertFalse(read_credential_file.called)
                self.assertFalse(execvpe.called)
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertNotIn("p" * 100, stderr.getvalue())
                self.assertNotIn("9" * 100, stderr.getvalue())

    def test_proof_json_rejects_lone_surrogate_without_raw_exception(self) -> None:
        arguments = self.cli_args("synthetic-proof")
        proof_index = arguments.index("--credential-identity") + 1
        arguments[proof_index] = '{"generation":"\\ud800"}'
        stderr = io.StringIO()
        with (
            mock.patch.object(helper, "read_credential_file") as read_credential_file,
            mock.patch.object(helper.os, "execvpe") as execvpe,
            contextlib.redirect_stderr(stderr),
        ):
            status = helper.main(arguments)
        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "proof_invalid\n")
        self.assertFalse(read_credential_file.called)
        self.assertFalse(execvpe.called)

    def test_legacy_positional_credential_form_is_rejected(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(helper.os, "execvpe") as execvpe,
            contextlib.redirect_stderr(stderr),
        ):
            status = helper.main([str(self.credential_path), "--", "synthetic-proof"])

        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "proof_required\n")
        self.assertFalse(execvpe.called)
        self.assertNotIn(str(self.credential_path), stderr.getvalue())

    def test_start_mutations_guard_stale_marker_handoff_and_preserve_failure(self) -> None:
        for operation in ("start", "start-many"):
            for document in START_GUARD_DOCS:
                with self.subTest(operation=operation, document=document):
                    block = documented_mutation_block(document, operation)
                    handoff = synthetic_handoff() if operation == "start" else synthetic_batch_handoff()
                    legacy = legacy_unchecked_mutation(block, operation) + "\n" + handoff
                    old_result, old_boundaries = self.run_synthetic_document(legacy)
                    self.assertEqual(old_result.returncode, 0)
                    self.assertIn(operation, old_boundaries)
                    self.assertIn("endpoint", old_boundaries)
                    self.assertIn("credential-read", old_boundaries)
                    self.assertIn("child", old_boundaries)

                    guarded_result, guarded_boundaries = self.run_synthetic_document(block + "\n" + handoff)
                    self.assertEqual(guarded_result.returncode, 37)
                    self.assertEqual(
                        guarded_result.stderr,
                        f"Hermes {operation} failed; endpoint handoff skipped.\n",
                    )
                    self.assertEqual(guarded_result.stdout, "")
                    self.assertEqual(guarded_boundaries, [operation])
                    self.assertNotIn(self.value.decode("ascii"), guarded_result.stdout + guarded_result.stderr)

    def test_skill_launcher_commands_use_current_marker_cli_without_podman(self) -> None:
        commands = documented_launcher_commands(SKILL_DOC)
        parsed = []
        parser = launcher.build_parser()
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(command[:2], ["python3", "scripts/hermes_agent.py"])
                parser_argv = [
                    "19119"
                    if value == "$PORT" or value.startswith("${HERMES_BASE_PORT:")
                    else "2"
                    if value.startswith("${HERMES_INSTANCE_COUNT:")
                    else value
                    for value in command[2:]
                ]
                try:
                    with contextlib.redirect_stderr(io.StringIO()):
                        parsed.append(parser.parse_args(parser_argv))
                except SystemExit as error:
                    self.fail(f"skill command is not current parser form: {command!r} ({error})")

        self.assertEqual(len(commands), len(EXPECTED_SKILL_OPERATIONS))
        self.assertEqual([command[2] for command in commands], EXPECTED_SKILL_OPERATIONS)
        self.assertEqual([args.operation for args in parsed], EXPECTED_SKILL_OPERATIONS)
        self.assertEqual(parsed[0].instance, "$INSTANCE")
        self.assertEqual(parsed[0].port, 19119)
        self.assertEqual(parsed[0].marker, "$MARKER_PATH")
        self.assertEqual(parsed[1].marker, "$MARKER_PATH")
        self.assertEqual(parsed[2].prefix, "${HERMES_INSTANCE_PREFIX:?set the fleet prefix}")
        self.assertEqual(parsed[2].count, 2)
        self.assertEqual(parsed[2].base_port, 19119)
        self.assertEqual(parsed[2].marker, ["${HERMES_MARKER_1:?set marker 1}", "${HERMES_MARKER_2:?set marker 2}"])
        for document in START_GUARD_DOCS:
            batch_commands = [
                command for command in documented_launcher_commands(document) if command[2] == "start-many"
            ]
            self.assertEqual(len(batch_commands), 1)
            self.assertEqual(batch_commands[0][batch_commands[0].index("--count") + 1], "2")
            self.assertEqual(batch_commands[0].count("--marker"), 2)
        self.assertEqual(parsed[3].marker, "$MARKER_PATH")
        self.assertEqual(parsed[4].marker, "${HERMES_MARKER_PATH:?set the exact absolute marker path}")
        self.assertFalse(parsed[4].purge_data)
        self.assertEqual(parsed[5].marker, "${HERMES_MARKER_1:?set marker 1}")
        self.assertFalse(parsed[5].purge_data)
        self.assertEqual(parsed[6].marker, "${HERMES_MARKER_2:?set marker 2}")
        self.assertFalse(parsed[6].purge_data)

        old_forms = (
            ["start", "--instance", "$INSTANCE", "--port", "$PORT"],
            ["endpoint", "--instance", "$INSTANCE"],
            ["status", "--instance", "$INSTANCE"],
            ["start-many", "--prefix", "$PREFIX", "--count", "2", "--base-port", "19119"],
            ["stop", "--instance", "$INSTANCE"],
            ["credential-file", "--marker", "$MARKER_PATH"],
            [
                "stop-many",
                "--prefix",
                "$PREFIX",
                "--count",
                "2",
                "--base-port",
                "19119",
            ],
        )
        for old_form in old_forms:
            with self.subTest(old_form=old_form), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(old_form)

    def test_skill_alias_is_relative_source_symlink(self) -> None:
        alias = ROOT / ".claude"
        self.assertTrue(alias.is_symlink())
        self.assertEqual(os.readlink(alias), ".agents")
        self.assertEqual(
            (alias / "skills" / "deploy-hermes-agent" / "SKILL.md").resolve(),
            SKILL_DOC.resolve(),
        )

    def test_documented_skill_handoff_preserves_identity_and_executes_child(self) -> None:
        for document, fields in DOCUMENTED_PARSER_FIELDS.items():
            with self.subTest(parser_document=document):
                assert_canonical_parser_handoff(document, fields)
        self.assertEqual(
            documented_skill_handoff_script(SKILL_DOC).splitlines()[1:],
            [
                'python3 scripts/with_live_credential.py \\',
                '--marker "$marker_path" \\',
                '--run-id "$run_id" \\',
                '--credential-file "$credential_file" \\',
                '--credential-identity "$credential_identity" \\',
                '-- \\',
                'node /path/to/browser-smoke.mjs',
            ],
        )

        bin_directory = Path(self.temporary.name) / "bin"
        bin_directory.mkdir()
        capture = Path(self.temporary.name) / "argv"
        fake_node = bin_directory / "node"
        fake_node.write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "if os.environ.get('HERMES_TEST_PASSWORD') != 'a' * 48:\n"
            "    raise SystemExit(97)\n"
            "Path(os.environ['HERMTERNAL_LIVE_SCREENSHOT_DESTINATION']).write_text('\\n'.join(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        fake_node.chmod(stat.S_IRWXU)
        proof = self.proof()
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                "HERMTERNAL_LIVE_SCREENSHOT_DESTINATION": str(capture),
                "endpoint": self.binding.endpoint,
                "marker_path": str(self.marker_path),
                "run_id": str(proof["run_id"]),
                "credential_file": str(proof["credential_file"]),
                "credential_identity": json.dumps(
                    proof["credential_identity"], sort_keys=True, separators=(",", ":")
                ),
            }
        )
        result = subprocess.run(
            ["/bin/sh", "-c", documented_skill_handoff_script(SKILL_DOC)],
            check=False,
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=environment,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(capture.read_text(encoding="utf-8").splitlines(), EXPECTED_SKILL_COMMAND[1:])
        self.assertEqual(self.credential_path.read_bytes(), self.value + b"\n")
        self.assertNotIn(self.value.decode("ascii"), result.stdout + result.stderr)

    def test_documented_handoff_invokes_valid_bun_command(self) -> None:
        for document, fields in DOCUMENTED_PARSER_FIELDS.items():
            with self.subTest(parser_document=document):
                assert_canonical_parser_handoff(document, fields)
        for document in DOCUMENTED_HANDOFF_DOCS:
            with self.subTest(document=document):
                self.assertEqual(documented_bun_command(document), EXPECTED_BUN_COMMAND)

        # Use only the synthetic fixture value from setUp. The fake child records
        # argv but never writes or prints HERMES_TEST_PASSWORD.
        bin_directory = Path(self.temporary.name) / "bin"
        bin_directory.mkdir()
        capture = Path(self.temporary.name) / "argv"
        fake_bun = bin_directory / "bun"
        fake_bun.write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "if not os.environ.get('HERMES_TEST_PASSWORD'):\n"
            "    raise SystemExit(97)\n"
            "Path(os.environ['HERMTERNAL_LIVE_SCREENSHOT_DESTINATION']).write_text('\\n'.join(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        fake_bun.chmod(stat.S_IRWXU)
        self._write_credential(self.value + b"\n")
        environment = os.environ.copy()
        environment["PATH"] = f"{bin_directory}{os.pathsep}{environment['PATH']}"
        environment["HERMTERNAL_LIVE_SCREENSHOT_DESTINATION"] = str(capture)
        environment["HERMES_LIVE_TARGET"] = "http://127.0.0.1:19124"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *self.cli_args(*EXPECTED_BUN_COMMAND)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(capture.read_text(encoding="utf-8").splitlines(), EXPECTED_BUN_COMMAND[1:])
        self.assertEqual(self.credential_path.read_bytes(), self.value + b"\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
