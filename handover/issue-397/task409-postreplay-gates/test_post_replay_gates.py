#!/usr/bin/env python3
"""Disposable self-test for post_replay_gates.py.

The fixture lives under /private/tmp, is initialized and committed locally, and
is removed on exit. It proves CLI validation, report hashing, fail-closed status
accounting, Task #475 screenshot evidence blocking, and candidate immutability.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "post_replay_gates.py"


def run(*argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *argv],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def git(candidate: Path, *argv: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(candidate), *argv],
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="task409-postreplay-selftest-", dir="/private/tmp"))
    try:
        candidate = workspace / "candidate"
        candidate.mkdir()
        (candidate / "README.txt").write_text("disposable candidate\n", encoding="utf-8")
        auth_spec = candidate / "apps/web/tests/e2e/ui-preview.spec.ts"
        auth_spec.parent.mkdir(parents=True)
        # Deliberately omit a marker-aware screenshot assertion. The source
        # handoff must fail instead of treating screenshot byte-length as proof.
        auth_spec.write_text(
            """\nfor (const activation of ['click', 'enter'] as const) {\n"
            "  await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });\n"
            "  await expect(username).toHaveValue('');\n"
            "  await expect(password).toHaveValue('');\n"
            "  const liveDom = await page.locator('html').evaluate((root) => ({ html: root.outerHTML, values: Array.from(root.querySelectorAll('input')).map((field) => field.value) }));\n"
            "  expect(JSON.stringify(liveDom)).not.toContain(passwordValue);\n"
            "  expect((await page.screenshot()).byteLength).toBeGreaterThan(0);\n"
            "}\n""",
            encoding="utf-8",
        )
        git(candidate, "init", "-q")
        git(candidate, "config", "user.email", "selftest@example.invalid")
        git(candidate, "config", "user.name", "Task 409 self-test")
        git(candidate, "add", "README.txt", "apps/web/tests/e2e/ui-preview.spec.ts")
        git(candidate, "commit", "-qm", "self-test fixture")
        before_head = git(candidate, "rev-parse", "HEAD")
        before_status = git(candidate, "status", "--porcelain=v1", "--untracked-files=all")

        output = workspace / "evidence" / "report.json"
        result = run(str(RUNNER), "--checkout-root", str(candidate), "--output", str(output))
        if result.returncode != 2:
            raise AssertionError(f"expected fail-closed exit 2, got {result.returncode}: {result.stderr}")
        summary_line = result.stdout.strip().splitlines()[-1]
        summary = json.loads(summary_line)
        if summary["report"] != str(output):
            raise AssertionError("CLI did not report the requested output path")
        report = json.loads(output.read_text(encoding="utf-8"))
        if report["offline_only"] is not True or report["network_operations"] is not False:
            raise AssertionError("offline policy was not recorded")
        if report["overall_status"] not in {"failed", "unavailable"}:
            raise AssertionError("dummy candidate unexpectedly passed overall")
        gates = {gate["id"]: gate for gate in report["gates"]}
        source_gate = gates["task-475-auth-source-evidence"]
        if source_gate["status"] != "failed":
            raise AssertionError("Task #475 source evidence did not fail closed")
        missing = source_gate["evidence"]["missing_checks"]
        if "screenshot_content_excludes_username" not in missing:
            raise AssertionError("screenshot-content blocker was not recorded")
        if gates["graph-impact-review"]["status"] != "skipped":
            raise AssertionError("graph mutation lane was not skipped")
        if gates["task-464-artifact-harness-handoff"]["status"] != "skipped":
            raise AssertionError("Task #464 handoff was not recorded as skipped")

        sidecar = output.with_name(output.name + ".sha256")
        expected_digest = hashlib.sha256(output.read_bytes()).hexdigest()
        reported_digest = sidecar.read_text(encoding="utf-8").split()[0]
        if expected_digest != reported_digest or expected_digest != summary["report_sha256"]:
            raise AssertionError("report hash or sidecar hash mismatch")
        if git(candidate, "rev-parse", "HEAD") != before_head:
            raise AssertionError("runner changed candidate HEAD")
        if git(candidate, "status", "--porcelain=v1", "--untracked-files=all") != before_status:
            raise AssertionError("runner changed candidate worktree")

        inside = run(
            str(RUNNER),
            "--checkout-root",
            str(candidate),
            "--output",
            str(candidate / "forbidden.json"),
        )
        if inside.returncode != 2 or "outside" not in inside.stderr:
            raise AssertionError("runner accepted an output path inside the candidate")

        plan = run(
            str(RUNNER),
            "--plan-only",
            "--checkout-root",
            str(candidate),
            "--output",
            str(workspace / "plan.json"),
        )
        if plan.returncode != 0 or len(plan.stdout.strip().splitlines()) < 15:
            raise AssertionError("plan-only output was incomplete")

        print(json.dumps({
            "status": "passed",
            "candidate": str(candidate),
            "report": str(output),
            "report_sha256": expected_digest,
            "summary": report["summary"],
            "candidate_head_unchanged": git(candidate, "rev-parse", "HEAD") == before_head,
            "candidate_status_unchanged": git(candidate, "status", "--porcelain=v1", "--untracked-files=all") == before_status,
        }, sort_keys=True))
        return 0
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
