#!/usr/bin/env python3
"""Validate the web-only PTY attach contract with Python's standard library.

The repository is intentionally not a Hermes runtime dependency. The default
run validates the checked-in, synthetic fixture set and recorded source
fingerprints without network access. ``--source-root`` is an optional audit
mode for a local checkout of the exact pinned Hermes revision; it verifies the
recorded full-file and line-range hashes before the fixture assertions run.

The assertions below are deliberately narrow and encode the source-correct
lifecycle split: missing attach is legacy and terminates on disconnect; a
previously accepted opaque handle keeps the PTY alive; retained output can
race live output; prompt/tool output bytes may be retained; and no user input
or action is replayed. Invalid handles are rejected
before the source registry can interpret them as a new key.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any, Iterable


REVISION = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
CONTRACT = "dashboard-v0.0.1"
ARTIFACT_FILES = (
    "source-evidence.json",
    "pty-attach-fixtures.json",
    "validate.py",
    "README.md",
)
REQUIRED_CASES = {
    "missing-attach-selects-legacy",
    "legacy-disconnect-terminates",
    "attach-detach-reattach",
    "malformed-attach-fails-closed",
    "expired-attach-fails-closed",
    "superseded-socket-fails-closed",
    "retained-output-race",
    "retained-output-truncation",
    "no-input-replay",
}
FORBIDDEN_FIXTURE_KEYS = {
    "access_token",
    "cookie_value",
    "credential",
    "live_transcript",
    "password",
    "raw_handle",
    "raw_token",
    "refresh_token",
    "secret",
    "ticket_value",
    "user_data",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def hex_string(value: Any, length: int, label: str) -> None:
    require(isinstance(value, str), f"{label} must be a string")
    require(len(value) == length, f"{label} must have {length} hex characters")
    require(all(char in "0123456789abcdef" for char in value), f"{label} is not lowercase hex")


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def walk_fixture_values(value: Any, path: str = "fixture") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk_fixture_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_fixture_values(child, f"{path}[{index}]")


def validate_redaction(fixtures: dict[str, Any]) -> None:
    redaction = fixtures.get("redaction")
    require(isinstance(redaction, dict), "fixture redaction policy is required")
    for key in ("raw_handles", "live_data", "credentials", "transcript_mirror"):
        require(redaction.get(key) is False, f"redaction.{key} must be false")

    for path, value in walk_fixture_values(fixtures):
        if isinstance(value, dict):
            for key in value:
                require(key.lower() not in FORBIDDEN_FIXTURE_KEYS, f"forbidden fixture key at {path}.{key}")
        if isinstance(value, str):
            # These markers catch accidental pasting of common credential forms
            # without rejecting the deliberately synthetic handle references.
            lowered = value.lower()
            for marker in ("eyj", "ghp_", "sk-", "xoxb-"):
                require(not lowered.startswith(marker), f"credential-like fixture value at {path}")


def events(case: dict[str, Any]) -> list[dict[str, Any]]:
    timeline = case.get("timeline")
    require(isinstance(timeline, list), f"{case.get('id')}: timeline is required")
    require(all(isinstance(item, dict) for item in timeline), f"{case.get('id')}: timeline items must be objects")
    return timeline


def event_names(case: dict[str, Any]) -> list[str]:
    result = []
    for item in events(case):
        name = item.get("event")
        require(isinstance(name, str), f"{case.get('id')}: event name is required")
        result.append(name)
    return result


def assert_order(names: list[str], before: str, after: str, case_id: str) -> None:
    require(before in names, f"{case_id}: missing event {before}")
    require(after in names, f"{case_id}: missing event {after}")
    require(names.index(before) < names.index(after), f"{case_id}: {before} must precede {after}")


def event_items(case: dict[str, Any], event: str) -> list[dict[str, Any]]:
    return [item for item in events(case) if item.get("event") == event]


def expect_fixture_failure(fixtures: dict[str, Any], mutation: str, mutate: Any) -> None:
    mutated = copy.deepcopy(fixtures)
    mutate(mutated)
    try:
        validate_fixtures(mutated)
    except AssertionError:
        return
    fail(f"mutation check accepted unsafe fixture: {mutation}")


def valid_handle(case: dict[str, Any]) -> None:
    handle = case.get("attach_handle")
    require(isinstance(handle, dict), f"{case.get('id')}: attach_handle is required")
    require(handle.get("present") is True, f"{case.get('id')}: handle must be present")
    require(handle.get("classification") == "valid_exact_opaque_handle", f"{case.get('id')}: handle is not exact opaque")
    reference = handle.get("reference")
    require(isinstance(reference, str) and reference.startswith("synthetic-"), f"{case.get('id')}: handle reference must be synthetic")


def missing_handle(case: dict[str, Any]) -> None:
    handle = case.get("attach_handle")
    require(isinstance(handle, dict), f"{case.get('id')}: attach_handle is required")
    require(handle.get("present") is False, f"{case.get('id')}: handle must be absent")
    require(handle.get("classification") == "missing", f"{case.get('id')}: missing classification is required")


def validate_case(case: dict[str, Any]) -> None:
    case_id = case.get("id")
    kind = case.get("kind")
    require(isinstance(case_id, str), "every case needs a string id")
    require(isinstance(kind, str), f"{case_id}: every case needs a kind")
    names = event_names(case)
    expected = case.get("expected")
    require(isinstance(expected, dict), f"{case_id}: expected object is required")

    if case_id == "missing-attach-selects-legacy":
        missing_handle(case)
        require(kind == "legacy_selection", f"{case_id}: wrong kind")
        require(expected == {"mode": "legacy", "keep_alive": False, "fallback_to_attach": False}, f"{case_id}: legacy selection changed")
        require(names == ["request.prepare", "legacy.branch.selected"], f"{case_id}: non-deterministic selection timeline")
        return

    if case_id == "legacy-disconnect-terminates":
        missing_handle(case)
        require(kind == "legacy_disconnect", f"{case_id}: wrong kind")
        assert_order(names, "socket.disconnect", "bridge.close", case_id)
        require("registry.detach" not in names and "registry.reuse" not in names, f"{case_id}: legacy path entered registry")
        require(expected.get("state_after_disconnect") == "exited", f"{case_id}: disconnect must exit")
        require(expected.get("process_lifetime") == "terminated", f"{case_id}: bridge must terminate")
        require(expected.get("reattach") == "prohibited", f"{case_id}: legacy reattach must be prohibited")
        require(expected.get("spawn_count") == 1, f"{case_id}: expected one spawn")
        require(expected.get("input_replay_count") == 0, f"{case_id}: input replay is forbidden")
        return

    if case_id == "attach-detach-reattach":
        valid_handle(case)
        require(kind == "attach_detach_reattach", f"{case_id}: wrong kind")
        attach_positions = [index for index, name in enumerate(names) if name == "session.attach"]
        require(len(attach_positions) == 2, f"{case_id}: expected initial and reattach events")
        assert_order(names, "registry.spawn", "session.attach", case_id)
        assert_order(names, "socket.disconnect", "registry.detach", case_id)
        assert_order(names, "registry.detach", "registry.reuse", case_id)
        require(names.index("registry.reuse") < attach_positions[1], f"{case_id}: registry reuse must precede reattach")
        spawn_events = event_items(case, "registry.spawn")
        reuse_events = event_items(case, "registry.reuse")
        require(len(spawn_events) == 1 and len(reuse_events) == 1, f"{case_id}: expected one spawn and one reuse")
        spawn_ref = spawn_events[0].get("session_ref")
        reuse_ref = reuse_events[0].get("session_ref")
        require(isinstance(spawn_ref, str) and isinstance(reuse_ref, str), f"{case_id}: session references are required")
        require(spawn_ref == reuse_ref, f"{case_id}: registry reuse changed the PTY session identity")
        require("bridge.close" not in names, f"{case_id}: detach must not close the bridge")
        require(expected.get("state_sequence") == ["attached", "detached", "attached"], f"{case_id}: state sequence changed")
        require(expected.get("process_lifetime_during_detach") == "alive", f"{case_id}: PTY must survive detach")
        require(expected.get("session_identity_preserved") is True, f"{case_id}: identity must survive reattach")
        require(expected.get("spawn_count") == 1, f"{case_id}: reattach must reuse one spawn")
        require(expected.get("reattach") == "same_exact_handle", f"{case_id}: handle replacement is unsafe")
        require(expected.get("input_replay_count") == 0, f"{case_id}: input replay is forbidden")
        return

    if case_id in {"malformed-attach-fails-closed", "expired-attach-fails-closed"}:
        require(kind in {"malformed_handle", "expired_handle"}, f"{case_id}: wrong kind")
        handle = case.get("attach_handle")
        require(isinstance(handle, dict) and handle.get("present") is True, f"{case_id}: invalid handle must be represented")
        require(handle.get("classification") == ("malformed" if case_id.startswith("malformed") else "expired"), f"{case_id}: classification changed")
        require("client.reject_without_upgrade" in names, f"{case_id}: client must reject before upgrade")
        require(not any(name.endswith("spawn") or name == "registry.spawn" for name in names), f"{case_id}: invalid handle spawned a PTY")
        require(expected.get("state") == "failed", f"{case_id}: invalid handle must fail")
        require(expected.get("client_action") == "reject_without_open", f"{case_id}: invalid handle action changed")
        require(expected.get("spawn_count") == 0, f"{case_id}: invalid handle must not spawn")
        require(expected.get("legacy_fallback") is False, f"{case_id}: invalid handle must not fall back to legacy")
        require(expected.get("retry_same_handle") is False, f"{case_id}: invalid handle must not retry")
        if case_id.startswith("expired"):
            assert_order(names, "reaper.reap", "client.reject_without_upgrade", case_id)
            require(expected.get("fresh_session_implicit") is False, f"{case_id}: stale handle must not create a fresh session")
        return

    if case_id == "superseded-socket-fails-closed":
        valid_handle(case)
        require(kind == "superseded_socket", f"{case_id}: wrong kind")
        require(names.count("session.attach") == 2, f"{case_id}: expected old and replacement attaches")
        assert_order(names, "session.attach", "socket.close", case_id)
        require(any(item.get("event") == "socket.close" and item.get("close_code") == 4409 for item in events(case)), f"{case_id}: close code must be 4409")
        assert_order(names, "socket.close", "stale_socket.detach_ignored", case_id)
        require(expected.get("active_socket") == "attach-b", f"{case_id}: replacement must remain active")
        require(expected.get("active_session_state") == "attached", f"{case_id}: replacement must remain attached")
        require(expected.get("stale_socket_action") == "stop_without_retry", f"{case_id}: stale socket must fail closed")
        require(expected.get("close_code") == 4409, f"{case_id}: expected superseded close code")
        require(expected.get("active_detach_count") == 0, f"{case_id}: stale finally detached the replacement")
        return

    if case_id == "retained-output-race":
        valid_handle(case)
        require(kind == "retained_output_race", f"{case_id}: wrong kind")
        payloads = case.get("payloads")
        require(payloads == {"retained_hex": "52", "live_hex": "4c"}, f"{case_id}: payload markers changed")
        schedules = case.get("schedule_variants")
        require(isinstance(schedules, list) and len(schedules) == 2, f"{case_id}: two race schedules are required")
        received = [item.get("receive_order") for item in schedules]
        allowed = [["retained", "live"], ["live", "retained"]]
        require(received == allowed, f"{case_id}: race orders must remain explicit and bounded")
        require(expected.get("allowed_receive_orders") == allowed, f"{case_id}: allowed orders changed")
        require(expected.get("client_visible_boundary") is False, f"{case_id}: source has no replay boundary")
        require(expected.get("render_policy") == "receive_order", f"{case_id}: render policy changed")
        require(expected.get("complete_replay_claim") is False, f"{case_id}: complete replay claim is unsafe")
        require(expected.get("retained_bytes_are_transcript") is False, f"{case_id}: retained bytes are not a transcript")
        return

    if case_id == "retained-output-truncation":
        valid_handle(case)
        require(kind == "retained_output_cap", f"{case_id}: wrong kind")
        observation = case.get("retention_observation")
        require(observation == {"buffer_cap_bytes": 1048576, "appended_bytes": 1048577, "oldest_bytes_dropped": 1}, f"{case_id}: ring-buffer workload changed")
        assert_order(names, "drain.append_output", "ring_buffer.truncate_oldest", case_id)
        assert_order(names, "ring_buffer.truncate_oldest", "session.attach", case_id)
        require(expected.get("truncated") is True, f"{case_id}: truncation must be observable to the validator")
        require(expected.get("oldest_output_may_be_missing") is True, f"{case_id}: oldest output may be missing")
        require(expected.get("complete_replay_claim") is False, f"{case_id}: complete replay claim is unsafe")
        require(expected.get("client_blocks_on_replay") is False, f"{case_id}: replay must not block close")
        return

    if case_id == "no-input-replay":
        valid_handle(case)
        require(kind == "no_input_replay", f"{case_id}: wrong kind")
        require(names.count("input.send") == 1, f"{case_id}: expected one user input")
        require(not any(name.startswith("input.replay") for name in names), f"{case_id}: input replay event is forbidden")
        assert_order(names, "input.send", "session.attach", case_id)
        snapshot_events = event_items(case, "attach.snapshot_send")
        require(len(snapshot_events) == 1, f"{case_id}: exactly one reattach snapshot is required")
        snapshot_payload_ref = snapshot_events[0].get("payload_ref")
        require(snapshot_payload_ref == "output-only", f"{case_id}: reattach snapshot must contain output bytes only")
        require(isinstance(snapshot_payload_ref, str), f"{case_id}: snapshot payload reference is required")
        for marker in ("input", "resize", "prompt", "tool", "action", "command"):
            require(marker not in snapshot_payload_ref.lower(), f"{case_id}: snapshot payload contains a replayable {marker}")
        require(expected.get("input_sent_count") == 1, f"{case_id}: input count changed")
        require(expected.get("input_replayed_count") == 0, f"{case_id}: input replay is forbidden")
        require(expected.get("resize_replayed_count") == 0, f"{case_id}: resize replay is forbidden")
        require(expected.get("prompt_replayed_count") == 0, f"{case_id}: prompt replay is forbidden")
        require(expected.get("tool_action_replayed_count") == 0, f"{case_id}: tool-action replay is forbidden")
        require(expected.get("output_snapshot_may_be_sent") is True, f"{case_id}: output snapshot behavior changed")
        require(expected.get("new_user_action_required") is True, f"{case_id}: retry must be explicit")
        return

    fail(f"unrecognized fixture case {case_id}")


def validate_fixtures(fixtures: dict[str, Any]) -> int:
    require(fixtures.get("schema") == "hermternal.fixture.pty-attach.v1", "fixture schema changed")
    require(fixtures.get("contract") == CONTRACT, "fixture contract changed")
    require(fixtures.get("source_revision") == REVISION, "fixture source revision changed")
    require(fixtures.get("surface") == "web-only", "PTY fixture surface must remain web-only")
    require(fixtures.get("synthetic") is True, "fixtures must be synthetic")
    retention = fixtures.get("retention")
    require(retention == {"ttl_seconds": 1800, "buffer_cap_bytes": 1048576}, "retention contract changed")
    validate_redaction(fixtures)

    cases = fixtures.get("cases")
    require(isinstance(cases, list), "fixtures.cases must be a list")
    ids = [case.get("id") for case in cases if isinstance(case, dict)]
    require(len(ids) == len(set(ids)), "fixture case ids must be unique")
    require(REQUIRED_CASES.issubset(set(ids)), f"missing required cases: {sorted(REQUIRED_CASES - set(ids))}")
    for case in cases:
        require(isinstance(case, dict), "fixture cases must be objects")
        validate_case(case)
    return len(cases)


def fixture_case(fixtures: dict[str, Any], case_id: str) -> dict[str, Any]:
    cases = fixtures.get("cases")
    require(isinstance(cases, list), "fixtures.cases must be a list")
    matches = [case for case in cases if isinstance(case, dict) and case.get("id") == case_id]
    require(len(matches) == 1, f"mutation target {case_id!r} must exist exactly once")
    return matches[0]


def run_mutation_checks(fixtures: dict[str, Any]) -> int:
    """Prove the validator rejects the two previously identified regressions."""
    def mutate_reused_session_identity(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        reuse = event_items(case, "registry.reuse")
        require(len(reuse) == 1, "mutation target must have one registry.reuse event")
        reuse[0]["session_ref"] = "synthetic-session-b"

    def mutate_input_snapshot(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "no-input-replay")
        snapshot = event_items(case, "attach.snapshot_send")
        require(len(snapshot) == 1, "mutation target must have one attach snapshot event")
        snapshot[0]["payload_ref"] = "synthetic-input-a"

    def mutate_tool_action_snapshot(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "no-input-replay")
        snapshot = event_items(case, "attach.snapshot_send")
        require(len(snapshot) == 1, "mutation target must have one attach snapshot event")
        snapshot[0]["payload_ref"] = "synthetic-tool-action-a"

    expect_fixture_failure(
        fixtures,
        "registry reuse points at a different PTY session",
        mutate_reused_session_identity,
    )
    expect_fixture_failure(
        fixtures,
        "reattach snapshot includes synthetic input",
        mutate_input_snapshot,
    )
    expect_fixture_failure(
        fixtures,
        "reattach snapshot includes a tool action",
        mutate_tool_action_snapshot,
    )
    return 3


def validate_source_evidence(evidence: dict[str, Any], source_root: Path | None) -> int:
    require(evidence.get("schema") == "hermternal.source-audit.pty-attach.v1", "source audit schema changed")
    require(evidence.get("contract") == CONTRACT, "source audit contract changed")
    source = evidence.get("source")
    require(isinstance(source, dict), "source audit metadata is required")
    require(source.get("repository") == "NousResearch/hermes-agent", "source repository changed")
    require(source.get("revision") == REVISION, "source revision changed")

    files = evidence.get("files")
    require(isinstance(files, list) and files, "source audit files are required")
    for record in files:
        require(isinstance(record, dict), "source audit file records must be objects")
        path_value = record.get("path")
        require(isinstance(path_value, str) and path_value.startswith("hermes_cli/"), "source audit path must be a Hermes path")
        hex_string(record.get("git_blob_sha"), 40, f"{path_value}.git_blob_sha")
        hex_string(record.get("sha256"), 64, f"{path_value}.sha256")
        size = record.get("size_bytes")
        require(isinstance(size, int) and size > 0, f"{path_value}.size_bytes must be positive")
        ranges = record.get("ranges")
        require(isinstance(ranges, list) and ranges, f"{path_value}.ranges are required")
        for line_range in ranges:
            require(isinstance(line_range, dict), f"{path_value}: line range must be an object")
            start = line_range.get("start")
            end = line_range.get("end")
            require(isinstance(start, int) and isinstance(end, int) and 1 <= start <= end, f"{path_value}: invalid line range")
            hex_string(line_range.get("sha256"), 64, f"{path_value}:{start}-{end}.sha256")
            markers = line_range.get("markers")
            require(isinstance(markers, list) and markers and all(isinstance(marker, str) and marker for marker in markers), f"{path_value}:{start}-{end}.markers are required")

        if source_root is None:
            continue
        local_path = source_root / path_value
        try:
            data = local_path.read_bytes()
        except OSError as exc:
            fail(f"source audit cannot read {local_path}: {exc}")
        require(len(data) == size, f"{path_value}: source size differs")
        require(hashlib.sha256(data).hexdigest() == record["sha256"], f"{path_value}: source sha256 differs")
        require(git_blob_sha(data) == record["git_blob_sha"], f"{path_value}: git blob sha differs")
        lines = data.splitlines(keepends=True)
        for line_range in ranges:
            start = line_range["start"]
            end = line_range["end"]
            require(end <= len(lines), f"{path_value}:{start}-{end}: source is too short")
            chunk = b"".join(lines[start - 1 : end])
            require(hashlib.sha256(chunk).hexdigest() == line_range["sha256"], f"{path_value}:{start}-{end}: range sha differs")
            text = chunk.decode("utf-8")
            for marker in line_range["markers"]:
                require(marker in text, f"{path_value}:{start}-{end}: missing marker {marker!r}")
    observations = evidence.get("observations")
    require(isinstance(observations, list), "source audit observations are required")
    observation_ids = {item.get("id") for item in observations if isinstance(item, dict)}
    require({"legacy-disconnect-terminates", "attach-detach-reattach", "malformed-expired-fail-closed", "superseded-socket-fail-closed", "retained-output-race", "no-input-replay"}.issubset(observation_ids), "source audit observations are incomplete")
    return len(files)


def artifact_size(root: Path) -> int:
    total = 0
    for relative in ARTIFACT_FILES:
        path = root / relative
        require(path.is_file(), f"missing artifact for size baseline: {relative}")
        total += path.stat().st_size
    return total


def write_baseline(path: Path, root: Path, duration_ns: int, case_count: int, mutation_count: int, source_verified: bool) -> None:
    baseline = {
        "schema": "hermternal.fixture-validation-baseline.v1",
        "command": (
            "python3 validate.py --source-root <pinned-checkout>"
            if source_verified else "python3 validate.py"
        ),
        "exit_status": 0,
        "source_verified": source_verified,
        "case_count": case_count,
        "mutation_check_count": mutation_count,
        "fixture_artifact_bytes": artifact_size(root),
        "validation_duration_ns": duration_ns,
        "validation_duration_ms": round(duration_ns / 1_000_000, 3),
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "threshold": None,
    }
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="optional local checkout of the pinned Hermes source")
    parser.add_argument("--baseline-output", type=Path, help="write one measured baseline JSON artifact")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent
    started = time.perf_counter_ns()
    try:
        evidence = load_json(root / "source-evidence.json")
        fixtures = load_json(root / "pty-attach-fixtures.json")
        file_count = validate_source_evidence(evidence, args.source_root)
        case_count = validate_fixtures(fixtures)
        mutation_count = run_mutation_checks(fixtures)
        duration_ns = time.perf_counter_ns() - started
        bytes_count = artifact_size(root)
        if args.baseline_output is not None:
            write_baseline(
                args.baseline_output,
                root,
                duration_ns,
                case_count,
                mutation_count,
                args.source_root is not None,
            )
    except AssertionError as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"validated source_files={file_count} cases={case_count} "
        f"mutation_checks={mutation_count} "
        f"fixture_artifact_bytes={bytes_count} "
        f"duration_ms={duration_ns / 1_000_000:.3f} "
        f"source_checkout_verified={args.source_root is not None}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
