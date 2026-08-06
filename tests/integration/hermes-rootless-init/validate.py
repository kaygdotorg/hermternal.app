#!/usr/bin/env python3
"""Validate the pinned Hermes rootless-init diagnosis fixture.

This module is deliberately offline. It validates bounded synthetic observations
and source identity metadata; it never starts an executor or treats a candidate
capability set as an approved security policy.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = ROOT / "cases.json"
SCHEMA = "hermternal.hermes-rootless-init.v1"
HERMES_COMMIT = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
HERMES_TREE = "886db5eb1150f819344d67fedc81aef0caab09ff"
MAX_JSON_BYTES = 256 * 1024
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 512
MAX_JSON_CONTAINER_ITEMS = 64
MAX_JSON_STRING_BYTES = 4096
MAX_JSON_INTEGER_DIGITS = 12
MAX_ERROR_MESSAGE_BYTES = 160

# These source identities are repeated here rather than trusted only from the
# fixture. The duplicate pin prevents a locally edited JSON record from
# changing the source-backed explanation without changing this validator too.
SOURCE_REFS = (
    (
        "Dockerfile",
        "298-311",
        "2de6192715ed9a839c257b1f34f98d0832797159",
        "The image returns to USER root so stage2 can remap the hermes UID/GID and own startup state.",
    ),
    (
        "docker/stage2-hook.sh",
        "23-24",
        "899c8e86ac989735a27d67cb3b11df88762bbb9b",
        "The bootstrap drops startup work to hermes with s6-setuidgid.",
    ),
    (
        "docker/stage2-hook.sh",
        "214-220",
        "899c8e86ac989735a27d67cb3b11df88762bbb9b",
        "Recursive data-volume chown failures are logged and allowed to continue.",
    ),
    (
        "docker/stage2-hook.sh",
        "234-245",
        "899c8e86ac989735a27d67cb3b11df88762bbb9b",
        "The pinned source explicitly treats rootless chown failure as non-fatal when the mapped volume is already usable.",
    ),
    (
        "docker/stage2-hook.sh",
        "374-396",
        "899c8e86ac989735a27d67cb3b11df88762bbb9b",
        "Fresh startup directories are created through s6-setuidgid hermes.",
    ),
    (
        "docker/cont-init.d/015-supervise-perms",
        "64-86",
        "8d7b473d29ca5cae8da6e24150cec18c8c9284b7",
        "s6 supervise and event ownership warnings are best-effort; the script does not make chown failure fatal.",
    ),
    (
        "docker/main-wrapper.sh",
        "31-31",
        "efabad9839343853106e18bf51657fe5db84f44a",
        "The real CMD path also drops root to hermes with s6-setuidgid.",
    ),
    (
        "docker/s6-rc.d/dashboard/run",
        "53-56",
        "2eb0cf9cb18b38772b35ed156e3a542ed7e51636",
        "An enabled dashboard uses the same root-to-hermes drop.",
    ),
)

APPROVED_BOUNDARY = {
    "cap_drop": ["ALL"],
    "cap_add": [],
    "no_new_privileges": True,
    "host_network": False,
    "published_ports": [],
    "host_profile_bind": False,
    "network_internal": True,
    "volume_kind": "named_project_scoped",
    "restart": "no",
}
REQUIRED_CAPS = ["CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"]
NOT_SOURCE_JUSTIFIED = [
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_SYS_ADMIN",
]
CASE_IDS = (
    "cleanup-after-failed-readiness",
    "docker-cap-drop-all-exit-126",
    "harness-hostconfig-binds-volume-assertion",
    "podman-rootless-supervise-perms-exit-2",
    "unsafe-workaround-arbitrary-user",
    "unsafe-workaround-capability-escalation",
)
MATRIX_COMMON_KEYS = {
    "executor",
    "user_namespace",
    "volume_state",
    "required_caps",
    "conditional_caps",
    "not_source_justified",
    "reason_codes",
}
MATRIX_EXECUTORS = {"docker", "podman"}
POLICY_REASON_CODES = {
    "unsafe-workaround-capability-escalation": [
        "privileged",
        "capability_escalation",
        "host_network",
        "published_port",
        "host_profile_bind",
        "no_new_privileges_disabled",
    ],
    "unsafe-workaround-arbitrary-user": ["arbitrary_user_override"],
}
RUNTIME_CASE_KEYS = {
    "id",
    "kind",
    "executor",
    "rootless",
    "boundary",
    "runtime",
    "cleanup",
    "expected",
}
HARNESS_CASE_KEYS = {"id", "kind", "executor", "rootless", "observed", "expected"}
POLICY_CASE_KEYS = {"id", "kind", "executor", "rootless", "mutation", "expected"}
CLEANUP_CASE_KEYS = {"id", "kind", "executor", "rootless", "runtime", "cleanup", "expected"}
CASE_KEYS_BY_ID = {
    "docker-cap-drop-all-exit-126": RUNTIME_CASE_KEYS,
    "podman-rootless-supervise-perms-exit-2": RUNTIME_CASE_KEYS,
    "harness-hostconfig-binds-volume-assertion": HARNESS_CASE_KEYS,
    "unsafe-workaround-capability-escalation": POLICY_CASE_KEYS,
    "unsafe-workaround-arbitrary-user": POLICY_CASE_KEYS,
    "cleanup-after-failed-readiness": CLEANUP_CASE_KEYS,
}


class ValidationError(ValueError):
    """A stable, intentionally non-sensitive fixture validation failure."""


class DuplicateKeyError(ValidationError):
    """A JSON object repeated a key."""


def _duplicate_key_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate_key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ValidationError("nonfinite_number")


def _validate_json_tree(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES:
        raise ValidationError("too_many_json_nodes")
    if depth > MAX_JSON_DEPTH:
        raise ValidationError("json_too_deep")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if len(str(abs(value))) > MAX_JSON_INTEGER_DIGITS:
            raise ValidationError("integer_too_large")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError("nonfinite_number")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES:
            raise ValidationError("string_too_large")
        if any(ord(char) < 0x20 for char in value):
            raise ValidationError("control_character")
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise ValidationError("array_too_large")
        for child in value:
            _validate_json_tree(child, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise ValidationError("object_too_large")
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValidationError("non_string_key")
            _validate_json_tree(child, depth=depth + 1, nodes=nodes)
        return
    raise ValidationError("unsupported_json_type")


def _load_fixture_bytes(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_JSON_BYTES:
        raise ValidationError("json_too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("invalid_utf8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_key_object,
            parse_constant=_reject_json_constant,
        )
    except DuplicateKeyError:
        raise
    except (json.JSONDecodeError, ValidationError) as error:
        if isinstance(error, ValidationError):
            raise
        raise ValidationError("malformed_json") from error
    _validate_json_tree(value)
    if not isinstance(value, dict):
        raise ValidationError("root_not_object")
    return value


def load_fixture(path: Path = FIXTURE_PATH) -> dict[str, Any]:
    try:
        return _load_fixture_bytes(path.read_bytes())
    except FileNotFoundError as error:
        raise ValidationError("fixture_missing") from error
    except OSError as error:
        raise ValidationError("fixture_unreadable") from error


def _exact_keys(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("object_required")
    if set(value) != keys:
        raise ValidationError("object_keys_mismatch")
    return value


def _string(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("string_required")
    return value


def _bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValidationError("boolean_required")
    return value


def _integer(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("integer_required")
    return value


def _list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError("array_required")
    return value


def _string_list(value: Any, *, exact: list[str] | None = None) -> list[str]:
    values = _list(value)
    if any(not isinstance(item, str) for item in values):
        raise ValidationError("string_array_required")
    if exact is not None and values != exact:
        raise ValidationError("array_value_mismatch")
    return values


def _validate_boundary(value: Any, *, exact: bool = True) -> None:
    keys = set(APPROVED_BOUNDARY)
    boundary = _exact_keys(value, keys)
    _string_list(boundary["cap_drop"], exact=["ALL"])
    _string_list(boundary["cap_add"], exact=[])
    if _bool(boundary["no_new_privileges"]) is not True:
        raise ValidationError("no_new_privileges_required")
    for key in ("host_network", "host_profile_bind", "network_internal"):
        if _bool(boundary[key]) is not APPROVED_BOUNDARY[key]:
            raise ValidationError("isolation_boundary_mismatch")
    _string_list(boundary["published_ports"], exact=[])
    if _string(boundary["volume_kind"]) != "named_project_scoped":
        raise ValidationError("named_volume_required")
    if _string(boundary["restart"]) != "no":
        raise ValidationError("restart_policy_mismatch")
    if exact and boundary != APPROVED_BOUNDARY:
        raise ValidationError("boundary_mismatch")


def _validate_source(data: dict[str, Any]) -> None:
    source = _exact_keys(data["pinned_source"], {"repository", "commit", "tree", "references"})
    if _string(source["repository"]) != "NousResearch/hermes-agent":
        raise ValidationError("source_repository_mismatch")
    if _string(source["commit"]) != HERMES_COMMIT:
        raise ValidationError("source_commit_mismatch")
    if _string(source["tree"]) != HERMES_TREE:
        raise ValidationError("source_tree_mismatch")
    references = _list(source["references"])
    if len(references) != len(SOURCE_REFS):
        raise ValidationError("source_reference_count")
    for reference, expected in zip(references, SOURCE_REFS):
        item = _exact_keys(reference, {"path", "lines", "blob", "finding"})
        if tuple(item[key] for key in ("path", "lines", "blob")) != expected[:3]:
            raise ValidationError("source_reference_mismatch")
        if _string(item["finding"]) != expected[3]:
            raise ValidationError("source_finding_mismatch")


def _validate_matrix(data: dict[str, Any]) -> None:
    # Executor identity is evidence, not decoration: duplicates or a missing
    # variant could make an incomplete matrix look like a passing comparison.
    matrix = _exact_keys(data["capability_matrix"], {"status", "not_live_verified", "entries"})
    if _string(matrix["status"]) != "candidate_only_pending_review":
        raise ValidationError("candidate_status_mismatch")
    if _bool(matrix["not_live_verified"]) is not True:
        raise ValidationError("live_matrix_claim")
    entries = _list(matrix["entries"])
    if len(entries) != 2:
        raise ValidationError("capability_entry_count")
    seen_executors: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValidationError("object_required")
        executor = _string(entry.get("executor"))
        if executor not in MATRIX_EXECUTORS or executor in seen_executors:
            raise ValidationError("capability_executor_count")
        seen_executors.add(executor)
        required_keys = MATRIX_COMMON_KEYS | ({"preconditions"} if executor == "podman" else set())
        item = _exact_keys(entry, required_keys)
        namespace = _string(item["user_namespace"])
        expected_namespace = "rootful" if executor == "docker" else "rootless"
        if namespace != expected_namespace:
            raise ValidationError("namespace_mismatch")
        if _string(item["volume_state"]) != "fresh_named":
            raise ValidationError("fresh_volume_required")
        _string_list(item["required_caps"], exact=REQUIRED_CAPS)
        _string_list(item["conditional_caps"], exact=[])
        _string_list(item["not_source_justified"], exact=NOT_SOURCE_JUSTIFIED)
        reasons = _string_list(item["reason_codes"])
        if reasons != ["stage2_targeted_chown", "stage2_setuidgid", "main_wrapper_setuidgid"]:
            raise ValidationError("capability_reason_mismatch")
        if executor == "podman":
            preconditions = _string_list(item["preconditions"])
            if preconditions != ["subuid_mapping_includes_hermes_uid", "subgid_mapping_includes_hermes_gid", "rootless_user_namespace"]:
                raise ValidationError("rootless_precondition_mismatch")
    if seen_executors != MATRIX_EXECUTORS:
        raise ValidationError("capability_executor_count")


def _validate_proposed_run(data: dict[str, Any]) -> None:
    proposal = _exact_keys(
        data["proposed_one_run"],
        {
            "status",
            "executor",
            "compose_provider",
            "account",
            "rootless",
            "project",
            "image",
            "command",
            "cap_drop",
            "cap_add",
            "no_new_privileges",
            "security_opt",
            "published_ports",
            "binds",
            "host_network",
            "host_profile_bind",
            "network",
            "volume",
            "resource_limits",
            "evidence",
            "teardown",
            "readiness",
            "approval_required",
        },
    )
    if _string(proposal["status"]) != "awaiting_independent_review":
        raise ValidationError("proposal_status_mismatch")
    if _string(proposal["executor"]) != "podman":
        raise ValidationError("proposal_executor_mismatch")
    if _string(proposal["compose_provider"]) != "podman-compose":
        raise ValidationError("proposal_provider_mismatch")
    if _string(proposal["account"]) != "hermternal-test":
        raise ValidationError("proposal_account_mismatch")
    if _bool(proposal["rootless"]) is not True:
        raise ValidationError("proposal_rootless_required")
    if _string(proposal["project"]) != "generated_hermes_rootless_init_candidate":
        raise ValidationError("proposal_project_mismatch")
    if _string(proposal["image"]) != "hermes-agent:hermternal-f5be9236":
        raise ValidationError("proposal_image_mismatch")
    _string_list(proposal["command"], exact=["sleep", "infinity"])
    _string_list(proposal["cap_drop"], exact=["ALL"])
    _string_list(proposal["cap_add"], exact=REQUIRED_CAPS)
    if _bool(proposal["no_new_privileges"]) is not True:
        raise ValidationError("proposal_no_new_privileges")
    _string_list(proposal["security_opt"], exact=["no-new-privileges:true"])
    _string_list(proposal["published_ports"], exact=[])
    _string_list(proposal["binds"], exact=[])
    if _bool(proposal["host_network"]) or _bool(proposal["host_profile_bind"]):
        raise ValidationError("proposal_isolation_mismatch")
    if _string(proposal["network"]) != "generated_internal_project_network":
        raise ValidationError("proposal_network_mismatch")
    if _string(proposal["volume"]) != "generated_named_project_volume":
        raise ValidationError("proposal_volume_mismatch")
    limits = _exact_keys(
        proposal["resource_limits"],
        {"cpus", "memory", "pids", "tmpfs", "shm_size", "log_driver", "log_max_size"},
    )
    if (_string(limits["cpus"]), _string(limits["memory"]), _integer(limits["pids"])) != ("0.50", "512m", 256):
        raise ValidationError("proposal_resource_limits")
    _string_list(limits["tmpfs"], exact=["/tmp:size=64m,mode=1777", "/run:size=16m,mode=755"])
    if _string(limits["shm_size"]) != "64m":
        raise ValidationError("proposal_shm_limit")
    if _string(limits["log_driver"]) != "k8s-file" or _string(limits["log_max_size"]) != "1m":
        raise ValidationError("proposal_log_limit")
    _string_list(proposal["evidence"], exact=["bounded_redacted_state", "native_inspect", "zero_leftover_counts"])
    _string_list(proposal["teardown"], exact=["down", "--volumes", "--remove-orphans"])
    if _string(proposal["readiness"]) != "bounded_container_state_and_native_inspect_only":
        raise ValidationError("proposal_readiness_mismatch")
    if _bool(proposal["approval_required"]) is not True:
        raise ValidationError("proposal_approval_missing")


def _validate_cleanup(value: Any) -> None:
    cleanup = _exact_keys(
        value,
        {
            "project_scope",
            "command",
            "status",
            "leftover_containers",
            "leftover_networks",
            "leftover_volumes",
        },
    )
    if _string(cleanup["project_scope"]) != "recognized_generated_project":
        raise ValidationError("cleanup_scope_unrecognized")
    _string_list(cleanup["command"], exact=["down", "--volumes", "--remove-orphans"])
    if _integer(cleanup["status"]) != 0:
        raise ValidationError("cleanup_command_failed")
    for key in ("leftover_containers", "leftover_networks", "leftover_volumes"):
        count = _integer(cleanup[key])
        if count < 0 or count > 0:
            raise ValidationError("cleanup_leftovers")


def _validate_executor_identity(executor_value: Any, rootless_value: Any) -> str:
    executor = _string(executor_value)
    rootless = _bool(rootless_value)
    if executor == "docker" and not rootless:
        return executor
    if executor == "podman" and rootless:
        return executor
    raise ValidationError("executor_identity_mismatch")


def _validate_runtime_case(case: dict[str, Any]) -> str:
    runtime = _exact_keys(
        case["runtime"],
        {"started", "readiness", "exit_code", "failure_code", "warning_codes", "raw_log_retained"},
    )
    if _bool(runtime["started"]) is not True:
        raise ValidationError("runtime_start_observation_missing")
    if _string(runtime["readiness"]) != "failed":
        raise ValidationError("runtime_readiness_mismatch")
    exit_code = _integer(runtime["exit_code"])
    if exit_code not in {2, 126}:
        raise ValidationError("runtime_exit_code_mismatch")
    failure_code = _string(runtime["failure_code"])
    warning_codes = _string_list(runtime["warning_codes"])
    if _bool(runtime["raw_log_retained"]) is not False:
        raise ValidationError("raw_log_retention")
    _validate_boundary(case["boundary"])
    _validate_cleanup(case["cleanup"])
    executor = _validate_executor_identity(case["executor"], case["rootless"])
    if executor == "docker":
        if (exit_code, failure_code, warning_codes) != (126, "s6_setuidgid_permission_denied", []):
            raise ValidationError("docker_observation_mismatch")
        return "pinned_boundary_incompatibility"
    if (exit_code, failure_code, warning_codes) != (2, "s6_supervise_perms_chown_warning", ["supervise_perms_chown"]):
        raise ValidationError("podman_observation_mismatch")
    return "pinned_rootless_incompatibility"


def _validate_harness_case(case: dict[str, Any]) -> str:
    observed = _exact_keys(case["observed"], {"hostconfig_binds", "mounts", "assertion"})
    binds = _string_list(observed["hostconfig_binds"])
    if binds != ["generated_named_volume:/opt/data:rw"]:
        raise ValidationError("harness_bind_observation_mismatch")
    mounts = _list(observed["mounts"])
    if len(mounts) != 1:
        raise ValidationError("mount_observation_count")
    mount = _exact_keys(mounts[0], {"type", "source_kind", "destination"})
    if tuple(mount[key] for key in ("type", "source_kind", "destination")) != ("volume", "named", "/opt/data"):
        raise ValidationError("mount_observation_mismatch")
    if _string(observed["assertion"]) != "named_volume_must_not_appear_in_hostconfig_binds":
        raise ValidationError("harness_assertion_mismatch")
    if _validate_executor_identity(case["executor"], case["rootless"]) != "docker":
        raise ValidationError("harness_executor_mismatch")
    return "harness_defect"


def _validate_policy_case(case: dict[str, Any]) -> str:
    _validate_executor_identity(case["executor"], case["rootless"])
    if case["id"] == "unsafe-workaround-capability-escalation":
        expected_keys = {
            "cap_drop",
            "cap_add",
            "privileged",
            "no_new_privileges",
            "host_network",
            "published_ports",
            "host_profile_bind",
            "network_internal",
        }
        mutation = _exact_keys(case["mutation"], expected_keys)
        _string_list(mutation["cap_drop"], exact=[])
        _string_list(mutation["cap_add"], exact=["ALL"])
        if not _bool(mutation["privileged"]):
            raise ValidationError("privileged_mutation_missing")
        if _bool(mutation["no_new_privileges"]):
            raise ValidationError("unsafe_nnp_mutation_missing")
        if not _bool(mutation["host_network"]):
            raise ValidationError("unsafe_host_network_missing")
        _string_list(mutation["published_ports"], exact=["9119:9119"])
        if not _bool(mutation["host_profile_bind"]):
            raise ValidationError("unsafe_profile_bind_missing")
        if _bool(mutation["network_internal"]):
            raise ValidationError("unsafe_network_mutation_missing")
        return "unsafe_workaround_rejected"
    if case["id"] == "unsafe-workaround-arbitrary-user":
        expected_keys = {
            "user_override",
            "cap_drop",
            "cap_add",
            "no_new_privileges",
            "host_network",
            "published_ports",
            "host_profile_bind",
            "network_internal",
        }
        mutation = _exact_keys(case["mutation"], expected_keys)
        if _string(mutation["user_override"]) != "arbitrary_non_hermes_uid":
            raise ValidationError("arbitrary_user_mutation_missing")
        _string_list(mutation["cap_drop"], exact=["ALL"])
        _string_list(mutation["cap_add"], exact=[])
        if not _bool(mutation["no_new_privileges"]):
            raise ValidationError("user_mutation_nnp")
        if _bool(mutation["host_network"]) or _bool(mutation["host_profile_bind"]):
            raise ValidationError("user_mutation_isolation")
        _string_list(mutation["published_ports"], exact=[])
        if not _bool(mutation["network_internal"]):
            raise ValidationError("user_mutation_network")
        return "unsafe_workaround_rejected"
    raise ValidationError("unknown_policy_case")


def _validate_cleanup_case(case: dict[str, Any]) -> str:
    runtime = _exact_keys(case["runtime"], {"readiness", "failure_code"})
    if (_string(runtime["readiness"]), _string(runtime["failure_code"])) != ("failed", "s6_supervise_perms_chown_warning"):
        raise ValidationError("cleanup_runtime_mismatch")
    _validate_cleanup(case["cleanup"])
    if _validate_executor_identity(case["executor"], case["rootless"]) != "podman":
        raise ValidationError("cleanup_executor_mismatch")
    return "cleanup_complete"


def _validate_case(case: Any) -> tuple[str, str]:
    if not isinstance(case, dict):
        raise ValidationError("case_object_required")
    case_id = _string(case.get("id"))
    if case_id not in CASE_KEYS_BY_ID:
        raise ValidationError("unknown_case")
    item = _exact_keys(case, CASE_KEYS_BY_ID[case_id])
    kind = _string(item["kind"])
    expected = item["expected"]
    if not isinstance(expected, dict):
        raise ValidationError("expected_object_required")
    if case_id == "docker-cap-drop-all-exit-126":
        if kind != "runtime_observation":
            raise ValidationError("docker_case_kind")
        classification = _validate_runtime_case(item)
        if expected != {"classification": classification, "release_status": "blocked_readiness"}:
            raise ValidationError("docker_expected_mismatch")
        return case_id, classification
    if case_id == "podman-rootless-supervise-perms-exit-2":
        if kind != "runtime_observation":
            raise ValidationError("podman_case_kind")
        classification = _validate_runtime_case(item)
        if expected != {"classification": classification, "release_status": "blocked_readiness"}:
            raise ValidationError("podman_expected_mismatch")
        return case_id, classification
    if case_id == "harness-hostconfig-binds-volume-assertion":
        if kind != "harness_evidence":
            raise ValidationError("harness_case_kind")
        classification = _validate_harness_case(item)
        if expected != {"classification": classification, "correction": "inspect_native_mount_type_and_source_kind"}:
            raise ValidationError("harness_expected_mismatch")
        return case_id, classification
    if case_id in POLICY_REASON_CODES:
        if kind != "policy_mutation":
            raise ValidationError("unsafe_case_kind")
        classification = _validate_policy_case(item)
        if expected.keys() != {"classification", "reason_codes"}:
            raise ValidationError("unsafe_expected_keys")
        if expected["classification"] != classification:
            raise ValidationError("unsafe_expected_mismatch")
        _string_list(expected["reason_codes"], exact=POLICY_REASON_CODES[case_id])
        return case_id, classification
    if case_id == "cleanup-after-failed-readiness":
        if kind != "cleanup_observation":
            raise ValidationError("cleanup_case_kind")
        classification = _validate_cleanup_case(item)
        if expected != {"classification": classification, "release_status": "blocked_readiness"}:
            raise ValidationError("cleanup_expected_mismatch")
        return case_id, classification
    raise ValidationError("unknown_case")


def validate_fixture(data: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        data,
        {
            "schema",
            "operation",
            "issue",
            "synthetic_only",
            "live_execution",
            "pinned_source",
            "approved_boundary",
            "capability_matrix",
            "proposed_one_run",
            "cases",
        },
    )
    if _string(data["schema"]) != SCHEMA:
        raise ValidationError("schema_mismatch")
    if _string(data["operation"]) != "R-02B" or _integer(data["issue"]) != 250:
        raise ValidationError("operation_mismatch")
    if _bool(data["synthetic_only"]) is not True or _bool(data["live_execution"]) is not False:
        raise ValidationError("live_execution_claim")
    _validate_source(data)
    # Validate the complete nested schema before indexing any member. This
    # keeps every deletion mutation on the stable redacted CLI failure path.
    approved = _exact_keys(
        data["approved_boundary"],
        set(APPROVED_BOUNDARY) | {"resource_limits"},
    )
    _validate_boundary(
        {key: approved[key] for key in APPROVED_BOUNDARY},
        exact=True,
    )
    limits = _exact_keys(approved["resource_limits"], {"cpus", "memory", "pids"})
    if (_string(limits["cpus"]), _string(limits["memory"]), _integer(limits["pids"])) != ("0.50", "512m", 256):
        raise ValidationError("resource_limits_mismatch")
    _validate_matrix(data)
    _validate_proposed_run(data)
    cases = _list(data["cases"])
    if len(cases) != len(CASE_IDS):
        raise ValidationError("case_count")
    observed_ids: list[str] = []
    classifications: dict[str, int] = {}
    for case in cases:
        case_id, classification = _validate_case(case)
        observed_ids.append(case_id)
        classifications[classification] = classifications.get(classification, 0) + 1
    if tuple(sorted(observed_ids)) != CASE_IDS:
        raise ValidationError("case_order_or_ids")
    if set(classifications) != {
        "cleanup_complete",
        "harness_defect",
        "pinned_boundary_incompatibility",
        "pinned_rootless_incompatibility",
        "unsafe_workaround_rejected",
    }:
        raise ValidationError("classification_coverage")
    return {
        "case_count": len(cases),
        "classifications": dict(sorted(classifications.items())),
        "candidate_status": "candidate_only_pending_review",
        "live_execution": False,
        "cleanup_complete": True,
    }


# Apply URL/header/assignment redactions before path and blob scans so a
# secret query parameter or credential cannot be exposed by a later rewrite.
_REDACTION_PATTERNS = (
    (re.compile(r"https?://[^\s]+"), "[REDACTED_URL]"),
    (
        re.compile(
            r"(?i)\bauthorization\s*(?::|=)\s*(?:(?:basic|bearer|token)\s+)?"
            r"(?:\"[^\"\\r\\n]*\"|'[^'\\r\\n]*'|[^\s,;}\]]+)"
        ),
        "Authorization: [REDACTED]",
    ),
    (re.compile(r"(?i)\bx-api-key\s*(?::|=)\s*[^\s,;}\]]+"), "X-API-Key: [REDACTED]"),
    (re.compile(r"(?i)\bcookie\s*(?::|=)\s*[^\r\n]+"), "Cookie: [REDACTED]"),
    (
        re.compile(
            r'''(?i)(?:\"|')?\b(?:api[_-]?key|access[_-]?key|token|password|client[_-]?secret)'''
            r'''(?:\"|')?\s*(?::|=)\s*(?:\"[^\"\\r\\n]*\"|'[^'\\r\\n]*'|[^\s,;}\]]+)'''
        ),
        "[REDACTED_ASSIGNMENT]",
    ),
    # A path may contain spaces. Consume through the next structural delimiter
    # rather than stopping at whitespace and leaking the suffix.
    (
        re.compile(
            r"(?<![A-Za-z0-9_])(?:[A-Za-z]:[\\/][^\\r\\n,;]+|\\\\[^\\r\\n,;]+|/(?!/)[^\\r\\n,;]+)"
        ),
        "[REDACTED_PATH]",
    ),
)
_BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{8,}={0,2}(?![A-Za-z0-9+/_-])")


def _redact_base64_match(match: re.Match[str]) -> str:
    token = match.group(0)
    normalized = token.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        base64.b64decode(normalized, validate=True)
    except (ValueError, binascii.Error):
        return token
    return "[REDACTED_BLOB]"


def redact_diagnostic(value: str) -> str:
    """Redact common secret/path shapes and cap diagnostics before output."""
    if not isinstance(value, str):
        return "[REDACTED]"
    redacted = value
    for pattern, replacement in _REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    # Decode only to recognize standard, URL-safe, padded, or short Base64;
    # decoded bytes are never retained in diagnostics.
    redacted = _BASE64_CANDIDATE.sub(_redact_base64_match, redacted)
    redacted = " ".join(redacted.split())
    return redacted.encode("utf-8")[:MAX_ERROR_MESSAGE_BYTES].decode("utf-8", "ignore")


def _result(*, ok: bool, summary: dict[str, Any] | None = None, error: str | None = None) -> dict[str, Any]:
    if not ok:
        return {
            "ok": False,
            "schema": SCHEMA,
            "case_count": 0,
            "classifications": {},
            "candidate_status": "unknown",
            "live_execution": False,
            "cleanup_complete": False,
            "errors": ["validation_failed"],
            "redacted": True,
        }
    assert summary is not None
    return {
        "ok": True,
        "schema": SCHEMA,
        "case_count": summary["case_count"],
        "classifications": summary["classifications"],
        "candidate_status": summary["candidate_status"],
        "live_execution": summary["live_execution"],
        "cleanup_complete": summary["cleanup_complete"],
        "errors": [],
        "redacted": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--fixture", type=Path, default=FIXTURE_PATH)
    args = parser.parse_args(argv)
    try:
        summary = validate_fixture(load_fixture(args.fixture))
    except (ValidationError, OSError, UnicodeError, ValueError):
        print(json.dumps(_result(ok=False), separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(_result(ok=True, summary=summary), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
