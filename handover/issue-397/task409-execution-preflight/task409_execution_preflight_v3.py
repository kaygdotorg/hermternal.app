#!/usr/bin/env python3
"""Task #409 Phase A pre-replay artifact/matrix consistency gate.

Phase A is deliberately consistency-only.  It reads exactly three frozen
artifacts and checks their stable identities, exact hashes, Markdown fence
parity, a closed matrix schema, the approved candidate-4 lane map, and pinned
base inputs.  It never invokes Git, the embedded shell, replay, a network, or a
candidate identity.  A separate approval digest is required by Phase B so this
phase cannot approve caller-supplied OIDs and thereby create circular trust.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve().parent
PARITY_PATH = HERE / "review_frozen_pair.py"
SPEC = importlib.util.spec_from_file_location("task409_frozen_pair_v3", PARITY_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load parity helper: {PARITY_PATH}")
PARITY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PARITY
SPEC.loader.exec_module(PARITY)

SCHEMA = "task409-execution-preflight/v3"
PHASE = "A-pre-replay-artifact-matrix"
LANE = "candidate-4"
MATRIX_SCHEMA = "hermternal.task409.final-execution-matrix.v1"
MATRIX_BASE_REF = "origin/dev"
MATRIX_MAIN_REF = "origin/main"
BASE_REF = "refs/remotes/origin/dev"
MAIN_REF = "refs/remotes/origin/main"
BASE_COMMIT = "729f2613af2b78d58b07918478e9102d5716f367"
BASE_TREE = "43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f"
MAIN_COMMIT = "3ebf8b3fe4767442490ab3053c0c1ccf84e8019f"
REQUIRED_HEADING = b"## Canonical machine-readable ordered execution driver\n"
BASH_OPEN = b"```bash\n"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
IDENTITY_FIELDS = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size", "st_nlink")
MAX_ARTIFACT_SIZE = {"markdown": 2 * 1024 * 1024, "json": 4 * 1024 * 1024, "shell": 2 * 1024 * 1024}
MANDATORY_STALE_PATHS = ("/private/tmp/hermternal-task409-approved-driver.sh", "/tmp/hermternal-task409-final-execution-matrix.md", "/tmp/hermternal-task409-final-execution-matrix.json")
MANDATORY_STALE_HASHES = ("0be7d21cfcb06cbf4ee65509dae974290eca70fa849530643f69f89c3119e97e",)
EXPECTED_LANE_IDS = ("renderer-lifecycle", "static-manifest-chain", "authentication-design-token-manifest", "authentication-semantic-delta", "fixture-registry-authority", "apple-benchmark-range", "proxy-deployment-proof", "launcher-semantic-projection", "dependency-audit-correction", "swift-parity-correction", "live-proof-semantic-projection")
EXPECTED_LANE_KINDS = ("approved-range-plus-semantic-delta", "ordered-commit-range", "ordered-commit-range", "semantic-content-projection", "authority-range-plus-detached-correction", "ordered-commit-range", "ordered-commit-range", "cumulative-semantic-projection", "single-semantic-commit", "direct-source-plus-semantic-child", "cumulative-semantic-projection")
REJECTED_AUTH_ENDPOINTS = (
    "d88cd9adfcef94980ae674f40d99c65e1cf9b666",
    "f87ce048b5afc4fad7ac361baa589d47745b580b",
)
REJECTED_AUTH_RANGE = f"{REJECTED_AUTH_ENDPOINTS[0]}..{REJECTED_AUTH_ENDPOINTS[1]}"
EXPECTED_FINAL_MATRIX_MODE = "100644"
EXPECTED_LANE_PATHS = {
    "renderer-lifecycle": ["apps/web/src/lib/terminal/README.md", "apps/web/src/lib/terminal/renderer.test.ts", "apps/web/tests/bench/terminal-renderer.bench.ts", "apps/web/tests/bench/terminal-renderer.provenance.ts"],
    "static-manifest-chain": ["apps/web/README.md", "apps/web/package.json", "apps/web/tests/static/assert-static-build.mjs", "apps/web/tests/static/terminal-only-manifest.mjs", "apps/web/tests/static/terminal-only-manifest.test.mjs"],
    "authentication-design-token-manifest": ["contracts/design-tokens/README.md", "contracts/design-tokens/web/README.md", "contracts/design-tokens/web/artboards.json", "contracts/design-tokens/web/test_validate.py", "contracts/design-tokens/web/validate.py"],
    "authentication-semantic-delta": ["apps/web/src/lib/auth-ui/AuthPreview.svelte", "apps/web/src/lib/auth-ui/AuthPreview.test.ts", "apps/web/src/lib/auth-ui/BrowserAuthView.svelte", "apps/web/src/lib/auth-ui/BrowserAuthView.test.ts", "apps/web/src/lib/auth-ui/ProviderCard.svelte", "apps/web/src/lib/auth-ui/ProviderCard.test.ts", "apps/web/src/lib/auth-ui/browser-auth-session.test.ts", "apps/web/src/lib/auth-ui/browser-auth.md", "apps/web/src/lib/auth-ui/fixtures.ts", "apps/web/src/lib/auth-ui/types.ts", "apps/web/src/lib/root-route.test.ts", "apps/web/src/lib/root-route.ts", "apps/web/src/lib/workspace/Composer.svelte", "apps/web/src/lib/workspace/Composer.test.ts", "apps/web/src/lib/workspace/LiveWorkspaceView.svelte", "apps/web/src/lib/workspace/LiveWorkspaceView.test.ts", "apps/web/src/lib/workspace/WorkspacePreview.svelte", "apps/web/src/lib/workspace/WorkspacePreview.test.ts", "apps/web/src/lib/workspace/live-workspace-session.test.ts", "apps/web/src/lib/workspace/live-workspace-session.ts", "apps/web/src/routes/ui-preview/+page.svelte", "apps/web/src/routes/ui-preview/ui-preview.test.ts", "apps/web/tests/e2e/ui-preview.spec.ts"],
    "fixture-registry-authority": ["contracts/fixtures/README.md", "contracts/fixtures/index.json", "contracts/fixtures/validator/test_validate.py", "contracts/fixtures/validator/validate.py", "contracts/fixtures/validator/validation-baseline.json", "docs/architecture/fixture-registry-authority.md", "scripts/fixture_authority_test_source.py", "scripts/fixture_registry_authority.objects.bundle", "scripts/fixture_registry_authority.v2.hardened.json", "scripts/fixture_registry_authority.v2.hardened.pin.json", "scripts/test_fixture_registry_authority.py", "scripts/verify_fixture_registry_authority.py"],
    "apple-benchmark-range": ["benchmarks/apple/.gitignore", "benchmarks/apple/Package.swift", "benchmarks/apple/README.md", "benchmarks/apple/Sources/AppleBenchmarkHarness/MockWorkloads.swift", "benchmarks/apple/Sources/AppleBenchmarkHarness/Models.swift", "benchmarks/apple/Sources/AppleBenchmarkHarness/Resources/workload.json", "benchmarks/apple/Sources/AppleBenchmarkHarness/Runner.swift", "benchmarks/apple/Sources/AppleBenchmarkHarness/Support.swift", "benchmarks/apple/Sources/apple-benchmark/main.swift", "benchmarks/apple/Tests/AppleBenchmarkHarnessTests/AppleBenchmarkHarnessTests.swift"],
    "proxy-deployment-proof": ["docs/deployment/README.md", "scripts/README.md", "scripts/caddy_proof.py", "scripts/test_caddy_proof.py", "scripts/test_traefik_proof.py", "scripts/traefik_proof.py", "tests/integration/hermes-caddy/README.md", "tests/integration/hermes-traefik/README.md", "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt", "tests/integration/hermes-traefik/traefik-proof-evidence.json"],
    "launcher-semantic-projection": [".agents/skills/deploy-hermes-agent/SKILL.md", "apps/web/tests/live/README.md", "scripts/README.md", "scripts/hermes_agent.py", "scripts/live_run_marker.py", "scripts/read_launcher_result.py", "scripts/test_hermes_agent.py", "scripts/test_live_run_marker.py", "scripts/test_read_launcher_result.py", "scripts/test_with_live_credential.py", "scripts/with_live_credential.py"],
    "dependency-audit-correction": ["docs/security/dependency-audit.md", "scripts/dependency_audit.py", "scripts/test_dependency_audit.py"],
    "swift-parity-correction": ["contracts/swift-parity/README.md", "contracts/swift-parity/Sources/HermternalSwiftParity/Parity.swift", "contracts/swift-parity/Tests/HermternalSwiftParityTests/ParityTests.swift"],
    "live-proof-semantic-projection": ["apps/web/playwright.live.config.ts", "apps/web/src/lib/live-artifact-policy.test.ts", "apps/web/src/lib/live-screenshot-contract.test.ts", "apps/web/tests/live/README.md", "apps/web/tests/live/live-artifact-policy.mjs", "apps/web/tests/live/live-playwright-config.mjs", "apps/web/tests/live/live-proof-ledger.mjs", "apps/web/tests/live/live-proof-page-bridge.mjs", "apps/web/tests/live/live-proof-parent-compat.mjs", "apps/web/tests/live/live-proof-status.mjs", "apps/web/tests/live/live-reconciliation-auth.mjs", "apps/web/tests/live/live-reconciliation-transport.mjs", "apps/web/tests/live/live-reconciliation.mjs", "apps/web/tests/live/live-screenshot-capture.mjs", "apps/web/tests/live/live-screenshot-contract.mjs", "apps/web/tests/live/live-support-parent-compat.mjs", "apps/web/tests/live/live-trusted-executables.mjs", "apps/web/tests/live/official-hermes.spec.ts", "apps/web/tests/live/reconcile-live-proof.spec.ts", "scripts/README.md", "scripts/test_with_live_credential.py", "scripts/with_live_credential.py"],
}
APPROVED_OVERLAPS = {"scripts/README.md", "apps/web/tests/live/README.md", "scripts/test_with_live_credential.py", "scripts/with_live_credential.py"}
FINAL_ALIAS_KEYS = {"final_head", "final-head", "candidate_ref", "candidate-ref", "candidate_oid", "candidate-oid", "candidate_commit", "candidate-commit", "candidate_parent", "candidate-parent", "candidate_tree", "candidate-tree", "ref_target", "ref-target", "head", "parent", "tree", "oid"}
ROOT_KEYS = {"schema", "phase", "artifacts", "shell_metadata", "normalized_json_sha256", "inputs", "stale", "policy", "approval"}
POLICY_KEYS = {
    "base_ref",
    "base_commit",
    "base_tree",
    "main_ref",
    "main_commit",
    "required_ancestors",
    "forbidden_ancestors",
    "lane_chain",
}

# The frozen matrix has two deliberately closed runtime contracts.  ED is the
# executable authority (37 fields); VC is its review mapping (45 fields).  The
# mapping below is checked before the Phase-A approval digest is calculated so
# a forged or drifted prose contract cannot become authenticated policy.
ED_KEYS = frozenset({
    "argv", "clean_primary_clone_transport", "clean_primary_identity_fields",
    "clean_primary_repository_template", "clean_primary_root_template",
    "clean_primary_root_template_normalized", "clean_primary_storage_identity",
    "clean_primary_whole_worktree_status", "forbidden_commands",
    "fresh_shell_requirement", "immutable", "markdown_fence_extraction",
    "markdown_parity_appendix", "matrix_identity", "matrix_path", "mode",
    "mutation_contract", "no_push_boundary", "non_authoritative_standalone_scripts",
    "object_closure_contract", "ordered_steps", "primary_repository",
    "replay_root_constraint", "replay_root_identity", "replay_root_template",
    "replay_root_template_normalized", "reproducible_hash_commands", "root_creation_contract",
    "schema", "shell", "shell_sha256", "shell_size_metadata", "source_identity_fields",
    "source_of_truth", "strict_git_environment", "trusted_executables",
    "worktree_separation_contract",
})
VC_KEYS = frozenset({
    "clean_primary_clone_transport", "clean_primary_identity_fields",
    "clean_primary_repository_template", "clean_primary_root_template",
    "clean_primary_root_template_normalized", "clean_primary_storage_identity",
    "clean_primary_whole_worktree_status", "declared_projection_state_maps",
    "driver_ordered_steps", "driver_schema", "driver_shell_body_bytes",
    "driver_shell_body_lines", "driver_shell_sha256", "expected_pre_replay_missing_local_object",
    "final_matrix_modes", "forbidden_inherited_environment_patterns", "fresh_shell_requirement",
    "intersection_paths", "invocation_argv", "launcher_mechanical_paths", "launcher_paths",
    "live_mechanical_paths", "live_paths", "live_readme_80fe_blob", "markdown_fence_extraction",
    "markdown_parity_appendix", "matrix_identity", "non_authoritative_standalone_scripts", "object_closure_contract",
    "ordered_steps", "range_target_postcondition_paths", "rejected_auth_endpoints",
    "replay_root_identity", "root_creation_contract", "scripts_readme_blob", "scripts_readme_bytes",
    "scripts_readme_lines", "scripts_readme_sha256", "shell_size_metadata", "source_identity_fields",
    "stage_two_d3_overlap_paths", "strict_environment_allowlist", "swift_source_sha", "union_paths",
    "worktree_separation_contract",
})
ED_TO_VC = {
    "schema": "driver_schema", "argv": "invocation_argv", "ordered_steps": "ordered_steps",
    "strict_git_environment.allowlist": "strict_environment_allowlist",
    "strict_git_environment.reject_inherited_patterns": "forbidden_inherited_environment_patterns",
    "shell_sha256": "driver_shell_sha256",
}

# These two nested contracts are independently trusted validator policy.  They
# are intentionally not copied from the candidate document at validation time.
EXPECTED_MUTATION_CONTRACT = {
    "before_every_mutation_and_cleanup": [
        "validated replay root",
        "primary/worktree separation",
        "primary clean",
        "origin/dev==BASE",
        "origin/main==MAIN",
        "detached current HEAD/tree",
        "replay origin pins",
        "exact dirty transaction paths",
    ],
    "before_first_replay_mutation": ["HEAD==BASE", "HEAD^{tree}==BASE_TREE"],
    "cas_per_path": [
        "declared source-parent tree/blob/mode/type or exact absence",
        "declared stage-precondition tree/blob/mode/type or exact absence",
        "old index blob",
        "old index mode",
        "index stage 0",
        "old worktree blob",
        "old worktree mode",
        "old worktree regular-file type or exact absence",
        "target blob/mode/type after update",
    ],
    "scope_rule": (
        "Range lanes validate source-parent/range scope. Semantic lanes validate source parent/child "
        "delta scope and project explicit target blobs. Candidate-to-source whole-tree diff/apply is "
        "forbidden. Repeated stable IDs in source ancestry audit metadata are not applied; applied "
        "transaction patch IDs must be unique. Matrix approved hashes are source projection gates; "
        "candidate staged patches must independently be non-empty and binary-aware."
    ),
    "overlap_rule": (
        "Launcher uses 10 mechanical paths; live uses 21; the three d3 overlap paths are checked before "
        "live; scripts/README.md is a separate merge."
    ),
    "cleanup_rule": (
        "Only the exact allowlisted replay checkout and README temp, then the explicitly allowlisted "
        "empty REPLAY_ROOT, may be removed; no find, glob, or broad search."
    ),
    "bootstrap_boundary": [
        (
            "Before every bootstrap write, validate the dedicated replay-root shape, primary separation/pins, "
            "and either the empty pre-replay state or the exact detached bootstrap HEAD/tree state."
        ),
        "After HEAD is initialized to BASE, require HEAD==BASE and HEAD^{tree}==BASE_TREE before read-tree.",
    ],
    "cleanup_boundary": [
        (
            "Before each replay checkout, README temp, and final replay-root removal, validate the full "
            "root/HEAD/tree/status boundary."
        ),
        "Only explicit allowlisted paths beneath the validated replay root may be removed.",
    ],
}
EXPECTED_MUTATION_CONTRACT_SHA256 = "d461e58a8c76a457e23de25217b77c95cfbf19cebcd1a3411467ebfb46a4836a"
EXPECTED_REPRODUCIBLE_HASH_COMMANDS = {
    "binary_patch_id": "/usr/bin/git -C REPLAY diff --binary --full-index --no-ext-diff --no-textconv A B -- PATH... | /usr/bin/git patch-id --stable",
    "raw_sha256": "/usr/bin/git -C REPLAY diff --binary --full-index --no-ext-diff --no-textconv A B -- PATH... | /usr/bin/shasum -a 256",
    "launcher_scoped": {
        "left": "729f2613af2b78d58b07918478e9102d5716f367",
        "right": "d3c40687659ee645a5f03bc80cbf61ec8c49979a",
        "stable_patch_id": "0030c185191be447cf53a54cc535c3a0ee172823",
        "raw_sha256": "abf56c277f205c229951bb6165afecb476cce08b5560872455a6d65d72b1b238",
        "mechanical_stable_patch_id": "cd1e6446174eca48b7bca2b263c332e0f71303b1",
        "mechanical_raw_sha256": "5c9f76cd27ba4c4136f324926aab1f01f00e1033b21ee0dfb81da9ac3d016942",
    },
    "live_scoped": {
        "left": "d3c40687659ee645a5f03bc80cbf61ec8c49979a",
        "right": "80fe3b68fb676a3b6589fce9aed79140bf37b667",
        "stable_patch_id": "1e4799b4eaf505bd4b06e939608edabc6698fca6",
        "raw_sha256": "85a8a57fef533d9cb8a3907550a769b704ab2fb478647b16402a12ceb8558fa1",
        "mechanical_stable_patch_id": "304ee69ee3b7753aa516ee86f3b3053d3f9ec97b",
        "mechanical_raw_sha256": "12892436be96696fa5f0261e5c238b5aa82d46267b829b5e081896ab642dd1c3",
    },
}
EXPECTED_REPRODUCIBLE_HASH_COMMANDS_SHA256 = "b58ec751e438693bb91b1dda389ca773c9c616902721525bd25ece47918034f5"
# These hashes bind the nested structures from which VC45 derives its fields.
# They are validator-owned policy, not values copied from validation_contract.
EXPECTED_ORDERED_LANES_SHA256 = "c601f08096b4c304ce05da354b0aee33a7474e520012bf82a91190fd3997888d"
EXPECTED_LIVE_OVERLAP_SHA256 = "9931dd0da8b14f7404d3f958b481646b657e8b8c102b60b19c104fc18d80b22b"
EXPECTED_FORBIDDEN_ANCESTRY_SHA256 = "7b44d0e1acf6929126a1e4621dd9a65ed1f7787881b0be2a50011182a1f5a602"


def _trusted_contract_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


# Fail closed at module load if the validator's embedded policy objects drift
# from their independently reviewed canonical digests.
if _trusted_contract_sha256(EXPECTED_MUTATION_CONTRACT) != EXPECTED_MUTATION_CONTRACT_SHA256:
    raise RuntimeError("embedded mutation contract digest is invalid")
if _trusted_contract_sha256(EXPECTED_REPRODUCIBLE_HASH_COMMANDS) != EXPECTED_REPRODUCIBLE_HASH_COMMANDS_SHA256:
    raise RuntimeError("embedded reproducible hash command digest is invalid")

EXACT_DUPLICATE_CONTRACTS = (
    "markdown_fence_extraction", "shell_size_metadata", "root_creation_contract",
    "worktree_separation_contract", "clean_primary_whole_worktree_status",
    "source_identity_fields", "clean_primary_identity_fields", "matrix_identity",
    "clean_primary_storage_identity", "replay_root_identity", "fresh_shell_requirement",
    "clean_primary_root_template", "clean_primary_repository_template",
    "clean_primary_root_template_normalized", "markdown_parity_appendix",
    "non_authoritative_standalone_scripts", "object_closure_contract",
    "clean_primary_clone_transport",
)
DIRECT_CANONICAL_ED = (
    "immutable", "mode", "source_of_truth", "matrix_path", "primary_repository",
    "replay_root_template", "replay_root_template_normalized", "replay_root_constraint",
    "trusted_executables", "mutation_contract", "forbidden_commands",
    "reproducible_hash_commands", "shell", "no_push_boundary",
)
LANE_ANCHORS = {
    "renderer-lifecycle": "5559e9ad4cf78debc98e8935c47cdc956535f96c",
    "static-manifest-chain": "e664505c7ad9779855a394c62f72823fad7eba76",
    "authentication-design-token-manifest": "d88cd9adfcef94980ae674f40d99c65e1cf9b666",
    "authentication-semantic-delta": "b1741699ca93262306b039771fe96282cb4142fd",
    "fixture-registry-authority": "a88dd1233c01f780544d563b2a030fdd1cfd0c0f",
    "apple-benchmark-range": "8be4f513286813a7a1cbe7bbc997f53b7d557209",
    "proxy-deployment-proof": "e3a2d2e662f2e606f318d35f4fccc63ba9738f7c",
    "launcher-semantic-projection": "d3c40687659ee645a5f03bc80cbf61ec8c49979a",
    "dependency-audit-correction": "a2a8a0b03f515409a02e6668d2600e5ebb6e5152",
    "swift-parity-correction": "221620c04bb051f2597c52bdeb16ccc55c5b2e9c",
    "live-proof-semantic-projection": "80fe3b68fb676a3b6589fce9aed79140bf37b667",
}
FORBIDDEN_ANCESTRY = (
    "13df3d058f1d14ca07b199a45c5b01cb4bf7b020",
    "f87ce048b5afc4fad7ac361baa589d47745b580b",
    "7271e7bac836a519c3df66a93ceb3b2c5a0d8921",
    "03e2b0c828276044d1229c0200a5ac969140a344",
    "ad9bc22b7cc86e0c007a0347e2dec78fa49132a4",
    "48b58c19e4e4991d1d15321a8e39b8261937b59b",
    "c7ab4f9b0fec97b4e4de20bada6f43e57bd7d5e3",
    "1f4388b24ccf7ebc3c42b2192515ae343a52083a",
    "9d9756b2a0a20130258766ea3a532c067e2f13f6",
    "77c6701c652a6bbd23d2c32227dcd61c34dd8c33",
    "44cc58146569bc580d9fd3f78b9241102df62c97",
    "f7bf2f131fa079a4d204b86619039600d1559028",
    "293dbca7f4e992d16e848acb73dd29257ed4ad0d",
    "befb8c7e673157932f5f13242d863e64806cffac",
    "83c709bf9a22672362662f7c369b2c235f5859e9",
    "b1741699ca93262306b039771fe96282cb4142fd",
    "94b0dd97247093f5ca3eb5dee4f1e3c6926e6439",
    "d3c40687659ee645a5f03bc80cbf61ec8c49979a",
    "f54c8511e67a50fa7a00bf28e694459c77cf21c3",
    "80fe3b68fb676a3b6589fce9aed79140bf37b667",
    "221620c04bb051f2597c52bdeb16ccc55c5b2e9c",
    "027806c8596f8b9a4ce200b2fe1344e013f46685",
)


def _expected_policy() -> dict[str, Any]:
    return {
        "base_ref": BASE_REF,
        "base_commit": BASE_COMMIT,
        "base_tree": BASE_TREE,
        "main_ref": MAIN_REF,
        "main_commit": MAIN_COMMIT,
        "required_ancestors": [BASE_COMMIT],
        "forbidden_ancestors": list(dict.fromkeys(FORBIDDEN_ANCESTRY)),
        "lane_chain": [
            {"id": lane_id, "anchor": LANE_ANCHORS[lane_id]}
            for lane_id in EXPECTED_LANE_IDS
        ],
    }


def policy_digest(policy: Mapping[str, Any]) -> str:
    raw = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


APPROVED_POLICY_SHA256 = policy_digest(_expected_policy())


def phase_a_approval_digest(manifest: Mapping[str, Any]) -> str:
    """Bind the consistency result and authenticated ancestry policy without recursion."""
    payload = {
        key: manifest[key]
        for key in (
            "schema",
            "phase",
            "artifacts",
            "shell_metadata",
            "normalized_json_sha256",
            "inputs",
            "stale",
            "policy",
        )
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class Reject(Exception):
    """A deliberate fail-closed preflight rejection."""


def reject(message: str) -> None:
    raise Reject(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def _identity(st: os.stat_result) -> dict[str, int]:
    return {"st_dev": int(st.st_dev), "st_ino": int(st.st_ino), "st_uid": int(st.st_uid), "st_gid": int(st.st_gid), "st_mode": int(stat.S_IMODE(st.st_mode)), "st_size": int(st.st_size), "st_nlink": int(st.st_nlink)}


def _safe_read(path: Path, label: str, limit: int) -> tuple[bytes, os.stat_result]:
    try:
        raw, st = PARITY.read_stable(path)
    except SystemExit as exc:
        reject(f"{label}: {exc}")
    require(len(raw) <= limit, f"{label} exceeds bounded size")
    require(st.st_uid == os.getuid() and not stat.S_IMODE(st.st_mode) & 0o022 and st.st_nlink == 1, f"{label} is not private")
    return raw, st


def read_twice(path: Path, label: str, limit: int) -> tuple[bytes, os.stat_result]:
    first, fst = _safe_read(path, label, limit)
    second, sst = _safe_read(path, label, limit)
    require(first == second and _identity(fst) == _identity(sst), f"{label} changed during preflight")
    return first, fst


def canonical_absolute(value: Any, label: str, *, must_exist: bool = True) -> Path:
    require(isinstance(value, str) and value and "\x00" not in value, f"{label} must be a nonempty path")
    path = Path(value)
    require(path.is_absolute(), f"{label} must be absolute")
    if must_exist:
        require(str(path) == os.path.realpath(str(path)), f"{label} must be canonical absolute")
    else:
        parent = path.parent
        require(str(parent) == os.path.realpath(str(parent)), f"{label} parent must be canonical")
        require(not path.exists() and not os.path.lexists(path), f"{label} leaf must not already exist")
    return path


def _json_pairs(label: str):
    def hook(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in items:
            require(key not in value, f"{label} contains duplicate key {key!r}")
            value[key] = child
        return value
    return hook


def parse_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_pairs(label))
    except Reject:
        raise
    except Exception as exc:
        reject(f"{label} JSON parse failed: {exc}")
    require(isinstance(value, dict), f"{label} root must be an object")
    return value


def _walk_aliases(value: Any, path: tuple[str, ...] = ()) -> None:
    """Reject identity aliases except ledger OIDs at exact matrix locations."""
    allowed_generic = {
        ("base", "commit"), ("base", "tree"), ("base", "protected_main_commit"),
    }
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace(" ", "").replace("-", "_")
            location = path + (str(key),)
            generic_allowed = normalized in {"parent", "tree", "commit", "oid"} and (
                location[-2:] in {("source_commits", str(key)), ("ordered_commits", str(key))}
                or location[-1:] == ("parent",) and any(part in {"source_commits", "ordered_commits"} for part in path)
                or location[-1:] == ("tree",) and any(part in {"source_commits", "source_parent_state", "stage_precondition", "semantic_delta"} for part in path)
                or location[-1:] == ("commit",) and any(part in {"source_commits", "source_parent_state", "stage_precondition"} for part in path)
                or location in allowed_generic
            )
            if normalized in {item.replace("-", "_") for item in FINAL_ALIAS_KEYS} and not generic_allowed:
                reject(f"Phase A forbids final identity alias at /{'/'.join(location)}")
            _walk_aliases(child, location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_aliases(child, path + (str(index),))


def _nested_get(value: Mapping[str, Any], dotted: str) -> Any:
    current: Any = value
    for part in dotted.split("."):
        require(isinstance(current, Mapping) and part in current, f"execution driver missing {dotted}")
        current = current[part]
    return current


def _canonical_execution_contract(document: Mapping[str, Any], json_path: Path, shell_raw: bytes, shell_sha: str, shell_meta: Mapping[str, Any]) -> None:
    """Authenticate the closed ED37/VC45 contract before any Phase-A digest.

    ED and VC are candidate-derived evidence, never mutual authority.  Mapped
    and duplicated values must agree, while direct ED expectations are fixed by
    this validator and the supplied artifact paths/raw shell bytes.
    """
    execution = document.get("execution_driver")
    validation = document.get("validation_contract")
    require(isinstance(execution, dict) and isinstance(validation, dict), "execution and validation contracts must be objects")
    require(frozenset(execution) == ED_KEYS, "execution_driver fields differ from closed ED37 schema")
    require(frozenset(validation) == VC_KEYS, "validation_contract fields differ from closed VC45 schema")

    mapped = {"schema": "driver_schema", "argv": "invocation_argv", "ordered_steps": "ordered_steps",
              "strict_git_environment.allowlist": "strict_environment_allowlist",
              "strict_git_environment.reject_inherited_patterns": "forbidden_inherited_environment_patterns",
              "shell_sha256": "driver_shell_sha256"}
    duplicated = set(EXACT_DUPLICATE_CONTRACTS)
    raw_derived = {"shell_sha256", "shell_size_metadata"}
    # Nested strict_git_environment members are represented by one ED field;
    # keep the coverage assertion at the closed top-level ED37 boundary.
    covered = {source.split(".", 1)[0] for source in mapped} | duplicated | raw_derived | set(DIRECT_CANONICAL_ED)
    require(covered == set(ED_KEYS), "ED37 coverage mapping is incomplete or has extra fields")
    require(set(mapped.values()) | duplicated | {
        "driver_shell_body_bytes", "driver_shell_body_lines", "strict_environment_allowlist",
        "forbidden_inherited_environment_patterns", "driver_schema", "invocation_argv", "driver_ordered_steps",
    } <= set(VC_KEYS), "VC45 coverage mapping targets missing fields")

    lanes = document.get("ordered_lanes")
    live_overlap = document.get("live_overlap")
    forbidden_ancestry = document.get("forbidden_ancestry")
    require(isinstance(lanes, list) and isinstance(live_overlap, dict) and isinstance(forbidden_ancestry, dict), "VC authoritative source structures are missing")
    # Bind every candidate-derived source used below to an independently
    # canonical fixture projection.  This prevents paired mutation of a source
    # structure and its copied VC scalar from satisfying a circular comparison.
    require(_trusted_contract_sha256(lanes) == EXPECTED_ORDERED_LANES_SHA256, "ordered lane authority differs")
    require(_trusted_contract_sha256(live_overlap) == EXPECTED_LIVE_OVERLAP_SHA256, "live overlap authority differs")
    require(_trusted_contract_sha256(forbidden_ancestry) == EXPECTED_FORBIDDEN_ANCESTRY_SHA256, "forbidden ancestry authority differs")
    blob_matrix = live_overlap.get("blob_matrix")
    require(isinstance(blob_matrix, list) and blob_matrix, "VC blob matrix is missing")

    def _ordered_unique_paths(values: Sequence[str], label: str) -> list[str]:
        require(all(isinstance(path, str) for path in values), f"{label} paths are not strings")
        require(len(values) == len(set(values)), f"{label} paths contain duplicates")
        require(list(values) == sorted(values), f"{label} paths are not canonical sorted order")
        return list(values)

    def _matrix_paths(flag: str) -> list[str]:
        return _ordered_unique_paths([row["path"] for row in blob_matrix if row.get(flag) is True], f"blob_matrix.{flag}")

    launcher_paths = _matrix_paths("launcher_scope")
    live_paths = _matrix_paths("live_scope")
    union_paths = _ordered_unique_paths(sorted(set(launcher_paths) | set(live_paths)), "blob matrix union")
    intersection_paths = _ordered_unique_paths(sorted(set(launcher_paths) & set(live_paths)), "blob matrix intersection")
    launcher_mechanical_paths = _matrix_paths("launcher_mechanical")
    live_mechanical_paths = _matrix_paths("live_mechanical")
    stage_two_paths = _ordered_unique_paths(list(live_overlap.get("stage_two_required_d3_overlap_paths", [])), "stage-two d3 overlap")
    require(validation["declared_projection_state_maps"] == sum(isinstance(lane, dict) and "source_parent_state" in lane and "stage_precondition" in lane for lane in lanes), "VC declared projection state maps differ")
    require(validation["range_target_postcondition_paths"] == sum(len(commit.get("target_states", {})) for lane in lanes if isinstance(lane, dict) for commit in lane.get("range", {}).get("source_commits", [])), "VC range target postcondition paths differ")
    require(validation["launcher_paths"] == len(launcher_paths) and validation["live_paths"] == len(live_paths), "VC launcher/live path counts differ")
    require(validation["launcher_mechanical_paths"] == len(launcher_mechanical_paths) and validation["live_mechanical_paths"] == len(live_mechanical_paths), "VC mechanical path counts differ")
    require(validation["union_paths"] == len(union_paths) and validation["intersection_paths"] == len(intersection_paths), "VC union/intersection counts differ")
    require(validation["stage_two_d3_overlap_paths"] == len(stage_two_paths), "VC stage-two overlap count differs")
    require(validation["final_matrix_modes"] == f"{EXPECTED_FINAL_MATRIX_MODE} for all 29 rows" and len(blob_matrix) == 29 and {row.get("expected_final_mode") for row in blob_matrix} == {EXPECTED_FINAL_MATRIX_MODE}, "VC final matrix modes differ")
    require(validation["rejected_auth_endpoints"] == list(REJECTED_AUTH_ENDPOINTS), "VC rejected auth endpoints differ")
    require(validation["swift_source_sha"] == next((lane.get("source_commit", {}).get("commit") for lane in lanes if lane.get("id") == "swift-parity-correction"), None), "VC Swift source SHA differs")
    scripts_readme = live_overlap.get("scripts_readme")
    require(isinstance(scripts_readme, dict), "VC scripts README source is missing")
    require(validation["live_readme_80fe_blob"] == next((row.get("80fe_live_blob") for row in blob_matrix if row.get("path") == "apps/web/tests/live/README.md"), None), "VC live README blob differs")
    require(validation["expected_pre_replay_missing_local_object"] == scripts_readme.get("expected_git_blob"), "VC missing-local object differs")
    require(validation["scripts_readme_bytes"] == scripts_readme.get("expected_bytes"), "VC scripts README bytes differ")
    require(validation["scripts_readme_lines"] == scripts_readme.get("expected_lines"), "VC scripts README lines differ")
    require(validation["scripts_readme_sha256"] == scripts_readme.get("expected_sha256"), "VC scripts README SHA differs")
    require(validation["scripts_readme_blob"] == scripts_readme.get("expected_git_blob"), "VC scripts README blob differs")

    for source, target in mapped.items():
        require(_nested_get(execution, source) == validation[target], f"ED/VC mapped field differs: {source} -> {target}")
    for key in duplicated:
        require(execution[key] == validation[key], f"ED/VC duplicate field differs: {key}")

    # These fields are trusted only against fixed validator-owned objects.  Do
    # this before validating the candidate-provided shell bytes so shell
    # metadata cannot authenticate a forged mutation or hash contract.
    require(execution["mutation_contract"] == EXPECTED_MUTATION_CONTRACT, "mutation contract differs from trusted policy")
    require(_trusted_contract_sha256(execution["mutation_contract"]) == EXPECTED_MUTATION_CONTRACT_SHA256, "mutation contract digest differs from trusted policy")
    require(execution["reproducible_hash_commands"] == EXPECTED_REPRODUCIBLE_HASH_COMMANDS, "reproducible hash commands differ from trusted policy")
    require(_trusted_contract_sha256(execution["reproducible_hash_commands"]) == EXPECTED_REPRODUCIBLE_HASH_COMMANDS_SHA256, "reproducible hash commands digest differs from trusted policy")

    authority = document.get("authority")
    require(isinstance(authority, dict) and set(authority) == {"repository", "no_repository_files_changed"}, "authority is not closed")
    repository = authority["repository"]
    require(isinstance(repository, str) and repository == os.path.realpath(repository), "authority repository is not canonical")
    require(execution["immutable"] is True, "execution driver immutable flag differs")
    require(execution["mode"] == "offline-future-replay-only", "execution driver mode differs")
    require(execution["source_of_truth"] == "/execution_driver/shell", "execution source_of_truth differs")
    require(execution["matrix_path"] == str(json_path), "execution matrix_path differs from supplied JSON")
    require(execution["primary_repository"] == repository, "execution primary repository differs from authority")
    require(execution["replay_root_template"] == "/private/tmp/hermternal-task409-final-replay.$$", "replay root template differs")
    require(execution["replay_root_template_normalized"] == execution["replay_root_template"], "normalized replay root template differs")
    require(execution["replay_root_constraint"] == "absolute /private/tmp root outside the primary checkout and every registered/nested worktree", "replay root constraint differs")
    require(execution["trusted_executables"] == {
        "bash": "/bin/bash", "cut": "/usr/bin/cut", "env": "/usr/bin/env", "git": "/usr/bin/git",
        "mkdir": "/bin/mkdir", "python3": "/opt/homebrew/bin/python3", "rm": "/bin/rm",
        "rmdir": "/bin/rmdir", "shasum": "/usr/bin/shasum",
    }, "trusted executable map differs")
    require(execution["mutation_contract"] is not None, "mutation contract is missing")
    mutation_contract_sha = hashlib.sha256(json.dumps(
        execution["mutation_contract"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    require(mutation_contract_sha == EXPECTED_MUTATION_CONTRACT_SHA256, "mutation contract differs from canonical authority")
    require(execution["forbidden_commands"] == ["git fetch", "git push", "git worktree add", "git merge -s ours", "-X ours", "--strategy-option=ours", "curl", "ssh", "WebSocket", "live Hermes", "credential access"], "forbidden command list differs")
    require(execution["reproducible_hash_commands"] is not None, "reproducible hash commands are missing")
    reproducible_hash_commands_sha = hashlib.sha256(json.dumps(
        execution["reproducible_hash_commands"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    require(reproducible_hash_commands_sha == EXPECTED_REPRODUCIBLE_HASH_COMMANDS_SHA256, "reproducible hash commands differ from canonical authority")
    require(execution["no_push_boundary"] == "The driver stops after final remote equality and independent approval requirement. A separate approved operator may consider a normal non-force push outside this artifact.", "no-push boundary differs")
    require(execution["shell"].encode("utf-8") == shell_raw, "raw shell bytes differ from ED shell")
    require(execution["shell_sha256"] == shell_sha and hashlib.sha256(shell_raw).hexdigest() == shell_sha, "raw shell hash differs")
    require(execution["shell_size_metadata"] == dict(shell_meta), "raw shell metadata differs")
    require(validation["driver_shell_body_bytes"] == len(shell_raw) and validation["driver_shell_body_lines"] == shell_raw.count(b"\n"), "VC raw shell size differs")
    require(shell_raw.endswith(b"\n") and validation["shell_size_metadata"]["terminal_byte_hex"] == shell_raw[-1:].hex(), "raw shell LF metadata differs")


def exact_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} must be 64 lowercase hexadecimal characters")
    return value


def exact_oid(value: Any, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value) is not None, f"{label} must be exactly 40 lowercase hexadecimal characters")
    return value


def _path(value: Any, label: str) -> str:
    require(isinstance(value, str) and value and len(value) <= 4096 and "\x00" not in value, f"{label} path is invalid")
    require(not value.startswith("/") and "\\" not in value, f"{label} path must be relative POSIX")
    require(not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value), f"{label} path contains controls")
    parts = value.split("/")
    require(all(part not in {"", ".", ".."} and not part.startswith("-") for part in parts), f"{label} path has traversal or unsafe component")
    return value


LANE_KEYSETS = {
    "renderer-lifecycle": {"order", "id", "title", "kind", "range", "semantic_delta", "owned_paths", "rejected_sources", "note", "source_parent_state", "stage_precondition"},
    "static-manifest-chain": {"order", "id", "title", "kind", "range", "owned_paths", "ordered_commits", "do_not_reorder"},
    "authentication-design-token-manifest": {"order", "id", "title", "kind", "range", "owned_paths"},
    "authentication-semantic-delta": {"order", "id", "title", "kind", "semantic_delta", "rehearsal_oracle", "owned_paths", "source_parent_state", "stage_precondition"},
    "fixture-registry-authority": {"order", "id", "title", "kind", "range", "semantic_delta", "owned_paths", "evidence", "source_parent_state", "stage_precondition"},
    "apple-benchmark-range": {"order", "id", "title", "kind", "range", "owned_paths"},
    "proxy-deployment-proof": {"order", "id", "title", "kind", "range", "owned_paths", "must_precede", "live_overlap_rank"},
    "launcher-semantic-projection": {"order", "id", "title", "kind", "source_commit", "source_ancestry_audit", "projection_parent", "projection_paths", "mechanical_paths", "excluded_mechanical_paths", "precondition_map", "note", "projection_parent_tree", "source_parent_state", "stage_precondition"},
    "dependency-audit-correction": {"order", "id", "title", "kind", "source_commit", "owned_paths", "rejected_sources", "source_parent_state", "stage_precondition"},
    "swift-parity-correction": {"order", "id", "title", "kind", "source_commit", "semantic_delta", "owned_paths", "identity_checks", "source_parent_state", "stage_precondition"},
    "live-proof-semantic-projection": {"order", "id", "title", "kind", "source_commit", "intermediate_checkpoint", "source_ancestry_audit", "projection_parent", "projection_paths", "mechanical_paths", "excluded_mechanical_paths", "required_d3_overlap_preconditions", "precondition_map", "note", "projection_parent_tree", "source_parent_state", "stage_precondition"},
}


def _validate_lane_map(document: Mapping[str, Any]) -> None:
    lanes = document.get("ordered_lanes")
    require(isinstance(lanes, list) and len(lanes) == len(EXPECTED_LANE_IDS), "ordered_lanes cardinality differs")
    for index, (lane_id, kind) in enumerate(zip(EXPECTED_LANE_IDS, EXPECTED_LANE_KINDS), 1):
        lane = lanes[index - 1]
        require(isinstance(lane, dict), f"lane {index} is not an object")
        require(set(lane) == LANE_KEYSETS[lane_id], f"lane {lane_id} fields differ")
        require(lane["id"] == lane_id and lane["kind"] == kind and lane["order"] == index, f"lane {lane_id} identity differs")
        paths = lane.get("owned_paths", lane.get("projection_paths"))
        require(paths == EXPECTED_LANE_PATHS[lane_id], f"lane {lane_id} path map differs")
        require(len(paths) == len(set(paths)), f"lane {lane_id} contains duplicate paths")
        for item in paths:
            _path(item, f"lane {lane_id}")
    seen: dict[str, list[str]] = {}
    for lane in lanes:
        for item in lane.get("owned_paths", lane.get("projection_paths")):
            seen.setdefault(item, []).append(lane["id"])
    require(set(item for item, owners in seen.items() if len(owners) > 1) == APPROVED_OVERLAPS, "lane overlap set differs")


def check_candidate_matrix_schema(document: dict[str, Any], md_raw: bytes, expected: Mapping[str, Any], object_width: int = 40) -> None:
    require(document.get("schema") == MATRIX_SCHEMA and document.get("task") == 409 and document.get("artifact_task") == 464, "candidate matrix identity differs")
    require(document.get("base", {}).get("ref") == MATRIX_BASE_REF and document.get("base", {}).get("protected_main_ref") == MATRIX_MAIN_REF, "matrix base refs differ")
    base = document["base"]
    exact_oid(base["commit"], "matrix base commit")
    exact_oid(base["tree"], "matrix base tree")
    exact_oid(base["protected_main_commit"], "matrix protected main commit")
    require(base["commit"] == expected["base_commit"] and base["tree"] == expected["base_tree"] and base["protected_main_commit"] == expected["main_commit"], "matrix base OIDs differ")
    _validate_lane_map(document)
    authority = document.get("authority")
    require(
        isinstance(authority, dict)
        and set(authority) == {"repository", "no_repository_files_changed"},
        "matrix authority fields differ",
    )
    repository = authority.get("repository")
    require(
        isinstance(repository, str)
        and repository
        and "\x00" not in repository
        and os.path.isabs(repository)
        and os.path.realpath(repository) == repository,
        "matrix authority repository differs",
    )
    require(authority.get("no_repository_files_changed") is True, "matrix authority boundary differs")
    # Candidate 4/5 keep authority in the closed JSON object only.  The legacy
    # Markdown Authority row belongs to the superseded candidate-final matrix;
    # accepting it would make two metadata channels authoritative.
    authority_rows = re.findall(rb"^\|\s*Authority\s*\|.*$", md_raw, flags=re.MULTILINE)
    require(not authority_rows, "Markdown Authority rows must be absent")


def check_stale_references(md_raw: bytes, json_raw: bytes, shell: bytes, paths: Sequence[str], hashes: Sequence[str]) -> None:
    require(len(paths) == len(set(paths)) and len(hashes) == len(set(hashes)), "stale declarations contain duplicates")
    for item in MANDATORY_STALE_PATHS:
        require(item in paths, f"mandatory stale path omitted: {item}")
    for item in MANDATORY_STALE_HASHES:
        require(item in hashes, f"mandatory stale hash omitted: {item}")
    md = md_raw.decode("utf-8", "strict"); js = json_raw.decode("utf-8", "strict"); sh = shell.decode("utf-8", "strict")
    for token in [*paths, *hashes]:
        require(token not in sh, f"stale token appears in shell: {token}")
        if token in MANDATORY_STALE_PATHS[1:] or token in MANDATORY_STALE_HASHES:
            require(token not in js, f"superseded token appears in JSON: {token}")
        for match in re.finditer(re.escape(token.lower()), md.lower()):
            context = md.lower()[max(0, match.start() - 240):match.end() + 280]
            require(any(word in context for word in ("stale", "non-authoritative", "do not execute", "ignore", "rejected")), f"stale token lacks non-execution context: {token}")


_MARKDOWN_ALIAS = r"(?:candidate[_ -](?:ref|oid|commit|parent|tree)|ref[_ -]?target|final[_ -]?head)"
_MARKDOWN_OUTSIDE_ALIAS_RE = re.compile(_MARKDOWN_ALIAS + r"\s*[:=]", re.IGNORECASE)
_MARKDOWN_INSIDE_CONCRETE_ALIAS_RE = re.compile(
    rf"(?i:{_MARKDOWN_ALIAS})\s*[:=]\s*[\"']?"
    rf"(?:[0-9a-f]{{40}}(?![0-9a-f])|"
    rf"refs/[A-Za-z0-9._/-]+(?![A-Za-z0-9._/-]))"
    rf"(?=[\s\"'`;|&\\)]|$)"
)
_MARKDOWN_OPENING_FENCE_RE = re.compile(rb"(?m)^```bash\n")
_MARKDOWN_CLOSING_FENCE_RE = re.compile(rb"(?m)^```[ \t]*(?:\r?\n|\Z)")


def _canonical_shell_fence_span(md_raw: bytes, shell_raw: bytes) -> tuple[int, int, int, int]:
    """Return the exact line-anchored opening/body/closing shell span.

    The frozen parity helper recognizes the first raw triple-backtick token.  A
    shell body may contain an inline triple-backtick string, so Phase A uses the
    stricter line-anchored grammar here and compares the resulting bytes to the
    supplied shell directly.  Standalone closing fences remain unambiguous and a
    later standalone close is rejected as a duplicate.
    """
    heading_at = md_raw.find(REQUIRED_HEADING)
    require(heading_at >= 0, "Markdown shell heading is missing")
    opening = _MARKDOWN_OPENING_FENCE_RE.search(md_raw, heading_at + len(REQUIRED_HEADING))
    require(opening is not None, "Markdown shell opening fence is missing")
    closing = _MARKDOWN_CLOSING_FENCE_RE.search(md_raw, opening.end())
    require(closing is not None, "Markdown shell closing fence is missing")
    require(md_raw[opening.end():closing.start()] == shell_raw, "Markdown shell fence boundaries differ")
    trailing_closing = _MARKDOWN_CLOSING_FENCE_RE.search(md_raw, closing.end())
    require(trailing_closing is None, "Markdown contains a duplicate standalone closing fence")
    return opening.start(), opening.end(), closing.start(), closing.end()


def _check_markdown(md_raw: bytes, shell_raw: bytes, shell_sha: str, normalized_sha: str, shell_meta: Mapping[str, Any]) -> None:
    opening_start, body_start, closing_start, closing_end = _canonical_shell_fence_span(md_raw, shell_raw)
    text = md_raw.decode("utf-8", "strict")
    for literal in (f"Driver shell SHA-256: `{shell_sha}`", f"normalized JSON identity `{normalized_sha}`", f"Shell body bytes | `{shell_meta['body_bytes']}`", f"Shell body lines | `{shell_meta['body_lines']}`", f"terminal byte `{shell_meta['terminal_byte_hex']}`"):
        require(literal in text, f"Markdown omits {literal}")
    inside_text = shell_raw.decode("utf-8", "strict")
    if _MARKDOWN_INSIDE_CONCRETE_ALIAS_RE.search(inside_text):
        reject("Markdown shell contains a concrete final candidate identity claim")
    # Outside the exact parity-authenticated fence, reject every alias
    # assignment, including placeholders that are safe in executable source.
    outside_text = (md_raw[:opening_start] + md_raw[closing_end:]).decode("utf-8", "strict")
    for line in outside_text.splitlines():
        if _MARKDOWN_OUTSIDE_ALIAS_RE.search(line):
            reject("Markdown contains a final candidate identity claim")


def validate_manifest(manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    require(set(manifest) == ROOT_KEYS, "Phase A manifest fields differ")
    require(manifest["schema"] == SCHEMA and manifest["phase"] == PHASE, "Phase A manifest schema/phase differs")
    _walk_aliases(manifest)
    artifacts = manifest["artifacts"]
    require(isinstance(artifacts, dict) and set(artifacts) == {"markdown", "json", "shell"}, "manifest artifact set differs")
    for name in artifacts:
        item = artifacts[name]
        require(isinstance(item, dict) and set(item) == {"path", "sha256", "identity"}, f"manifest {name} fields differ")
        canonical_absolute(item["path"], f"manifest {name}")
        exact_sha(item["sha256"], f"manifest {name} SHA-256")
        identity = item["identity"]
        require(isinstance(identity, dict) and set(identity) == set(IDENTITY_FIELDS), f"manifest {name} identity fields differ")
        for field in IDENTITY_FIELDS:
            require(isinstance(identity[field], int) and not isinstance(identity[field], bool) and identity[field] >= 0, f"manifest {name} identity is invalid")
    shell_meta = manifest["shell_metadata"]
    require(isinstance(shell_meta, dict) and set(shell_meta) == {"body_bytes", "body_lines", "terminal_byte_hex"}, "shell metadata fields differ")
    require(isinstance(shell_meta["body_bytes"], int) and 0 < shell_meta["body_bytes"] <= MAX_ARTIFACT_SIZE["shell"], "shell body_bytes is invalid")
    require(isinstance(shell_meta["body_lines"], int) and shell_meta["body_lines"] > 0, "shell body_lines is invalid")
    require(isinstance(shell_meta["terminal_byte_hex"], str) and re.fullmatch(r"[0-9a-f]{2}", shell_meta["terminal_byte_hex"]), "shell terminal byte is invalid")
    normalized = exact_sha(manifest["normalized_json_sha256"], "normalized JSON SHA-256")
    inputs = manifest["inputs"]
    require(isinstance(inputs, dict) and set(inputs) == {"lane", "object_format", "base_ref", "base_commit", "base_tree", "main_ref", "main_commit"}, "Phase A inputs fields differ")
    require(inputs["lane"] == LANE and inputs["object_format"] == "sha1" and inputs["base_ref"] == BASE_REF and inputs["main_ref"] == MAIN_REF, "Phase A input pins differ")
    for key, value in (("base_commit", inputs["base_commit"]), ("base_tree", inputs["base_tree"]), ("main_commit", inputs["main_commit"])):
        exact_oid(value, f"inputs.{key}")
    require(inputs["base_commit"] == BASE_COMMIT and inputs["base_tree"] == BASE_TREE and inputs["main_commit"] == MAIN_COMMIT, "Phase A OID pins differ")
    stale = manifest["stale"]
    require(isinstance(stale, dict) and set(stale) == {"paths", "hashes"}, "stale fields differ")
    require(isinstance(stale["paths"], list) and all(isinstance(x, str) and x.startswith("/") and "\x00" not in x for x in stale["paths"]), "stale paths invalid")
    require(isinstance(stale["hashes"], list), "stale hashes invalid")
    for x in stale["hashes"]: exact_sha(x, "stale hash")
    policy = manifest["policy"]
    require(isinstance(policy, dict) and set(policy) == POLICY_KEYS, "Phase A policy fields differ")
    require(policy["base_ref"] == BASE_REF and policy["main_ref"] == MAIN_REF, "Phase A policy refs differ")
    for key in ("base_commit", "base_tree", "main_commit"):
        exact_oid(policy[key], f"policy.{key}")
    require(policy["base_commit"] == BASE_COMMIT and policy["base_tree"] == BASE_TREE and policy["main_commit"] == MAIN_COMMIT, "Phase A policy pins differ")
    for key in ("required_ancestors", "forbidden_ancestors"):
        values = policy[key]
        require(isinstance(values, list) and len(values) == len(set(values)), f"policy.{key} must be duplicate-free")
        for value in values:
            exact_oid(value, f"policy.{key} item")
    require(policy["required_ancestors"] == [BASE_COMMIT], "Phase A required ancestry differs")
    require(policy["forbidden_ancestors"] == list(dict.fromkeys(FORBIDDEN_ANCESTRY)), "Phase A forbidden ancestry differs")
    chain = policy["lane_chain"]
    require(isinstance(chain, list) and len(chain) == len(EXPECTED_LANE_IDS), "Phase A lane chain cardinality differs")
    require([item.get("id") for item in chain] == list(EXPECTED_LANE_IDS), "Phase A lane chain order differs")
    for item in chain:
        require(isinstance(item, dict) and set(item) == {"id", "anchor"}, "Phase A lane chain item fields differ")
        require(item["anchor"] == LANE_ANCHORS[item["id"]], f"Phase A lane anchor differs: {item['id']}")
    approval = manifest["approval"]
    require(isinstance(approval, dict) and set(approval) == {"status", "manifest_sha256", "policy_sha256"}, "approval fields differ")
    require(approval["status"] == "consistency-only" and approval["manifest_sha256"] == "not-bound-in-phase-a", "Phase A approval must remain unclaimed")
    require(approval["policy_sha256"] == APPROVED_POLICY_SHA256 and policy_digest(policy) == APPROVED_POLICY_SHA256, "Phase A policy approval differs")
    return {**inputs, "normalized_json_sha256": normalized, "stale_paths": stale["paths"], "stale_hashes": stale["hashes"], "markdown_sha256": artifacts["markdown"]["sha256"], "json_sha256": artifacts["json"]["sha256"], "shell_sha256": artifacts["shell"]["sha256"], "policy": policy}, dict(shell_meta)


def validate_artifacts(manifest: dict[str, Any]) -> dict[str, Any]:
    expected, shell_meta = validate_manifest(manifest)
    artifacts = manifest["artifacts"]
    paths = {name: canonical_absolute(artifacts[name]["path"], f"manifest {name}") for name in ("markdown", "json", "shell")}
    require(len(set(paths.values())) == 3, "artifact paths must be distinct")
    reads: dict[str, tuple[bytes, os.stat_result]] = {}
    for name in paths:
        reads[name] = read_twice(paths[name], name, MAX_ARTIFACT_SIZE[name])
        raw, st = reads[name]
        require(hashlib.sha256(raw).hexdigest() == artifacts[name]["sha256"], f"{name} hash differs")
        require(_identity(st) == artifacts[name]["identity"], f"{name} identity differs")
    md_raw, json_raw, shell_raw = reads["markdown"][0], reads["json"][0], reads["shell"][0]
    document = parse_json(json_raw, "candidate matrix")
    require(set(document.get("artifact_paths", {})) == {"markdown", "json"}, "matrix artifact_paths must be exact")
    require(document["artifact_paths"]["markdown"] == str(paths["markdown"]) and document["artifact_paths"]["json"] == str(paths["json"]), "matrix artifact paths differ")
    check_candidate_matrix_schema(document, md_raw, expected)
    actual_meta = {"body_bytes": len(shell_raw), "body_lines": shell_raw.count(b"\n"), "terminal_byte_hex": shell_raw[-1:].hex()}
    _canonical_execution_contract(document, paths["json"], shell_raw, expected["shell_sha256"], actual_meta)
    require(document["execution_driver"]["shell"].encode("utf-8") == shell_raw, "JSON shell differs")
    require(document["execution_driver"]["shell_sha256"] == expected["shell_sha256"], "JSON shell hash differs")
    require(shell_raw.endswith(b"\n") and actual_meta == shell_meta, "shell metadata differs")
    require(PARITY.normalized_json_sha256(json_raw, expected["normalized_json_sha256"]) == expected["normalized_json_sha256"], "normalized JSON hash differs")
    check_stale_references(md_raw, json_raw, shell_raw, expected["stale_paths"], expected["stale_hashes"])
    _check_markdown(md_raw, shell_raw, expected["shell_sha256"], expected["normalized_json_sha256"], shell_meta)
    return {"phase": PHASE, "paths": {name: str(path) for name, path in paths.items()}, "hashes": {key: expected[key] for key in ("markdown_sha256", "json_sha256", "shell_sha256", "normalized_json_sha256")}, "identities": {name: _identity(reads[name][1]) for name in reads}, "inputs": {key: expected[key] for key in ("lane", "object_format", "base_ref", "base_commit", "base_tree", "main_ref", "main_commit")}, "shell_metadata": shell_meta, "policy": expected["policy"]}


def _check_private_parent(parent: Path) -> None:
    require(parent.is_absolute() and str(parent) == os.path.realpath(str(parent)), "preflight root parent must be canonical")
    st = os.lstat(parent)
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "preflight root parent must be a directory")
    mode = stat.S_IMODE(st.st_mode)
    require(not mode & 0o022 or (mode & 0o1000 and str(parent) == "/private/tmp"), "preflight root parent is not private")


def create_owner_marked_root(requested: str | None) -> Path:
    """Allocate exactly one fresh private root after all semantic checks."""
    if requested is None:
        parent = HERE / "runs-v3"
        if not parent.exists():
            os.mkdir(parent, 0o700)
        _check_private_parent(parent)
        leaf = None
        for _ in range(64):
            candidate = parent / ("candidate-4-phase-a-" + secrets.token_hex(10))
            try:
                os.mkdir(candidate, 0o700)
                leaf = candidate
                break
            except FileExistsError:
                continue
        require(leaf is not None, "could not allocate a unique preflight root")
    else:
        leaf = canonical_absolute(requested, "preflight root", must_exist=False)
        require(str(leaf).startswith("/private/tmp/"), "preflight root must be under /private/tmp")
        _check_private_parent(leaf.parent)
        try:
            os.mkdir(leaf, 0o700)
        except FileExistsError:
            reject("preflight root already exists")
        except OSError as exc:
            reject(f"cannot create preflight root: {exc}")
    marker = leaf / ".owner"
    payload = {"kind": "task409-execution-preflight-owner", "schema": SCHEMA, "phase": PHASE, "uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid(), "created_unix": int(time.time()), "read_only": True, "executor": "not implemented"}
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = -1
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        offset = 0
        while offset < len(raw): offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    except OSError as exc:
        try: os.unlink(marker)
        except OSError: pass
        try: os.rmdir(leaf)
        except OSError: pass
        reject(f"cannot create owner marker: {exc}")
    finally:
        if fd >= 0: os.close(fd)
    st = os.lstat(marker)
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1, "owner marker identity is invalid")
    return leaf


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw, _ = read_twice(path, "input manifest", 4 * 1024 * 1024)
    return parse_json(raw, "input manifest"), hashlib.sha256(raw).hexdigest()


def _identity_from_wrapper(value: str, label: str) -> dict[str, int]:
    fields = IDENTITY_FIELDS
    parts = value.split(",")
    require(len(parts) == len(fields), f"{label} identity field count differs")
    parsed: dict[str, int] = {}
    for field, item in zip(fields, parts):
        require(item.isdigit(), f"{label}.{field} identity is not decimal")
        parsed[field] = int(item, 10)
    return parsed


def _manifest_from_wrapper(values: Sequence[str]) -> dict[str, Any]:
    """Build the closed manifest in memory; allocation happens only later.

    The shell wrapper supplies only artifact facts.  Policy, stale declarations,
    and approval fields come from this module's canonical constants so the
    wrapper cannot create a second policy source that drifts from validation.
    """
    require(len(values) == 20, "wrapper fact count differs")
    (
        markdown,
        json_path,
        shell,
        markdown_sha,
        json_sha,
        shell_sha,
        normalized_sha,
        markdown_identity,
        json_identity,
        shell_identity,
        body_bytes,
        body_lines,
        terminal,
        lane,
        object_format,
        base_ref,
        base_commit,
        base_tree,
        main_ref,
        main_commit,
    ) = values

    def artifact(path: str, sha: str, identity: str) -> dict[str, Any]:
        return {"path": path, "sha256": sha, "identity": _identity_from_wrapper(identity, path)}

    try:
        body_bytes_int = int(body_bytes, 10)
        body_lines_int = int(body_lines, 10)
    except ValueError:
        reject("wrapper shell metadata must be decimal integers")
    return {
        "schema": SCHEMA,
        "phase": PHASE,
        "artifacts": {
            "markdown": artifact(markdown, markdown_sha, markdown_identity),
            "json": artifact(json_path, json_sha, json_identity),
            "shell": artifact(shell, shell_sha, shell_identity),
        },
        "shell_metadata": {
            "body_bytes": body_bytes_int,
            "body_lines": body_lines_int,
            "terminal_byte_hex": terminal,
        },
        "normalized_json_sha256": normalized_sha,
        "inputs": {
            "lane": lane,
            "object_format": object_format,
            "base_ref": base_ref,
            "base_commit": base_commit,
            "base_tree": base_tree,
            "main_ref": main_ref,
            "main_commit": main_commit,
        },
        "stale": {
            "paths": list(MANDATORY_STALE_PATHS),
            "hashes": list(MANDATORY_STALE_HASHES),
        },
        "policy": _expected_policy(),
        "approval": {
            "status": "consistency-only",
            "manifest_sha256": "not-bound-in-phase-a",
            "policy_sha256": APPROVED_POLICY_SHA256,
        },
    }


def _write_manifest_after_validation(path: Path, manifest: Mapping[str, Any]) -> tuple[Path, str]:
    """Materialize the validated manifest only after the single root allocation."""
    require(path.is_absolute() and str(path) == os.path.realpath(str(path)), "manifest output must be canonical absolute")
    parent = path.parent
    require(parent.is_dir() and str(parent) == os.path.realpath(str(parent)), "manifest output parent must already exist and be canonical")
    require(not os.path.lexists(path), "manifest output already exists")
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = -1
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    except OSError as exc:
        reject(f"cannot write validated manifest: {exc}")
    finally:
        if fd >= 0:
            os.close(fd)
    return path, hashlib.sha256(raw).hexdigest()


def _raw_argv_scan(argv: Sequence[str]) -> None:
    require(all(isinstance(x, str) for x in argv), "arguments must be text")
    require("--execute" not in argv, "Phase A --execute is forbidden before allocation")
    require("--ref" not in argv and not any(item.startswith("--ref=") for item in argv), "Phase A does not accept refs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Task #409 Phase A consistency-only pre-replay gate")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--manifest")
    source.add_argument("--wrapper-facts", nargs=20, metavar="FACT")
    parser.add_argument("--manifest-output")
    parser.add_argument("--preflight-root")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        actual = list(sys.argv[1:] if argv is None else argv)
        _raw_argv_scan(actual)
        args = build_parser().parse_args(actual)
        if args.wrapper_facts is not None:
            manifest = _manifest_from_wrapper(args.wrapper_facts)
            # Validate all artifact bytes and policy before allocating any root.
            result = validate_artifacts(manifest)
            requested_output = Path(args.manifest_output) if args.manifest_output else None
            root = create_owner_marked_root(args.preflight_root)
            output_path = requested_output or (root / "input-manifest.json")
            manifest_path, manifest_sha = _write_manifest_after_validation(output_path, manifest)
        else:
            manifest_path = canonical_absolute(args.manifest, "manifest")
            manifest, manifest_sha = load_manifest(manifest_path)
            result = validate_artifacts(manifest)
            approval_digest = phase_a_approval_digest(manifest)
            root = create_owner_marked_root(args.preflight_root)
        approval_digest = phase_a_approval_digest(manifest)
        output = {"phase": PHASE, "preflight_root": str(root), "owner_marker": str(root / ".owner"), "manifest": str(manifest_path), "manifest_sha256": manifest_sha, "phase_a_approval_digest": approval_digest, "policy_sha256": policy_digest(result["policy"]), **result, "candidate_identity": "not-claimed", "execution": "not-run", "mutation": "not-run", "network": "not-used", "approval": "consistency-only"}
        print("PASS: Phase A pre-replay artifact/matrix consistency checks passed")
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except Reject as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, AssertionError) as exc:
        print(f"REJECT: unexpected structural Phase A failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
