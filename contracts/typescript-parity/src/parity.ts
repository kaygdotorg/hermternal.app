import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { dlopen, FFIType, ptr, toArrayBuffer, type Pointer } from "bun:ffi";
import { resolve, isAbsolute, join } from "node:path";

export const HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e";
export const CONTRACT = "dashboard-v0.0.1";
export const REGISTRY_SCHEMA = "hermternal.fixture-index.v1";

// These caps keep fixture validation bounded even when a checked-in path is replaced
// between the initial stat and the read. They are intentionally above every reviewed
// artifact while remaining small enough for synchronous CI and offline CLI use.
export const MAX_JSON_BYTES = 256 * 1024;
export const MAX_JSON_DEPTH = 16;
const MAX_JSON_NODES = 10_000;
const MAX_JSON_ARRAYS = 512;
const MAX_JSON_ARRAY_ITEMS = 512;
const MAX_JSON_OBJECTS = 512;
const MAX_JSON_OBJECT_KEYS = 128;
const MAX_JSON_KEY_LENGTH = 128;
const MAX_JSON_STRING_VALUES = 4_096;
const MAX_JSON_STRING_LENGTH = 1_024;
const MAX_COMPATIBILITY_JSON_BYTES = 128 * 1024;
const MAX_COMPATIBILITY_JSON_DEPTH = 32;
const MAX_COMPATIBILITY_JSON_NODES = 4_096;
const MAX_COMPATIBILITY_STRING_BYTES = 4_096;
const MAX_OUTPUT_STRING_LENGTH = 256;
const MAX_OUTPUT_CASES = 64;
const MAX_OUTPUT_COVERAGE_IDS = 64;
export const MAX_REPORT_BYTES = 8 * 1024;
const MAX_REGISTRY_FILES = 512;
const MAX_INVENTORY_DEPTH = 32;
const MAX_INVENTORY_DIRECTORIES = 512;
const MAX_TOTAL_ARTIFACT_BYTES = 8 * 1024 * 1024;
const MAX_READ_DURATION_MS = 1_000;
export const MAX_ERROR_CODE_LENGTH = 64;
export const MAX_ERROR_MESSAGE_LENGTH = 240;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const SAFE_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SAFE_PATH_PATTERN = /^[A-Za-z0-9._/-]+$/;
const DIRECTORY_READ_FLAGS =
  fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW;
const FILE_READ_FLAGS =
  fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW;
const DUPLICATED_DESCRIPTOR_FLAGS = fsConstants.O_RDONLY | fsConstants.O_NONBLOCK;
const FIXTURE_METADATA_FILES = new Set(["README.md", "index.json", "schema.json"]);
const FIXTURE_VALIDATOR_DIRECTORY = "validator";
const NON_SUCCESS_COVERAGE_STATUSES = [
  "pending",
  "empty",
  "failure",
  "cancelled",
  "unknown",
] as const;
const STATE_IDS = ["pending", "empty", "success", "failure", "cancelled", "unknown"] as const;
const EXPECTED_STATE_SEMANTICS: Readonly<Record<string, readonly string[]>> = {
  pending: ["collection_in_progress", "blocked", "no_success_claim", "wait_or_cancel"],
  empty: ["no_observations", "blocked", "no_success_claim", "collect_required_evidence"],
  success: ["synthetic_fixture_validated", "blocked_live_compatibility", "artifact_only_no_live_claim", "not_applicable"],
  failure: ["required_case_failed", "blocked", "retain_failure_evidence", "idempotent_collection_only"],
  cancelled: ["cancelled_before_completion", "blocked", "no_outward_change", "resume_after_source_state_reread"],
  unknown: ["result_unavailable", "blocked", "no_duplicate_prompt_session_ticket_or_pty_input", "reread_source_state_before_retry"],
};

export const PLATFORMS = ["web", "ios", "ipados", "macos"] as const;
export type Platform = (typeof PLATFORMS)[number];
export type Family =
  | "auth"
  | "connection"
  | "session"
  | "chat"
  | "image"
  | "pty"
  | "deep-link"
  | "compatibility";

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonRecord = { [key: string]: JsonValue };

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function sanitizeErrorText(value: string): string {
  // JSON escapes lone surrogates into six-byte sequences. Normalize them and all
  // single-line control separators before applying the serialized UTF-8 budget.
  return value
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "?")
    .replace(/[\ud800-\udfff]/g, "?");
}

export function boundedErrorText(value: string, limit: number, fallback: string): string {
  const sanitized = sanitizeErrorText(value);
  const safeValue = sanitized.length > 0 ? sanitized : sanitizeErrorText(fallback);
  if (utf8Bytes(JSON.stringify(safeValue)) - 2 <= limit) return safeValue;

  const suffix = "…";
  let result = "";
  for (const character of safeValue) {
    const candidate = `${result}${character}${suffix}`;
    if (utf8Bytes(JSON.stringify(candidate)) - 2 > limit) break;
    result += character;
  }
  return result.length > 0 ? `${result}${suffix}` : "?";
}

export class ContractInputError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(boundedErrorText(message, MAX_ERROR_MESSAGE_LENGTH, "parity check failed"));
    this.name = "ContractInputError";
    this.code = boundedErrorText(code, MAX_ERROR_CODE_LENGTH, "contract_error");
  }
}

interface RegistryFile {
  readonly path: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

type FixtureRootStatus = "ready" | "pending";
type CoverageStatus = "ready" | (typeof NON_SUCCESS_COVERAGE_STATUSES)[number];

interface FixtureRoot {
  readonly id: string;
  readonly path: string;
  readonly status: FixtureRootStatus;
  readonly contract: string;
  readonly hermesSourceSha: string;
  readonly syntheticOnly: true;
  readonly liveClaim: false;
  readonly platforms: readonly Platform[];
  readonly states: readonly string[];
  readonly coverageIds: readonly string[];
  readonly validator: string | null;
  readonly files: readonly RegistryFile[];
}

interface CoverageRow {
  readonly id: string;
  readonly status: CoverageStatus;
  readonly fixtureIds: readonly string[];
  readonly platforms: readonly Platform[];
  readonly requiredStates: readonly string[];
  readonly notes: string;
}

interface RegistryParity {
  readonly status: string;
  readonly fixtureSource: string;
  readonly platforms: readonly Platform[];
  readonly ptyPolicy: string;
  readonly missingResultPolicy: string;
  readonly resultEquivalence: string;
  readonly liveClaim: false;
}

export interface FixtureRegistry {
  readonly evidenceStatus: "partial" | "complete";
  readonly fixtureRoots: readonly FixtureRoot[];
  readonly coverage: readonly CoverageRow[];
  readonly parity: RegistryParity;
  readonly states: readonly JsonRecord[];
  readonly redaction: JsonRecord;
  readonly benchmark: JsonRecord;
}

export interface FixtureCase {
  readonly id: string;
  readonly expected: JsonRecord;
  readonly raw: JsonRecord;
}

export interface CompatibilityRecord {
  readonly compatible: false;
  readonly liveRun: false;
  readonly deploymentAttestation: string;
  readonly behavioralProbe: string;
  readonly proxyProof: string;
  readonly parityEvidence: string;
  readonly benchmarkEvidence: string;
}

export interface ProjectedOutcome {
  readonly family: Family;
  readonly caseId: string;
  readonly platform: Platform;
  readonly decision: string;
  readonly semantic: JsonRecord;
}

export interface ParityCaseResult {
  readonly family: Family;
  readonly coverageId: string;
  readonly caseId: string;
  readonly status: "proven" | "blocked";
  readonly platforms: readonly Platform[];
  readonly webDecision?: string;
  readonly appleDecision?: string;
}

export interface ParityReport {
  readonly ok: true;
  readonly contract: string;
  readonly hermesSourceSha: string;
  readonly syntheticOnly: true;
  readonly liveClaim: false;
  readonly networkCalls: 0;
  readonly readyCaseCount: number;
  readonly blockedCoverageIds: readonly string[];
  readonly cases: readonly ParityCaseResult[];
  readonly compatibility: CompatibilityRecord;
}

const JSON_ARTIFACTS: Readonly<Record<string, string>> = {
  "deployment-security-browser-auth": "deployment-security/browser-auth/cases.json",
  "connection-restoration": "connection-restoration/cases.json",
  "session-persistence": "session-persistence/cases.json",
  "image-attachment-lifecycle": "image-attachment-lifecycle/cases.json",
  "pty-contract": "pty-contract/pty-contract-fixtures.json",
  "deep-link-grammar": "deep-link-grammar/cases.json",
  "compatibility-attestation": "compatibility-attestation/cases.json",
  "source-audit-compatibility-gate":
    "source-audit/compatibility-gate/compatibility_record.json",
};

interface ArtifactSchema {
  readonly topKeys: readonly string[];
  readonly caseKeys?: readonly string[];
  readonly expectedKeys?: readonly string[];
  readonly expectedKeysByKind?: Readonly<Record<string, readonly string[]>>;
  readonly schemaField?: string;
  readonly schemaValue?: string;
  readonly sourceField?: string;
  readonly contractIsObject?: boolean;
}

const ARTIFACT_SCHEMAS: Readonly<Record<string, ArtifactSchema>> = {
  "deployment-security-browser-auth": {
    topKeys: ["schema", "operation", "contract", "pinned_source_sha", "synthetic_only", "network_access", "redaction", "cases"],
    caseKeys: ["expected", "id", "input", "kind"],
    expectedKeys: ["cookie_cleanup", "diagnostic", "provider_exchange", "providers", "reason", "redirect", "session_cookie", "state", "status"],
    schemaField: "schema",
    schemaValue: "hermternal.deployment-security.browser-auth.v1",
    sourceField: "pinned_source_sha",
  },
  "connection-restoration": {
    topKeys: ["schema", "operation", "contract", "hermes_source_sha", "synthetic_only", "surface", "states", "invariants", "cases", "redaction"],
    caseKeys: ["events", "expected", "id", "initial_context", "initial_state", "notes"],
    expectedKeys: ["active_profile", "compatibility_gate", "decision", "draft", "effects", "final_state", "prompt_auto_resubmitted", "prompt_retry", "restore_barrier", "selected_profile", "selected_session", "ticket_generations", "trace", "transport_closed"],
    schemaField: "schema",
    schemaValue: "hermternal.connection-restoration.v1",
    sourceField: "hermes_source_sha",
  },
  "session-persistence": {
    topKeys: ["schema", "operation", "contract", "hermes_source_sha", "synthetic_only", "surface", "source_observations", "states", "invariants", "cases", "redaction"],
    caseKeys: ["events", "expected", "id", "initial_context", "initial_state", "notes"],
    expectedKeys: ["automatic_prompt_retry_attempted", "decision", "draft", "durable_row", "effects", "error_kind", "final_state", "history", "persist_attempts", "persistence", "prompt_in_flight", "prompt_retry", "prompt_submissions", "restore_barrier", "resume_attempts", "selected_session", "server_presence", "session_creations", "stored_session", "trace", "transport_closed"],
    schemaField: "schema",
    schemaValue: "hermternal.session-persistence.v1",
    sourceField: "hermes_source_sha",
  },
  "image-attachment-lifecycle": {
    topKeys: ["schema", "contract", "policy_reference", "hermes_source_sha", "fixture_policy", "synthetic_only", "limits", "redaction", "c13_consistency", "cases"],
    caseKeys: ["expected", "id", "input", "notes", "preprocess", "progress", "scenario", "timeline"],
    expectedKeys: ["attachment_state", "decision", "diagnostic", "draft", "duplicate_uploads", "metadata_retained", "retry", "transcript_reference", "upload_attempts", "upload_started"],
    schemaField: "schema",
    schemaValue: "hermternal.fixture.image-attachment-lifecycle.v1",
    sourceField: "hermes_source_sha",
  },
  "pty-contract": {
    topKeys: ["schema_version", "contract", "constants", "evidence", "source_audit", "cases"],
    contractIsObject: true,
    caseKeys: ["expected", "id", "input", "kind"],
    expectedKeysByKind: {
      "raw-bytes": ["render_hex", "utf8_decode", "reencode", "pty_bytes_logged"],
      "raw-bytes-multiframe": ["frame_boundaries_preserved", "incomplete_fragment_ref", "invalid_fragment_ref", "joined_hex", "pty_bytes_logged", "reencode", "rendered_frame_hex", "rendered_frame_refs", "split_codepoint_frames", "utf8_decode"],
      "resize": ["control_is_single_binary_message", "prefix_hex", "suffix_hex", "written_to_pty"],
      "resize-rejection": ["error_mode", "pty_write", "rejected_before_binary_send"],
      "legacy-lifecycle": ["close_result", "disconnect_result", "event_sequence", "final_state", "mode", "process_ref", "reattach", "registry_path", "spawn_count", "trigger"],
      "attach-lifecycle": ["close_result", "disconnect_result", "event_sequence", "handle_ref", "identity_preserved", "mode", "process_ref", "process_result", "reattach", "registry_ref", "registry_result", "registry_reuse_count", "retention_seconds", "session_ref", "socket_sequence", "spawn_count", "state_sequence"],
      "replacement": ["active_socket_ref", "close_before_assign", "handle_ref", "identity_preserved", "process_ref", "replacement_active", "session_ref", "stale_cleanup_detaches_replacement", "stale_close_code"],
      "process-exit": ["close_code", "final_state", "process_ref", "retry"],
      "detach-window": ["after_window", "at_boundary", "identity_preserved_during_window", "retention_seconds", "within_window"],
      "registry-cap": ["max_entries", "overflow_behavior", "size_never_exceeds_cap"],
      "replay-ring": ["capacity_bytes", "frame_type", "older_output", "tail_length", "tail_ref"],
      "replay-action-exclusion": ["prompt_output_may_be_retained", "replayed_action_kinds", "retained_output_refs", "snapshot_mode", "tool_output_may_be_retained"],
      "replay-live-race": ["allowed_orderings", "render_each_frame_as_received", "replay_boundary_claim", "separator_hex"],
      "no-byte-logging": ["action_payloads_logged", "allowed_metadata", "metadata_only", "payload_fields_are_null", "raw_bytes_logged", "retained_action_refs"],
    },
  },
  "deep-link-grammar": {
    topKeys: ["schema", "contract", "synthetic", "configured_origin", "id_policy", "reason_order", "redaction", "cases"],
    caseKeys: ["expected", "id", "link", "synthetic"],
    expectedKeys: ["diagnostic", "kind", "message_id", "reasons", "session_id", "valid"],
    schemaField: "schema",
    schemaValue: "hermternal.deep-link-grammar/v1",
  },
  "compatibility-attestation": {
    topKeys: ["schema", "operation", "contract", "pinned_source_sha", "cases", "redaction"],
    caseKeys: ["description", "expected", "id", "input"],
    expectedKeys: ["attestation_result", "runtime_gate"],
    schemaField: "schema",
    schemaValue: "hermternal.revision-attestation-fixtures.v1",
    sourceField: "pinned_source_sha",
  },
};

const REGISTRY_TOP_KEYS = ["schema", "contract", "hermes_source_sha", "synthetic_only", "live_claim", "evidence_status", "fixture_roots", "coverage", "parity", "states", "redaction", "benchmark"] as const;
const FIXTURE_ROOT_KEYS = ["id", "path", "status", "contract", "hermes_source_sha", "synthetic_only", "live_claim", "platforms", "states", "coverage_ids", "validator", "files"] as const;
const REGISTRY_FILE_KEYS = ["path", "sha256", "size_bytes"] as const;
const COVERAGE_KEYS = ["id", "status", "fixture_ids", "platforms", "required_states", "notes"] as const;
const PARITY_KEYS = ["status", "fixture_source", "platforms", "pty_policy", "missing_result_policy", "result_equivalence", "live_claim"] as const;
const STATE_KEYS = ["id", "evidence_state", "gate_decision", "safe_state", "retry_policy"] as const;
const REDACTION_KEYS = ["synthetic_only", "contains_credentials", "contains_cookies", "contains_bearer_values", "contains_ticket_values", "contains_raw_pty_bytes", "contains_transcripts", "contains_live_hosts", "contains_user_data", "failure_output"] as const;
const BENCHMARK_KEYS = ["path", "threshold", "evidence_mode", "build_mode"] as const;
const COMPATIBILITY_RECORD_KEYS = ["schema", "operation", "contract", "source", "merged_dev", "integration_dev", "artifacts", "observations", "status", "redaction", "blockers"] as const;
const COMPATIBILITY_SOURCE_KEYS = ["repository", "sha"] as const;
const COMPATIBILITY_MERGED_KEYS = ["ref", "head", "tree", "merged_prs"] as const;
const COMPATIBILITY_MERGED_PR_KEYS = ["number", "merge_commit"] as const;
const COMPATIBILITY_INTEGRATION_KEYS = ["ref", "head", "tree"] as const;
const COMPATIBILITY_ARTIFACTS_KEYS = ["algorithm", "files", "set_sha256"] as const;
const COMPATIBILITY_ARTIFACT_KEYS = ["path", "sha256", "size_bytes"] as const;
const COMPATIBILITY_OBSERVATIONS_KEYS = ["artifact_size_bytes", "artifact_set_sha256", "validator_duration_ms", "repetitions"] as const;
const COMPATIBILITY_BENCHMARK_KEYS = ["command", "commit", "environment", "artifact_set_sha256", "artifact_size_bytes", "samples_ms", "distribution", "threshold"] as const;
const COMPATIBILITY_ENVIRONMENT_KEYS = ["platform", "python"] as const;
const COMPATIBILITY_DISTRIBUTION_KEYS = ["min", "p50", "p95", "p99", "max", "mean"] as const;
const COMPATIBILITY_STATUS_KEYS = ["compatible", "live_run", "deployment_attestation", "behavioral_probe", "proxy_proof", "parity_evidence", "benchmark_evidence"] as const;
const COMPATIBILITY_REDACTION_KEYS = ["synthetic_only", "contains_credentials", "contains_hosts", "contains_raw_tickets", "contains_prompts", "contains_transcripts", "contains_pty_bytes"] as const;
const EXPECTED_COMPATIBILITY_STATUS: Readonly<Record<string, JsonValue>> = {
  compatible: false,
  live_run: false,
  deployment_attestation: "absent",
  behavioral_probe: "not_run",
  proxy_proof: "not_run",
  parity_evidence: "not_recorded",
  benchmark_evidence: "not_recorded",
};
const EXPECTED_COMPATIBILITY_BLOCKERS = [
  "deployment_attestation_absent",
  "behavioral_probe_not_run",
  "proxy_proof_not_run",
  "parity_and_accessibility_evidence_not_recorded",
  "benchmark_evidence_not_recorded",
  "fixture_only_scope_cannot_close_live_compatibility_gate",
] as const;
const EXPECTED_COMPATIBILITY_MERGED_HEAD = "8465bd4cacc87fe62ff952c38d7f3c2b5927bfbd";
const EXPECTED_COMPATIBILITY_MERGED_TREE = "aede9b87932f5cc28462120ef28be52a9a4aba7f";
const EXPECTED_COMPATIBILITY_INTEGRATION_HEAD = "0671593b42235d4fbad2f7f3e04255c9f51b257d";
const EXPECTED_COMPATIBILITY_INTEGRATION_TREE = "16fac2e9d6aa64dd2631b9f4b445146c115acfb0";
const EXPECTED_COMPATIBILITY_MERGED_PRS = [
  [221, "203dfca63eb073e5d4ddc27921447b5d0ab64a51"],
  [216, "8465bd4cacc87fe62ff952c38d7f3c2b5927bfbd"],
  [218, "c3c29992a85737dc0487772947780ed3239705fd"],
  [219, "41211da8e27c4dceeeac5782208d8140034a19de"],
  [220, "f32d4782b041a12347acba2d7d36172594dec6f7"],
] as const;
const EXPECTED_COMPATIBILITY_ARTIFACTS = [
  { path: "contracts/fixtures/source-audit/model-options/absent.json", sha256: "c850fa9d5276ab6f0a3929c9f97bc8b997df9c78ddaf404dd05006c1b9553637", sizeBytes: 769 },
  { path: "contracts/fixtures/source-audit/model-options/empty.json", sha256: "12b8e155cba83bb50efbef4dda698b844a451454d5580465f4c1a3b7059ca74d", sizeBytes: 815 },
  { path: "contracts/fixtures/source-audit/model-options/malformed.json", sha256: "e75fe09973cd14cd618601d0d3b180ba8a7dac7f63874df2ccfd1956b3a88054", sizeBytes: 987 },
  { path: "contracts/fixtures/source-audit/model-options/present.json", sha256: "c9850521d8d0deb1a571d3284d7f1f994550871d10ad5b6a1823b9ab2edb4d3a", sizeBytes: 1275 },
  { path: "contracts/fixtures/source-audit/model-options/test_model_options.py", sha256: "35cbd50542f7cafb3322ab240a4320c87b7523079aee14f484f4789e6c696a9d", sizeBytes: 29971 },
  { path: "contracts/fixtures/source-audit/model-options/unknown-operation.json", sha256: "84195ae496a31c5e9d484e2634832c70a117138fa133d6d6f3c1427ce08ff23b", sizeBytes: 835 },
  { path: "contracts/fixtures/source-audit/native-bearer/README.md", sha256: "0dd3d1b68658107bd3b7ec5cee236ef196e4dc34f82edd9426eb1a0cb1787308", sizeBytes: 5677 },
  { path: "contracts/fixtures/source-audit/native-bearer/cases.json", sha256: "56d5c98a29672d8b383c1f0200abd389ea945d54b722313db088de7360274439", sizeBytes: 22650 },
  { path: "contracts/fixtures/source-audit/native-bearer/source_audit.json", sha256: "bc12353629eceaf157ba6320cafcf8e8393d001c41390f14449b14daf682ff70", sizeBytes: 17900 },
  { path: "contracts/fixtures/source-audit/native-bearer/test_native_bearer.py", sha256: "2ae703faf534e3460ce31e05d1b5e789cf6b51777120cf6a241b3dbb2f71620b", sizeBytes: 35389 },
  { path: "contracts/fixtures/source-audit/oauth-browser/README.md", sha256: "274dc2a26553b937c77e8e5d0fb51cc1aa85bb1e7b2d6e44c4cbdc3701e8f45e", sizeBytes: 7378 },
  { path: "contracts/fixtures/source-audit/oauth-browser/cases.json", sha256: "a0961278dc2f34562b16ab7d30776972d12d201de74edd7e08463cdbd5f50178", sizeBytes: 7512 },
  { path: "contracts/fixtures/source-audit/oauth-browser/source_audit.json", sha256: "7b7758611a9aeb520353b473e6af00136a229d623ea77c806f49f2c2c5b3e131", sizeBytes: 6881 },
  { path: "contracts/fixtures/source-audit/oauth-browser/source_excerpts/cookies.py.txt", sha256: "4061f5e075fee015151a14ab75c7b77661400bb2ec0fa402559c0d49cae36f3e", sizeBytes: 418 },
  { path: "contracts/fixtures/source-audit/oauth-browser/source_excerpts/nous_provider.py.txt", sha256: "53f633d5e405459ad0d042470e06af545fad6d1d02b86f23a473ece283ce8c87", sizeBytes: 1898 },
  { path: "contracts/fixtures/source-audit/oauth-browser/source_excerpts/routes_auth.py.txt", sha256: "7a748fc29acee3d055049f0b1a12bba9e7d8aa13bc4852827888a0ebaaa507b4", sizeBytes: 3456 },
  { path: "contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py", sha256: "0445ff899949e29a760c1dff2471100914f0fa608e25f588804fd2bd101a8396", sizeBytes: 61959 },
  { path: "contracts/fixtures/source-audit/planning-reconciliation/README.md", sha256: "39cd6aae225fe883a87558d2a52ba7800424ed269aa553f850a3071d25beb89d", sizeBytes: 4870 },
  { path: "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json", sha256: "0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077", sizeBytes: 20045 },
  { path: "contracts/fixtures/source-audit/planning-reconciliation/test_validate.py", sha256: "4e912278671dc7809216fc26e280e191cf7279180186d45390b41b892b24407f", sizeBytes: 23038 },
  { path: "contracts/fixtures/source-audit/planning-reconciliation/validate.py", sha256: "09f5b87f7ebb49de73a706508ab2ec26ac4b8bd734c6532a16d0b7ddd6c26587", sizeBytes: 51103 },
  { path: "contracts/fixtures/source-audit/pty-attach/README.md", sha256: "3f1172482e5b0373ebbfbc9b4b5a85104a324fa801b9fe6f9da3a5b2a25e586b", sizeBytes: 7940 },
  { path: "contracts/fixtures/source-audit/pty-attach/pty-attach-fixtures.json", sha256: "0e32d184fa2ef693a126ecfc284eb6566fd2b0e55f662003c3f36f2209456d7a", sizeBytes: 16276 },
  { path: "contracts/fixtures/source-audit/pty-attach/source-evidence.json", sha256: "90291fcff446327a2c5f13758d3d6d78efe076ebbc78fb5fc72f1c5d7bd97fc3", sizeBytes: 10812 },
  { path: "contracts/fixtures/source-audit/pty-attach/validate.py", sha256: "14c312b23037e7a23495ccce169ad4c26fd3b2917b7229dd508c5867cbbba694", sizeBytes: 115214 },
  { path: "contracts/fixtures/source-audit/pty-attach/validation-baseline.json", sha256: "496f989e8a0399ff1eef0f98c66186014e40668633d99786619b1f5d24149d6d", sizeBytes: 460 },
  { path: "contracts/hermes-dashboard/model-options/README.md", sha256: "593cd24515b8a6c2f12a9fadd28964c88ba74ce0c882c6f0116cb9c532fb5cbd", sizeBytes: 4785 },
  { path: "contracts/hermes-dashboard/model-options/source-audit.json", sha256: "3f0f4c65360fbf0dd9e08529e37b1649386a09a8fa7ace00d86ce74d2e310869", sizeBytes: 2561 },
] as const;
const EXPECTED_COMPATIBILITY_BENCHMARK_COMMANDS: Readonly<Record<string, string>> = {
  normal: "python3 contracts/fixtures/source-audit/compatibility-gate/validate.py --repo-root . --record contracts/fixtures/source-audit/compatibility-gate/compatibility_record.json",
  optimized: "python3 -O contracts/fixtures/source-audit/compatibility-gate/validate.py --repo-root . --record contracts/fixtures/source-audit/compatibility-gate/compatibility_record.json",
};


interface Representative {
  readonly family: Family;
  readonly rootId: string;
  readonly coverageId: string;
  readonly caseIds: readonly string[];
}

const REPRESENTATIVES: readonly Representative[] = [
  {
    family: "auth",
    rootId: "deployment-security-browser-auth",
    coverageId: "browser-cookie-auth",
    caseIds: ["login-success", "callback-csrf-mismatch"],
  },
  {
    family: "connection",
    rootId: "connection-restoration",
    coverageId: "connection-restoration",
    caseIds: ["initial-connect-ready", "prompt-transport-loss-uncertain"],
  },
  {
    family: "session",
    rootId: "session-persistence",
    coverageId: "chat-stream-and-completion",
    caseIds: ["first-prompt-persists-session", "transport-loss-enters-delivery-uncertain"],
  },
  {
    family: "chat",
    rootId: "session-persistence",
    coverageId: "chat-stream-and-completion",
    caseIds: ["transport-loss-enters-delivery-uncertain", "automatic-prompt-retry-fails-closed"],
  },
  {
    family: "image",
    rootId: "image-attachment-lifecycle",
    coverageId: "image-attachment-lifecycle",
    caseIds: ["empty-selection", "malformed-base64", "success-transcript-reference"],
  },
  {
    family: "pty",
    rootId: "pty-contract",
    coverageId: "web-pty",
    caseIds: ["raw-bytes-preserve", "no-byte-logging"],
  },
  {
    family: "deep-link",
    rootId: "deep-link-grammar",
    coverageId: "private-deep-link",
    caseIds: ["valid-web-session", "wrong-origin"],
  },
  {
    family: "compatibility",
    rootId: "compatibility-attestation",
    coverageId: "deployment-attestation",
    caseIds: ["valid_attestation_with_probe", "missing_attestation"],
  },
];

function fail(code: string, message: string): never {
  throw new ContractInputError(code, message);
}

function isRecord(value: JsonValue | undefined): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: JsonValue | undefined, label: string): JsonRecord {
  if (!isRecord(value)) {
    fail("malformed_input", `${label} must be an object`);
  }
  return value;
}

function exactRecord(value: JsonValue | undefined, label: string, expectedKeys: readonly string[]): JsonRecord {
  const entry = record(value, label);
  const expected = new Set(expectedKeys);
  const unknown = Object.keys(entry).find((key) => !expected.has(key));
  if (unknown) {
    fail("unknown_field", `${label} contains unknown field ${unknown}`);
  }
  const missing = expectedKeys.find((key) => !Object.prototype.hasOwnProperty.call(entry, key));
  if (missing) {
    fail("missing_field", `${label} is missing required field ${missing}`);
  }
  return entry;
}

function array(value: JsonValue | undefined, label: string): JsonValue[] {
  if (!Array.isArray(value)) {
    fail("malformed_input", `${label} must be an array`);
  }
  return value;
}

function string(value: JsonValue | undefined, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    fail("malformed_input", `${label} must be a non-empty string`);
  }
  if (value.length > MAX_JSON_STRING_LENGTH) {
    fail("json_string_limit", `${label} exceeds the bounded string limit`);
  }
  return value;
}

function boundedOutputString(value: JsonValue | undefined, label: string): string {
  const result = string(value, label);
  if (result.length > MAX_OUTPUT_STRING_LENGTH) {
    fail("output_limit", `${label} exceeds the bounded output limit`);
  }
  return result;
}

function boolean(value: JsonValue | undefined, label: string): boolean {
  if (typeof value !== "boolean") {
    fail("malformed_input", `${label} must be a boolean`);
  }
  return value;
}

function number(value: JsonValue | undefined, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail("malformed_input", `${label} must be a non-negative safe integer`);
  }
  return value;
}

function finiteNumber(value: JsonValue | undefined, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    fail("malformed_input", `${label} must be a finite non-negative number`);
  }
  return value;
}

function literal(value: JsonValue | undefined, expected: string, label: string): void {
  if (value !== expected) {
    fail("incompatible_input", `${label} does not match the reviewed contract`);
  }
}

function identifier(value: JsonValue | undefined, label: string): string {
  const result = string(value, label);
  if (result.length > 120 || !SAFE_ID_PATTERN.test(result)) {
    fail("malformed_input", `${label} is not a canonical identifier`);
  }
  return result;
}

function safeRelativePath(value: string, label: string, allowDirectory = false): string {
  const parts = value.split("/");
  if (
    value.length > 240
    || isAbsolute(value)
    || !SAFE_PATH_PATTERN.test(value)
    || value.includes("\\")
    || parts.some((part) => part === "" || part === "." || part === "..")
    || (!allowDirectory && !parts.at(-1)?.includes("."))
  ) {
    fail("unsafe_path", `${label} is not a canonical repository-relative path`);
  }
  return value;
}

function platform(value: JsonValue | undefined, label: string): Platform {
  const candidate = string(value, label);
  if (!PLATFORMS.includes(candidate as Platform)) {
    fail("unknown_platform", `${label} is not a supported parity platform`);
  }
  return candidate as Platform;
}

function platforms(value: JsonValue | undefined, label: string): readonly Platform[] {
  const result = array(value, label).map((entry, index) => platform(entry, `${label}[${index}]`));
  if (new Set(result).size !== result.length) {
    fail("malformed_input", `${label} contains a duplicate platform`);
  }
  return result;
}

function strings(value: JsonValue | undefined, label: string): readonly string[] {
  const result = array(value, label).map((entry, index) => string(entry, `${label}[${index}]`));
  if (new Set(result).size !== result.length) {
    fail("malformed_input", `${label} contains a duplicate value`);
  }
  return result;
}

function identifiers(value: JsonValue | undefined, label: string, nonempty = true): readonly string[] {
  const result = array(value, label).map((entry, index) => identifier(entry, `${label}[${index}]`));
  if ((nonempty && result.length === 0) || new Set(result).size !== result.length) {
    fail("malformed_input", `${label} must contain unique canonical identifiers`);
  }
  return result;
}

interface JsonParserLimits {
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxStringBytes?: number;
  readonly integerTokensOnly?: boolean;
}

const DEFAULT_JSON_LIMITS: JsonParserLimits = {
  maxDepth: MAX_JSON_DEPTH,
  maxNodes: MAX_JSON_NODES,
};

// JSON.parse cannot reject duplicate keys or preserve whether a registry number
// was lexically an integer. This parser accounts for every value before descending.
class BoundedJsonParser {
  private index = 0;
  private nodes = 0;
  private arrays = 0;
  private objects = 0;
  private strings = 0;

  constructor(
    private readonly text: string,
    private readonly label: string,
    private readonly limits: JsonParserLimits,
  ) {}

  parse(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      fail("malformed_json", `${this.label} contains trailing JSON input`);
    }
    return value;
  }

  private parseValue(depth: number): JsonValue {
    if (depth > this.limits.maxDepth) {
      fail("json_depth_limit", `${this.label} exceeds the bounded JSON depth`);
    }
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) {
      fail("json_node_limit", `${this.label} exceeds the bounded JSON node count`);
    }
    this.skipWhitespace();
    const current = this.text[this.index];
    if (current === "{") return this.parseObject(depth);
    if (current === "[") return this.parseArray(depth);
    if (current === '"') return this.parseString();
    if (current === "t") return this.parseLiteral("true", true);
    if (current === "f") return this.parseLiteral("false", false);
    if (current === "n") return this.parseLiteral("null", null);
    if (current === "-" || (current !== undefined && current >= "0" && current <= "9")) {
      return this.parseNumber();
    }
    fail("malformed_json", `${this.label} contains an invalid JSON value`);
  }

  private parseObject(depth: number): JsonRecord {
    this.objects += 1;
    if (this.objects > MAX_JSON_OBJECTS) {
      fail("json_object_limit", `${this.label} exceeds the bounded object count`);
    }
    this.index += 1;
    const result = Object.create(null) as JsonRecord;
    const keys = new Set<string>();
    this.skipWhitespace();
    if (this.consume("}")) return result;
    while (true) {
      if (keys.size >= MAX_JSON_OBJECT_KEYS) {
        fail("json_object_limit", `${this.label} exceeds the bounded object-key count`);
      }
      this.skipWhitespace();
      const key = this.parseString();
      if (key.length > MAX_JSON_KEY_LENGTH) {
        fail("json_key_limit", `${this.label} contains an oversized object key`);
      }
      if (keys.has(key)) {
        fail("duplicate_key", `${this.label} contains a duplicate object key`);
      }
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) {
        fail("malformed_json", `${this.label} is missing an object separator`);
      }
      result[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      if (this.consume("}")) return result;
      if (!this.consume(",")) {
        fail("malformed_json", `${this.label} is missing an object delimiter`);
      }
      this.skipWhitespace();
      if (this.text[this.index] === "}") {
        fail("malformed_json", `${this.label} contains a trailing object delimiter`);
      }
    }
  }

  private parseArray(depth: number): JsonValue[] {
    this.arrays += 1;
    if (this.arrays > MAX_JSON_ARRAYS) {
      fail("json_array_limit", `${this.label} exceeds the bounded array count`);
    }
    this.index += 1;
    const result: JsonValue[] = [];
    this.skipWhitespace();
    if (this.consume("]")) return result;
    while (true) {
      if (result.length >= MAX_JSON_ARRAY_ITEMS) {
        fail("json_array_limit", `${this.label} exceeds the bounded array length`);
      }
      result.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume("]")) return result;
      if (!this.consume(",")) {
        fail("malformed_json", `${this.label} is missing an array delimiter`);
      }
      this.skipWhitespace();
      if (this.text[this.index] === "]") {
        fail("malformed_json", `${this.label} contains a trailing array delimiter`);
      }
    }
  }

  private parseString(): string {
    this.strings += 1;
    if (this.strings > MAX_JSON_STRING_VALUES) {
      fail("json_string_limit", `${this.label} exceeds the bounded string count`);
    }
    if (!this.consume('"')) {
      fail("malformed_json", `${this.label} contains an invalid JSON string at ${this.index}`);
    }
    let result = "";
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      this.index += 1;
      if (character === '"') return result;
      if (character === "\\") {
        const escape = this.text[this.index];
        this.index += 1;
        if (escape === '"' || escape === "\\" || escape === "/") result += escape;
        else if (escape === "b") result += "\b";
        else if (escape === "f") result += "\f";
        else if (escape === "n") result += "\n";
        else if (escape === "r") result += "\r";
        else if (escape === "t") result += "\t";
        else if (escape === "u") {
          const hex = this.text.slice(this.index, this.index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            fail("malformed_json", `${this.label} contains an invalid Unicode escape`);
          }
          result += String.fromCharCode(Number.parseInt(hex, 16));
          this.index += 4;
        } else {
          fail("malformed_json", `${this.label} contains an invalid string escape`);
        }
      } else {
        if (character === undefined || character.charCodeAt(0) < 0x20) {
          fail("malformed_json", `${this.label} contains an unescaped control character`);
        }
        result += character;
      }
      if (
        result.length > MAX_JSON_STRING_LENGTH
        || (this.limits.maxStringBytes !== undefined && utf8Bytes(result) > this.limits.maxStringBytes)
      ) {
        fail("json_string_limit", `${this.label} exceeds the bounded string length`);
      }
    }
    fail("malformed_json", `${this.label} contains an unterminated JSON string`);
  }

  private parseLiteral<T extends JsonValue>(literal: string, value: T): T {
    if (!this.text.startsWith(literal, this.index)) {
      fail("malformed_json", `${this.label} contains an invalid JSON literal`);
    }
    this.index += literal.length;
    return value;
  }

  private parseNumber(): number {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.text.slice(this.index));
    if (!match) {
      fail("malformed_json", `${this.label} contains an invalid JSON number`);
    }
    const token = match[0];
    if (this.limits.integerTokensOnly && /[.eE]/.test(token)) {
      fail("malformed_input", `${this.label} requires lexical JSON integer tokens`);
    }
    this.index += token.length;
    const value = Number(token);
    if (!Number.isFinite(value)) {
      fail("json_number_limit", `${this.label} contains an unrepresentable JSON number`);
    }
    return value;
  }

  private skipWhitespace(): void {
    while (this.index < this.text.length && /[\t\n\r ]/.test(this.text[this.index] ?? "")) {
      this.index += 1;
    }
  }

  private consume(expected: string): boolean {
    if (this.text[this.index] !== expected) return false;
    this.index += 1;
    return true;
  }
}

function parseJson(
  text: string,
  label: string,
  limits: JsonParserLimits = DEFAULT_JSON_LIMITS,
): JsonValue {
  return new BoundedJsonParser(text, label, limits).parse();
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface FileIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly size: number;
}

function fileIdentity(stats: { dev: number; ino: number; size: number }): FileIdentity {
  return { dev: stats.dev, ino: stats.ino, size: stats.size };
}

function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size;
}

interface NativeFileApi {
  readonly openat: (directoryFd: number, path: number, flags: number, mode: number) => number;
  readonly close: (fileDescriptor: number) => number;
  readonly dup: (fileDescriptor: number) => number;
  readonly fdopendir: (fileDescriptor: number) => Pointer | null;
  readonly readdir: (directory: Pointer) => Pointer | null;
  readonly closedir: (directory: Pointer) => number;
}

let nativeFileApi: NativeFileApi | undefined;
let nativeFileLibrary: unknown;

function getNativeFileApi(): NativeFileApi {
  if (nativeFileApi) return nativeFileApi;
  try {
    const libraryName = process.platform === "darwin" ? "libSystem.B.dylib" : "libc.so.6";
    const library = dlopen(libraryName, {
      openat: {
        args: [FFIType.int, FFIType.cstring, FFIType.int, FFIType.int],
        returns: FFIType.int,
      },
      close: {
        args: [FFIType.int],
        returns: FFIType.int,
      },
      dup: {
        args: [FFIType.int],
        returns: FFIType.int,
      },
      fdopendir: {
        args: [FFIType.int],
        returns: FFIType.ptr,
      },
      readdir: {
        args: [FFIType.ptr],
        returns: FFIType.ptr,
      },
      closedir: {
        args: [FFIType.ptr],
        returns: FFIType.int,
      },
    });
    nativeFileLibrary = library;
    nativeFileApi = library.symbols as unknown as NativeFileApi;
    return nativeFileApi;
  } catch {
    fail("artifact_read_failed", "descriptor-first reader is unavailable");
  }
}

function nativeCString(value: string): number {
  return ptr(new TextEncoder().encode(`${value}\0`));
}

export function atFdcwdForPlatform(platformName: string): number {
  if (platformName === "darwin") return -2;
  if (platformName === "linux") return -100;
  fail("artifact_read_failed", "descriptor-first reader is unsupported on this platform");
}

function closeNativeFile(api: NativeFileApi, fileDescriptor: number, label: string): void {
  if (fileDescriptor >= 0 && api.close(fileDescriptor) !== 0) {
    fail("descriptor_cleanup_failed", `${label} descriptor could not be closed`);
  }
}

// Traverse every pathname component from an anchored directory descriptor. The
// repository root is canonicalized once, but fixture descendants are never
// resolved through a pathname symlink; replacing a parent directory therefore
// cannot redirect this read to an attacker-selected tree.
function openDescriptorNoFollow(
  path: string,
  label: string,
  finalFlags = FILE_READ_FLAGS,
): number {
  const api = getNativeFileApi();
  const components = resolve(path).split("/").filter((component) => component.length > 0);
  let directoryFd = api.openat(atFdcwdForPlatform(process.platform), nativeCString("/"), DIRECTORY_READ_FLAGS, 0);
  if (directoryFd < 0) {
    fail("artifact_read_failed", `${label} could not open its descriptor root`);
  }
  try {
    for (const [index, component] of components.entries()) {
      const finalComponent = index === components.length - 1;
      const nextFd = api.openat(
        directoryFd,
        nativeCString(component),
        finalComponent ? finalFlags : DIRECTORY_READ_FLAGS,
        0,
      );
      if (nextFd < 0) {
        fail("unsafe_artifact", `${label} could not be opened without following a parent symlink`);
      }
      closeNativeFile(api, directoryFd, label);
      directoryFd = nextFd;
    }
    const result = directoryFd;
    directoryFd = -1;
    return result;
  } finally {
    closeNativeFile(api, directoryFd, label);
  }
}

function openChildDescriptorNoFollow(
  directoryFd: number,
  name: string,
  flags: number,
  label: string,
): number {
  if (name.includes("/") || name === "." || name === "..") {
    fail("unsafe_artifact", `${label} contains an unsafe directory entry`);
  }
  const descriptor = getNativeFileApi().openat(directoryFd, nativeCString(name), flags, 0);
  if (descriptor < 0) fail("unsafe_artifact", `${label} could not be opened without following a symlink`);
  return descriptor;
}

async function descriptorHandle(fileDescriptor: number, label: string): Promise<FileHandle> {
  try {
    return await open(`/dev/fd/${fileDescriptor}`, DUPLICATED_DESCRIPTOR_FLAGS);
  } catch {
    fail("artifact_read_failed", `${label} could not duplicate its secure descriptor`);
  }
}

function directoryEntryNames(directoryFd: number, label: string): readonly string[] {
  const api = getNativeFileApi();
  const duplicateFd = api.dup(directoryFd);
  if (duplicateFd < 0) fail("artifact_read_failed", `${label} descriptor could not be duplicated`);
  const directoryPointer = api.fdopendir(duplicateFd);
  if (!directoryPointer) {
    closeNativeFile(api, duplicateFd, label);
    fail("fixture_inventory_invalid", `${label} descriptor is not a directory`);
  }
  try {
    const names: string[] = [];
    const nameOffset = process.platform === "darwin" ? 21 : 19;
    const recordBytes = process.platform === "darwin" ? 1_048 : 280;
    while (true) {
      const entryPointer = api.readdir(directoryPointer);
      if (!entryPointer) break;
      const bytes = new Uint8Array(toArrayBuffer(entryPointer, 0, recordBytes));
      let end = nameOffset;
      while (end < bytes.length && bytes[end] !== 0) end += 1;
      let name: string;
      try {
        name = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(nameOffset, end));
      } catch {
        fail("fixture_inventory_invalid", `${label} contains a non-UTF-8 entry name`);
      }
      if (name !== "." && name !== "..") names.push(name);
      if (names.length > MAX_REGISTRY_FILES + MAX_INVENTORY_DIRECTORIES) {
        fail("fixture_inventory_invalid", `${label} contains too many entries`);
      }
    }
    return names;
  } finally {
    if (api.closedir(directoryPointer) !== 0) {
      fail("descriptor_cleanup_failed", `${label} directory stream could not be closed`);
    }
  }
}

export async function readDescriptorBytes(
  fileDescriptor: number,
  expectedBytes: number,
  label: string,
): Promise<Uint8Array> {
  // The descriptor is inherited directly, so the subprocess never resolves the
  // untrusted pathname. A separate process is required for a real wall-clock
  // boundary: SIGKILL can interrupt a kernel read that JavaScript cannot cancel.
  const child = Bun.spawn(["/usr/bin/head", "-c", String(expectedBytes + 1)], {
    stdin: fileDescriptor,
    stdout: "pipe",
    stderr: "ignore",
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new ContractInputError("artifact_read_timeout", `${label} did not finish reading`));
    }, MAX_READ_DURATION_MS);
  });
  try {
    const operation = Promise.all([
      new Response(child.stdout).arrayBuffer(),
      child.exited,
    ] as const);
    const [buffer, exitCode] = await Promise.race([operation, timeout]);
    if (exitCode !== 0) fail("artifact_read_failed", `${label} bounded reader failed`);
    const bytes = new Uint8Array(buffer);
    if (bytes.byteLength !== expectedBytes) {
      fail("artifact_changed", `${label} changed from its declared byte size while reading`);
    }
    return bytes;
  } finally {
    if (timer) clearTimeout(timer);
    // kill() is harmless after a normal exit. Awaiting exited proves that the
    // inherited child descriptor has closed before the parent continues.
    child.kill("SIGKILL");
    await child.exited;
  }
}

// Open the descriptor before trusting any pathname metadata. O_NONBLOCK prevents a
// FIFO replacement from waiting for a writer, component-by-component O_NOFOLLOW
// prevents parent-directory traversal, and the inherited-descriptor subprocess
// gives each read a killable wall-clock boundary with deterministic cleanup.
async function readBoundedBytes(
  path: string,
  label: string,
  registered?: RegistryFile,
  maxBytes = MAX_JSON_BYTES,
): Promise<Uint8Array> {
  let handle: FileHandle | undefined;
  let nativeFileDescriptor: number | undefined;
  try {
    nativeFileDescriptor = openDescriptorNoFollow(path, label);
    // /dev/fd duplicates the already-anchored descriptor; it does not resolve
    // the untrusted fixture pathname and is used only for portable Node stats.
    handle = await descriptorHandle(nativeFileDescriptor, label);

    const descriptorStatsRaw = await handle.stat();
    if (!descriptorStatsRaw.isFile()) {
      fail("unsafe_artifact", `${label} is not a regular file`);
    }
    const descriptorStats = fileIdentity(descriptorStatsRaw);
    if (!Number.isSafeInteger(descriptorStats.size) || descriptorStats.size < 0) {
      fail("artifact_read_failed", `${label} has an unsafe descriptor size`);
    }
    if (registered && descriptorStats.size !== registered.sizeBytes) {
      fail("artifact_size_mismatch", `${label} does not match its registered byte size`);
    }
    if (descriptorStats.size > maxBytes) {
      fail("json_too_large", `${label} exceeds the bounded artifact size`);
    }

    let pathStats;
    try {
      pathStats = await lstat(path);
    } catch {
      fail("artifact_changed", `${label} disappeared while it was being opened`);
    }
    if (!pathStats.isFile() || !sameFileIdentity(descriptorStats, fileIdentity(pathStats))) {
      fail("artifact_changed", `${label} changed while it was being opened`);
    }

    const bytes = await readDescriptorBytes(nativeFileDescriptor, descriptorStats.size, label);

    const finalStats = fileIdentity(await handle.stat());
    if (!sameFileIdentity(descriptorStats, finalStats)) {
      fail("artifact_changed", `${label} changed while it was being read`);
    }
    let finalPathStats;
    try {
      finalPathStats = await lstat(path);
    } catch {
      fail("artifact_changed", `${label} disappeared after it was read`);
    }
    if (!finalPathStats.isFile() || !sameFileIdentity(finalStats, fileIdentity(finalPathStats))) {
      fail("artifact_changed", `${label} changed after it was read`);
    }
    if (registered && sha256(bytes) !== registered.sha256) {
      fail("artifact_hash_mismatch", `${label} does not match its registered SHA-256`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof ContractInputError) throw error;
    return fail("artifact_read_failed", `${label} could not be read as bounded UTF-8 JSON`);
  } finally {
    let duplicatedCloseFailed = false;
    if (handle) {
      try {
        await handle.close();
      } catch {
        duplicatedCloseFailed = true;
      }
    }
    if (nativeFileDescriptor !== undefined) {
      closeNativeFile(getNativeFileApi(), nativeFileDescriptor, label);
    }
    if (duplicatedCloseFailed) {
      fail("descriptor_cleanup_failed", `${label} duplicated descriptor could not be closed`);
    }
  }
}

interface ReadJsonOptions {
  readonly registered?: RegistryFile;
  readonly maxBytes?: number;
  readonly parserLimits?: JsonParserLimits;
}

async function readJson(path: string, label: string, options: ReadJsonOptions = {}): Promise<JsonValue> {
  const bytes = await readBoundedBytes(path, label, options.registered, options.maxBytes);
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("malformed_utf8", `${label} is not valid UTF-8`);
  }
  return parseJson(text, label, options.parserLimits);
}

function parseRegistryFile(value: JsonValue | undefined, label: string): RegistryFile {
  const entry = exactRecord(value, label, REGISTRY_FILE_KEYS);
  const digest = string(entry.sha256, `${label}.sha256`);
  const sizeBytes = number(entry.size_bytes, `${label}.size_bytes`);
  if (!SHA256_PATTERN.test(digest)) {
    fail("malformed_input", `${label}.sha256 must be a lowercase SHA-256 digest`);
  }
  if (sizeBytes > MAX_JSON_BYTES) {
    fail("json_too_large", `${label}.size_bytes exceeds the bounded artifact size`);
  }
  return {
    path: safeRelativePath(string(entry.path, `${label}.path`), `${label}.path`),
    sha256: digest,
    sizeBytes,
  };
}

function parseFixtureRoot(value: JsonValue | undefined, index: number): FixtureRoot {
  const entry = exactRecord(value, `fixture_roots[${index}]`, FIXTURE_ROOT_KEYS);
  const status = string(entry.status, `fixture_roots[${index}].status`);
  if (status !== "ready" && status !== "pending") {
    fail("unknown_status", `fixture_roots[${index}].status is unknown`);
  }
  const files = array(entry.files, `fixture_roots[${index}].files`).map((file, fileIndex) =>
    parseRegistryFile(file, `fixture_roots[${index}].files[${fileIndex}]`),
  );
  if (new Set(files.map((file) => file.path)).size !== files.length) {
    fail("malformed_input", `fixture_roots[${index}].files contains a duplicate path`);
  }
  const validator = entry.validator === null
    ? null
    : safeRelativePath(
        string(entry.validator, `fixture_roots[${index}].validator`),
        `fixture_roots[${index}].validator`,
      );
  if (status === "pending" && (validator !== null || files.length !== 0)) {
    fail("fixture_inventory_invalid", "pending fixture roots must not claim artifacts");
  }
  if (status === "ready" && (validator === null || files.length === 0)) {
    fail("fixture_inventory_invalid", "ready fixture roots must list artifacts and a validator");
  }
  return {
    id: identifier(entry.id, `fixture_roots[${index}].id`),
    path: safeRelativePath(string(entry.path, `fixture_roots[${index}].path`), `fixture_roots[${index}].path`, true),
    status,
    contract: string(entry.contract, `fixture_roots[${index}].contract`),
    hermesSourceSha: string(entry.hermes_source_sha, `fixture_roots[${index}].hermes_source_sha`),
    syntheticOnly: boolean(entry.synthetic_only, `fixture_roots[${index}].synthetic_only`) as true,
    liveClaim: boolean(entry.live_claim, `fixture_roots[${index}].live_claim`) as false,
    platforms: platforms(entry.platforms, `fixture_roots[${index}].platforms`),
    states: identifiers(entry.states, `fixture_roots[${index}].states`),
    coverageIds: identifiers(entry.coverage_ids, `fixture_roots[${index}].coverage_ids`),
    validator,
    files,
  };
}

function parseCoverage(value: JsonValue | undefined, index: number): CoverageRow {
  const entry = exactRecord(value, `coverage[${index}]`, COVERAGE_KEYS);
  const status = string(entry.status, `coverage[${index}].status`);
  if (status !== "ready" && !NON_SUCCESS_COVERAGE_STATUSES.includes(status as (typeof NON_SUCCESS_COVERAGE_STATUSES)[number])) {
    fail("unknown_status", `coverage[${index}].status is unknown`);
  }
  return {
    id: identifier(entry.id, `coverage[${index}].id`),
    status: status as CoverageStatus,
    fixtureIds: identifiers(entry.fixture_ids, `coverage[${index}].fixture_ids`, false),
    platforms: platforms(entry.platforms, `coverage[${index}].platforms`),
    requiredStates: identifiers(entry.required_states, `coverage[${index}].required_states`),
    notes: string(entry.notes, `coverage[${index}].notes`),
  };
}

function parseParity(value: JsonValue | undefined): RegistryParity {
  const entry = exactRecord(value, "parity", PARITY_KEYS);
  return {
    status: string(entry.status, "parity.status"),
    fixtureSource: string(entry.fixture_source, "parity.fixture_source"),
    platforms: platforms(entry.platforms, "parity.platforms"),
    ptyPolicy: string(entry.pty_policy, "parity.pty_policy"),
    missingResultPolicy: string(entry.missing_result_policy, "parity.missing_result_policy"),
    resultEquivalence: string(entry.result_equivalence, "parity.result_equivalence"),
    liveClaim: boolean(entry.live_claim, "parity.live_claim") as false,
  };
}

function validateRegistryMetadata(raw: JsonRecord): {
  evidenceStatus: "partial" | "complete";
  states: JsonRecord[];
  redaction: JsonRecord;
  benchmark: JsonRecord;
} {
  const evidenceStatus = string(raw.evidence_status, "fixture index evidence_status");
  if (evidenceStatus !== "partial" && evidenceStatus !== "complete") {
    fail("incompatible_input", "fixture index evidence status is invalid");
  }

  const states = array(raw.states, "states").map((value, index) => {
    const entry = exactRecord(value, `states[${index}]`, STATE_KEYS);
    const expectedId = STATE_IDS[index];
    const id = identifier(entry.id, `states[${index}].id`);
    if (!expectedId || id !== expectedId) fail("incompatible_input", "fixture state inventory changed");
    const expected = EXPECTED_STATE_SEMANTICS[id];
    const actual = STATE_KEYS.slice(1).map((key) => string(entry[key], `states[${index}].${key}`));
    if (!expected || !sameStringList(actual, expected)) {
      fail("incompatible_input", "fixture state semantics changed");
    }
    return entry;
  });
  if (states.length !== STATE_IDS.length) fail("incompatible_input", "fixture state inventory changed");

  const redaction = exactRecord(raw.redaction, "redaction", REDACTION_KEYS);
  const falseFlags = REDACTION_KEYS.slice(1, -1);
  if (boolean(redaction.synthetic_only, "redaction.synthetic_only") !== true) {
    fail("live_input", "fixture registry redaction is not synthetic-only");
  }
  for (const key of falseFlags) {
    if (boolean(redaction[key], `redaction.${key}`) !== false) {
      fail("live_input", "fixture registry redaction permits retained sensitive data");
    }
  }
  literal(redaction.failure_output, "one_bounded_semantic_json_line", "redaction.failure_output");

  const benchmark = exactRecord(raw.benchmark, "benchmark", BENCHMARK_KEYS);
  literal(
    safeRelativePath(string(benchmark.path, "benchmark.path"), "benchmark.path"),
    "validator/validation-baseline.json",
    "benchmark.path",
  );
  if (benchmark.threshold !== null) fail("incompatible_input", "benchmark threshold must remain null");
  literal(benchmark.evidence_mode, "observed_worktree_only", "benchmark.evidence_mode");
  literal(
    benchmark.build_mode,
    "N/A - no production or release executable",
    "benchmark.build_mode",
  );
  return { evidenceStatus, states, redaction, benchmark };
}

async function canonicalRepositoryRoot(repoRoot: string): Promise<string> {
  try {
    // Only the repository root itself is canonicalized. Every descendant is
    // traversed from descriptors with O_NOFOLLOW, so a fixture parent swapped
    // after this point cannot redirect a read through a symlink.
    return await realpath(resolve(repoRoot));
  } catch {
    fail("artifact_read_failed", "repository root could not be resolved");
  }
}

export async function loadRegistry(repoRoot: string): Promise<FixtureRegistry> {
  const root = await canonicalRepositoryRoot(repoRoot);
  const raw = exactRecord(
    await readJson(join(root, "contracts/fixtures/index.json"), "fixture index", {
      parserLimits: { ...DEFAULT_JSON_LIMITS, integerTokensOnly: true },
    }),
    "fixture index",
    REGISTRY_TOP_KEYS,
  );
  literal(raw.schema, REGISTRY_SCHEMA, "fixture index schema");
  literal(raw.contract, CONTRACT, "fixture index contract");
  literal(raw.hermes_source_sha, HERMES_SOURCE_SHA, "fixture index source revision");
  if (boolean(raw.synthetic_only, "fixture index synthetic_only") !== true) {
    fail("live_input", "fixture index is not synthetic-only");
  }
  if (boolean(raw.live_claim, "fixture index live_claim") !== false) {
    fail("live_input", "fixture index makes a live claim");
  }

  const metadata = validateRegistryMetadata(raw);
  const fixtureRoots = array(raw.fixture_roots, "fixture_roots").map(parseFixtureRoot);
  const coverage = array(raw.coverage, "coverage").map(parseCoverage);
  const fixtureRootIds = fixtureRoots.map((entry) => entry.id);
  const coverageIdList = coverage.map((entry) => entry.id);
  if (
    new Set(fixtureRootIds).size !== fixtureRoots.length
    || !sameStringList(fixtureRootIds, [...fixtureRootIds].sort())
  ) {
    fail("malformed_input", "fixture root IDs must be sorted and unique");
  }
  if (
    new Set(coverageIdList).size !== coverage.length
    || !sameStringList(coverageIdList, [...coverageIdList].sort())
  ) {
    fail("malformed_input", "coverage IDs must be sorted and unique");
  }
  const allowedStates = new Set<string>(STATE_IDS);
  for (const entry of fixtureRoots) {
    if (entry.contract !== CONTRACT || entry.hermesSourceSha !== HERMES_SOURCE_SHA) {
      fail("incompatible_input", "fixture root is not pinned to the reviewed contract");
    }
    if (!SHA40_PATTERN.test(entry.hermesSourceSha)) {
      fail("malformed_input", "fixture root source revision is invalid");
    }
    if (entry.syntheticOnly !== true || entry.liveClaim !== false) {
      fail("live_input", "fixture root is not synthetic-only");
    }
    if (
      entry.states.some((state) => !allowedStates.has(state))
      || !sameStringList(entry.states, [...entry.states].sort())
      || !sameStringList(entry.coverageIds, [...entry.coverageIds].sort())
      || !sameStringList(entry.files.map((file) => file.path), entry.files.map((file) => file.path).sort())
    ) {
      fail("fixture_inventory_invalid", "fixture root metadata is not canonically sorted");
    }
  }
  const rootIds = new Set(fixtureRoots.map((entry) => entry.id));
  for (const entry of coverage) {
    if (entry.fixtureIds.some((id) => !rootIds.has(id))) {
      fail("unknown_fixture", "coverage references an unknown fixture root");
    }
    if (
      !sameStringList(entry.fixtureIds, [...entry.fixtureIds].sort())
      || !sameStringList(entry.platforms, [...entry.platforms].sort((left, right) => PLATFORMS.indexOf(left) - PLATFORMS.indexOf(right)))
      || !sameStringList(entry.requiredStates, [...entry.requiredStates].sort((left, right) => STATE_IDS.indexOf(left as never) - STATE_IDS.indexOf(right as never)))
      || entry.requiredStates.some((state) => !allowedStates.has(state))
      || entry.notes.length > 512
    ) {
      fail("malformed_input", "coverage metadata is not canonical");
    }
    if (entry.status === "ready" && entry.fixtureIds.length === 0) {
      fail("fixture_inventory_invalid", "ready coverage must cite a fixture root");
    }
    if (entry.status === "ready" && entry.fixtureIds.some((id) => fixtureRoots.find((rootEntry) => rootEntry.id === id)?.status !== "ready")) {
      fail("fixture_inventory_invalid", "ready coverage references a pending fixture root");
    }
  }
  const parity = parseParity(raw.parity);
  if (
    parity.status !== "synthetic_observed"
    || parity.liveClaim !== false
    || parity.fixtureSource !== "one_shared_registry"
    || !sameStringList(parity.platforms, PLATFORMS)
    || parity.ptyPolicy !== "web_only_apple_blocked"
    || parity.missingResultPolicy !== "block"
    || parity.resultEquivalence !== "semantic_outcomes_not_platform_specific_wire_bytes"
  ) {
    fail("incompatible_input", "parity policy is not the shared synthetic policy");
  }
  const coverageIds = new Set(coverage.map((entry) => entry.id));
  const referencedRootIds = new Set<string>();
  for (const rootEntry of fixtureRoots) {
    if (rootEntry.coverageIds.some((id) => !coverageIds.has(id))) {
      fail("fixture_inventory_invalid", "fixture root references an unknown coverage row");
    }
    for (const coverageId of rootEntry.coverageIds) {
      const coverageEntry = coverage.find((entry) => entry.id === coverageId);
      if (!coverageEntry?.fixtureIds.includes(rootEntry.id)) {
        fail("fixture_inventory_invalid", "fixture and coverage linkage must be bidirectional");
      }
    }
  }
  for (const coverageEntry of coverage) {
    for (const fixtureId of coverageEntry.fixtureIds) {
      const rootEntry = fixtureRoots.find((entry) => entry.id === fixtureId);
      if (!rootEntry) fail("unknown_fixture", "coverage references an unknown fixture root");
      if (!rootEntry.coverageIds.includes(coverageEntry.id)) {
        fail("fixture_inventory_invalid", "coverage and fixture linkage must be bidirectional");
      }
      referencedRootIds.add(fixtureId);
    }
  }
  if ([...rootIds].some((id) => !referencedRootIds.has(id))) {
    fail("fixture_inventory_invalid", "every fixture root must be connected to coverage");
  }
  const hasBlockedCoverage = coverage.some((entry) => entry.status !== "ready");
  if (metadata.evidenceStatus !== (hasBlockedCoverage ? "partial" : "complete")) {
    fail("incompatible_input", "fixture evidence status does not match coverage states");
  }
  return {
    evidenceStatus: metadata.evidenceStatus,
    fixtureRoots,
    coverage,
    parity,
    states: metadata.states,
    redaction: metadata.redaction,
    benchmark: metadata.benchmark,
  };
}

interface FixtureWalkOptions {
  readonly skipMetadata: boolean;
}

interface InventoryBudget {
  directories: number;
}

async function walkFixtureDescriptor(
  directoryFd: number,
  relativeDirectory: string,
  output: string[],
  options: FixtureWalkOptions,
  depth: number,
  budget: InventoryBudget,
): Promise<void> {
  if (depth > MAX_INVENTORY_DEPTH) {
    fail("fixture_inventory_invalid", "fixture inventory exceeds the bounded directory depth");
  }
  budget.directories += 1;
  if (budget.directories > MAX_INVENTORY_DIRECTORIES) {
    fail("fixture_inventory_invalid", "fixture inventory exceeds the bounded directory count");
  }

  const entryNames = directoryEntryNames(directoryFd, "fixture inventory directory");
  try {
    for (const entryName of entryNames) {
      if (entryName === ".DS_Store" || entryName === "__pycache__") continue;
      if (options.skipMetadata && relativeDirectory === "" && entryName === FIXTURE_VALIDATOR_DIRECTORY) continue;
      if (options.skipMetadata && relativeDirectory === "" && FIXTURE_METADATA_FILES.has(entryName)) continue;
      if (entryName.endsWith(".pyc")) continue;

      const relativePath = relativeDirectory ? `${relativeDirectory}/${entryName}` : entryName;
      const childFd = openChildDescriptorNoFollow(
        directoryFd,
        entryName,
        fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
        `fixture inventory ${relativePath}`,
      );
      let handle: FileHandle | undefined;
      try {
        handle = await descriptorHandle(childFd, `fixture inventory ${relativePath}`);
        const stats = await handle.stat();
        if (stats.isDirectory()) {
          await handle.close();
          handle = undefined;
          await walkFixtureDescriptor(childFd, relativePath, output, options, depth + 1, budget);
        } else {
          output.push(relativePath);
          if (output.length > MAX_REGISTRY_FILES) {
            fail("fixture_inventory_invalid", "fixture inventory exceeds the bounded file count");
          }
        }
      } finally {
        if (handle) {
          try {
            await handle.close();
          } catch {
            closeNativeFile(getNativeFileApi(), childFd, `fixture inventory ${relativePath}`);
            fail("descriptor_cleanup_failed", "fixture inventory duplicated descriptor could not be closed");
          }
        }
        closeNativeFile(getNativeFileApi(), childFd, `fixture inventory ${relativePath}`);
      }
    }
  } catch (error) {
    if (error instanceof ContractInputError) throw error;
    fail("fixture_inventory_invalid", "fixture inventory could not be enumerated");
  }
}

async function walkFixtureFiles(
  directoryPath: string,
  relativeDirectory: string,
  output: string[],
  options: FixtureWalkOptions,
): Promise<void> {
  const rootFd = openDescriptorNoFollow(
    directoryPath,
    "fixture inventory root",
    DIRECTORY_READ_FLAGS,
  );
  try {
    await walkFixtureDescriptor(rootFd, relativeDirectory, output, options, 0, { directories: 0 });
  } finally {
    closeNativeFile(getNativeFileApi(), rootFd, "fixture inventory root");
  }
}

function sameStringList(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

// The Python aggregate validator treats the registry as an inventory, not merely a
// source for the eight representatives. Recheck every ready root, every digest, and
// every non-metadata file before any semantic representative can claim parity.
async function validateRegistryInventory(repoRoot: string, registry: FixtureRegistry): Promise<void> {
  const fixturesRoot = join(repoRoot, "contracts/fixtures");
  const ownedFiles = new Set<string>();
  let totalBytes = 0;

  for (const root of registry.fixtureRoots) {
    if (root.status === "pending") {
      if (root.validator !== null || root.files.length !== 0) {
        fail("fixture_inventory_invalid", "pending fixture roots must not claim artifacts");
      }
      continue;
    }

    const actualFiles: string[] = [];
    await walkFixtureFiles(join(fixturesRoot, root.path), root.path, actualFiles, { skipMetadata: false });
    actualFiles.sort();
    const listedFiles = root.files.map((file) => file.path);
    if (!sameStringList(listedFiles, [...listedFiles].sort()) || !sameStringList(actualFiles, listedFiles)) {
      fail("fixture_inventory_invalid", "fixture file manifest is incomplete or stale");
    }
    const validatorPath = `${root.path}/${root.validator}`;
    if (!root.files.some((file) => file.path === validatorPath)) {
      fail("fixture_inventory_invalid", "fixture validator is not listed by the registry");
    }

    for (const file of root.files) {
      if (!file.path.startsWith(`${root.path}/`)) {
        fail("fixture_inventory_invalid", "fixture artifact escapes its registered root");
      }
      if (ownedFiles.has(file.path)) {
        fail("fixture_inventory_invalid", "fixture artifact is listed by multiple roots");
      }
      ownedFiles.add(file.path);
      totalBytes += file.sizeBytes;
      if (totalBytes > MAX_TOTAL_ARTIFACT_BYTES) {
        fail("fixture_inventory_invalid", "fixture artifacts exceed the bounded aggregate size");
      }
      await readBoundedBytes(join(fixturesRoot, file.path), `fixture artifact ${file.path}`, file);
    }
  }

  const actualInventory: string[] = [];
  await walkFixtureFiles(fixturesRoot, "", actualInventory, { skipMetadata: true });
  actualInventory.sort();
  const ownedInventory = [...ownedFiles].sort();
  if (!sameStringList(actualInventory, ownedInventory)) {
    fail("fixture_inventory_invalid", "unindexed fixture artifact exists");
  }
}

function validateArtifactShape(rootId: string, artifact: JsonRecord): void {
  if (rootId === "source-audit-compatibility-gate") {
    exactRecord(artifact, `fixture ${rootId}`, COMPATIBILITY_RECORD_KEYS);
    return;
  }
  const schema = ARTIFACT_SCHEMAS[rootId];
  if (!schema || !schema.caseKeys) {
    fail("unknown_fixture", "fixture root has no approved JSON schema");
  }
  const entry = exactRecord(artifact, `fixture ${rootId}`, schema.topKeys);
  if (schema.schemaField && schema.schemaValue) {
    literal(entry[schema.schemaField], schema.schemaValue, `fixture ${rootId}.${schema.schemaField}`);
  }
  if (schema.sourceField) {
    literal(entry[schema.sourceField], HERMES_SOURCE_SHA, `fixture ${rootId}.${schema.sourceField}`);
  }
  if (Object.prototype.hasOwnProperty.call(entry, "contract") && !schema.contractIsObject) {
    literal(entry.contract, CONTRACT, `fixture ${rootId}.contract`);
  }
  if (Object.prototype.hasOwnProperty.call(entry, "synthetic_only") && boolean(entry.synthetic_only, `fixture ${rootId}.synthetic_only`) !== true) {
    fail("live_input", `fixture ${rootId} is not synthetic-only`);
  }
  if (rootId === "pty-contract") {
    literal(entry.schema_version, "pty-contract-v1", "fixture pty-contract.schema_version");
    const contract = exactRecord(entry.contract, "fixture pty-contract.contract", [
      "route",
      "surface",
      "proof_mode",
      "pinned_hermes_sha",
      "source_of_truth",
      "output_encoding",
      "attach_rule",
      "replay_rule",
      "logging_rule",
    ]);
    literal(contract.surface, "web-only", "fixture pty-contract.contract.surface");
    literal(contract.pinned_hermes_sha, HERMES_SOURCE_SHA, "fixture pty-contract.contract.pinned_hermes_sha");
  }

  const cases = array(entry.cases, `fixture ${rootId}.cases`);
  const caseIds = new Set<string>();
  for (const [index, value] of cases.entries()) {
    const fixtureCase = exactRecord(value, `fixture ${rootId}.cases[${index}]`, schema.caseKeys);
    const caseId = string(fixtureCase.id, `fixture ${rootId}.cases[${index}].id`);
    if (caseIds.has(caseId)) {
      fail("malformed_input", `fixture ${rootId}.cases contains a duplicate ID`);
    }
    caseIds.add(caseId);
    let expectedKeys = schema.expectedKeys;
    if (schema.expectedKeysByKind) {
      const kind = string(fixtureCase.kind, `fixture ${rootId}.cases[${index}].kind`);
      expectedKeys = schema.expectedKeysByKind[kind];
      if (!expectedKeys) {
        fail("unknown_case_schema", `fixture ${rootId}.cases[${index}] has an unknown kind`);
      }
    }
    exactRecord(fixtureCase.expected, `fixture ${rootId}.cases[${index}].expected`, expectedKeys ?? []);
  }
}

function rootById(registry: FixtureRegistry, rootId: string): FixtureRoot {
  const root = registry.fixtureRoots.find((entry) => entry.id === rootId);
  if (!root) {
    fail("unknown_fixture", "representative fixture root is not registered");
  }
  return root;
}

function coverageById(registry: FixtureRegistry, coverageId: string): CoverageRow {
  const coverage = registry.coverage.find((entry) => entry.id === coverageId);
  if (!coverage) {
    fail("unknown_coverage", "representative coverage row is not registered");
  }
  return coverage;
}

function artifactPath(repoRoot: string, root: FixtureRoot): string {
  const relativeArtifact = JSON_ARTIFACTS[root.id];
  if (!relativeArtifact) {
    fail("unknown_fixture", "fixture root has no approved JSON artifact");
  }
  const expectedPrefix = `${root.path}/`;
  if (!relativeArtifact.startsWith(expectedPrefix)) {
    fail("incompatible_input", "fixture artifact is outside its registered root");
  }
  const registeredMatches = root.files.filter((entry) => entry.path === relativeArtifact);
  if (registeredMatches.length !== 1) {
    fail("unregistered_artifact", "fixture JSON artifact is not listed exactly once by the registry");
  }
  return join(resolve(repoRoot), "contracts/fixtures", safeRelativePath(relativeArtifact, "fixture artifact"));
}

function registeredArtifact(root: FixtureRoot): RegistryFile {
  const relativeArtifact = JSON_ARTIFACTS[root.id];
  if (!relativeArtifact) {
    fail("unknown_fixture", "fixture root has no approved JSON artifact");
  }
  const matches = root.files.filter((entry) => entry.path === relativeArtifact);
  const [match] = matches;
  if (matches.length !== 1 || !match) {
    fail("unregistered_artifact", "fixture JSON artifact is not listed exactly once by the registry");
  }
  return match;
}

async function loadArtifact(repoRoot: string, root: FixtureRoot): Promise<JsonRecord> {
  const compatibility = root.id === "source-audit-compatibility-gate";
  const artifact = record(
    await readJson(artifactPath(repoRoot, root), `fixture ${root.id}`, {
      registered: registeredArtifact(root),
      maxBytes: compatibility ? MAX_COMPATIBILITY_JSON_BYTES : MAX_JSON_BYTES,
      parserLimits: compatibility
        ? {
            maxDepth: MAX_COMPATIBILITY_JSON_DEPTH,
            maxNodes: MAX_COMPATIBILITY_JSON_NODES,
            maxStringBytes: MAX_COMPATIBILITY_STRING_BYTES,
          }
        : DEFAULT_JSON_LIMITS,
    }),
    `fixture ${root.id}`,
  );
  validateArtifactShape(root.id, artifact);
  return artifact;
}

export async function loadCase(repoRoot: string, registry: FixtureRegistry, rootId: string, caseId: string): Promise<FixtureCase> {
  if (!caseId || caseId.trim() !== caseId) {
    fail("malformed_input", "case ID must be a non-empty canonical string");
  }
  const root = rootById(registry, rootId);
  if (root.status !== "ready") {
    fail("coverage_pending", "pending fixture roots cannot provide parity evidence");
  }
  const artifact = await loadArtifact(await canonicalRepositoryRoot(repoRoot), root);
  const cases = array(artifact.cases, `fixture ${rootId}.cases`);
  const matches = cases.filter((entry) => isRecord(entry) && entry.id === caseId);
  if (matches.length !== 1) {
    fail("unknown_case", "representative case ID is absent or duplicated");
  }
  const raw = record(matches[0], `fixture ${rootId}.${caseId}`);
  return {
    id: string(raw.id, `fixture ${rootId}.${caseId}.id`),
    expected: record(raw.expected, `fixture ${rootId}.${caseId}.expected`),
    raw,
  };
}

function blockedCompatibilityRecord(status: string): CompatibilityRecord {
  const evidence = boundedOutputString(`blocked:${status}`, "compatibility blocked evidence");
  return {
    compatible: false,
    liveRun: false,
    deploymentAttestation: evidence,
    behavioralProbe: evidence,
    proxyProof: evidence,
    parityEvidence: evidence,
    benchmarkEvidence: evidence,
  };
}

function roundedBenchmarkValue(value: number): number {
  return Number(value.toFixed(3));
}

function validateCompatibilityBenchmark(
  value: JsonValue | undefined,
  mode: "normal" | "optimized",
  artifactDigest: string,
  artifactBytes: number,
): void {
  const label = `compatibility ${mode} benchmark`;
  const benchmark = exactRecord(value, label, COMPATIBILITY_BENCHMARK_KEYS);
  literal(benchmark.command, EXPECTED_COMPATIBILITY_BENCHMARK_COMMANDS[mode]!, `${label}.command`);
  literal(benchmark.commit, EXPECTED_COMPATIBILITY_INTEGRATION_HEAD, `${label}.commit`);
  const environment = exactRecord(benchmark.environment, `${label}.environment`, COMPATIBILITY_ENVIRONMENT_KEYS);
  string(environment.platform, `${label}.environment.platform`);
  string(environment.python, `${label}.environment.python`);
  literal(benchmark.artifact_set_sha256, artifactDigest, `${label}.artifact_set_sha256`);
  if (number(benchmark.artifact_size_bytes, `${label}.artifact_size_bytes`) !== artifactBytes) {
    fail("incompatible_input", `${label} artifact byte count is stale`);
  }
  const samples = array(benchmark.samples_ms, `${label}.samples_ms`);
  if (samples.length !== 30) fail("incompatible_input", `${label} must retain 30 samples`);
  const numericSamples = samples.map((sample, index) => finiteNumber(sample, `${label}.samples_ms[${index}]`));
  const ordered = [...numericSamples].sort((left, right) => left - right);
  const percentile = (fraction: number): number => ordered[Math.min(ordered.length - 1, Math.max(0, Math.ceil(fraction * ordered.length) - 1))]!;
  const expectedDistribution: Readonly<Record<string, number>> = {
    min: roundedBenchmarkValue(ordered[0]!),
    p50: roundedBenchmarkValue(percentile(0.5)),
    p95: roundedBenchmarkValue(percentile(0.95)),
    p99: roundedBenchmarkValue(percentile(0.99)),
    max: roundedBenchmarkValue(ordered[ordered.length - 1]!),
    mean: roundedBenchmarkValue(numericSamples.reduce((sum, sample) => sum + sample, 0) / numericSamples.length),
  };
  const distribution = exactRecord(benchmark.distribution, `${label}.distribution`, COMPATIBILITY_DISTRIBUTION_KEYS);
  for (const key of COMPATIBILITY_DISTRIBUTION_KEYS) {
    const actual = finiteNumber(distribution[key], `${label}.distribution.${key}`);
    if (actual !== expectedDistribution[key]) {
      fail("incompatible_input", `${label} distribution is stale`);
    }
  }
  if (benchmark.threshold !== null) fail("incompatible_input", `${label} threshold must remain null`);
}

function validateCompatibilityArtifact(artifact: JsonRecord): JsonRecord {
  const entry = exactRecord(artifact, "compatibility record", COMPATIBILITY_RECORD_KEYS);
  literal(entry.schema, "hermternal.compatibility-gate.v1", "compatibility schema");
  literal(entry.operation, "P0-02", "compatibility operation");
  literal(entry.contract, CONTRACT, "compatibility contract");

  const source = exactRecord(entry.source, "compatibility source", COMPATIBILITY_SOURCE_KEYS);
  literal(source.repository, "NousResearch/hermes-agent", "compatibility source repository");
  literal(source.sha, HERMES_SOURCE_SHA, "compatibility source revision");

  const merged = exactRecord(entry.merged_dev, "compatibility merged_dev", COMPATIBILITY_MERGED_KEYS);
  literal(merged.ref, "dev", "compatibility merged_dev.ref");
  literal(merged.head, EXPECTED_COMPATIBILITY_MERGED_HEAD, "compatibility merged_dev.head");
  literal(merged.tree, EXPECTED_COMPATIBILITY_MERGED_TREE, "compatibility merged_dev.tree");
  const mergedPrs = array(merged.merged_prs, "compatibility merged_dev.merged_prs");
  if (mergedPrs.length !== EXPECTED_COMPATIBILITY_MERGED_PRS.length) {
    fail("incompatible_input", "compatibility merged PR inventory changed");
  }
  for (const [index, expected] of EXPECTED_COMPATIBILITY_MERGED_PRS.entries()) {
    const mergedPr = exactRecord(mergedPrs[index], `compatibility merged_prs[${index}]`, COMPATIBILITY_MERGED_PR_KEYS);
    if (number(mergedPr.number, `compatibility merged_prs[${index}].number`) !== expected[0]) {
      fail("incompatible_input", "compatibility merged PR order or number changed");
    }
    literal(mergedPr.merge_commit, expected[1], `compatibility merged_prs[${index}].merge_commit`);
  }

  const integration = exactRecord(entry.integration_dev, "compatibility integration_dev", COMPATIBILITY_INTEGRATION_KEYS);
  literal(integration.ref, "dev", "compatibility integration_dev.ref");
  literal(integration.head, EXPECTED_COMPATIBILITY_INTEGRATION_HEAD, "compatibility integration_dev.head");
  literal(integration.tree, EXPECTED_COMPATIBILITY_INTEGRATION_TREE, "compatibility integration_dev.tree");

  const artifacts = exactRecord(entry.artifacts, "compatibility artifacts", COMPATIBILITY_ARTIFACTS_KEYS);
  literal(artifacts.algorithm, "sha256", "compatibility artifact algorithm");
  const artifactFiles = array(artifacts.files, "compatibility artifacts.files");
  if (artifactFiles.length !== EXPECTED_COMPATIBILITY_ARTIFACTS.length) {
    fail("incompatible_input", "compatibility artifact inventory changed");
  }
  let artifactBytes = 0;
  const artifactSet = createHash("sha256");
  for (const [index, expected] of EXPECTED_COMPATIBILITY_ARTIFACTS.entries()) {
    const file = exactRecord(artifactFiles[index], `compatibility artifacts.files[${index}]`, COMPATIBILITY_ARTIFACT_KEYS);
    const path = safeRelativePath(string(file.path, `compatibility artifacts.files[${index}].path`), `compatibility artifacts.files[${index}].path`);
    literal(path, expected.path, `compatibility artifacts.files[${index}].path`);
    const digest = string(file.sha256, `compatibility artifacts.files[${index}].sha256`);
    if (!SHA256_PATTERN.test(digest)) fail("malformed_input", "compatibility artifact digest is invalid");
    literal(digest, expected.sha256, `compatibility artifacts.files[${index}].sha256`);
    const sizeBytes = number(file.size_bytes, `compatibility artifacts.files[${index}].size_bytes`);
    if (sizeBytes !== expected.sizeBytes) {
      fail("incompatible_input", "compatibility artifact size changed");
    }
    artifactBytes += sizeBytes;
    // Match the focused validator's canonical NUL-delimited manifest digest so
    // coordinated mutations cannot preserve only the nested cross-references.
    artifactSet.update(`${path}\0${digest}\0${sizeBytes}\n`, "utf8");
  }
  const artifactDigest = string(artifacts.set_sha256, "compatibility artifacts.set_sha256");
  if (!SHA256_PATTERN.test(artifactDigest)) fail("malformed_input", "compatibility artifact-set digest is invalid");
  if (artifactSet.digest("hex") !== artifactDigest) {
    fail("incompatible_input", "compatibility artifact-set digest is stale");
  }

  const observations = exactRecord(entry.observations, "compatibility observations", COMPATIBILITY_OBSERVATIONS_KEYS);
  if (number(observations.artifact_size_bytes, "compatibility observations.artifact_size_bytes") !== artifactBytes) {
    fail("incompatible_input", "compatibility observed artifact byte count is stale");
  }
  literal(observations.artifact_set_sha256, artifactDigest, "compatibility observations.artifact_set_sha256");
  if (number(observations.repetitions, "compatibility observations.repetitions") !== 30) {
    fail("incompatible_input", "compatibility observations must retain 30 repetitions");
  }
  const durations = exactRecord(observations.validator_duration_ms, "compatibility validator durations", ["normal", "optimized"]);
  validateCompatibilityBenchmark(durations.normal, "normal", artifactDigest, artifactBytes);
  validateCompatibilityBenchmark(durations.optimized, "optimized", artifactDigest, artifactBytes);

  const status = exactRecord(entry.status, "compatibility status", COMPATIBILITY_STATUS_KEYS);
  for (const key of COMPATIBILITY_STATUS_KEYS) {
    if (status[key] !== EXPECTED_COMPATIBILITY_STATUS[key]) {
      fail("incompatible_input", "compatibility status contains non-canonical evidence");
    }
  }
  const redaction = exactRecord(entry.redaction, "compatibility redaction", COMPATIBILITY_REDACTION_KEYS);
  if (boolean(redaction.synthetic_only, "compatibility redaction.synthetic_only") !== true) {
    fail("live_input", "compatibility redaction is not synthetic-only");
  }
  for (const key of COMPATIBILITY_REDACTION_KEYS.slice(1)) {
    if (boolean(redaction[key], `compatibility redaction.${key}`) !== false) {
      fail("live_input", "compatibility redaction permits retained sensitive data");
    }
  }
  const blockers = strings(entry.blockers, "compatibility blockers");
  if (!sameStringList(blockers, EXPECTED_COMPATIBILITY_BLOCKERS)) {
    fail("incompatible_input", "compatibility blockers changed");
  }
  return status;
}

export async function loadCompatibilityRecord(repoRoot: string, registry: FixtureRegistry): Promise<CompatibilityRecord> {
  const root = rootById(registry, "source-audit-compatibility-gate");
  const canonicalCoverage = coverageById(registry, "compatibility-gate");
  if (
    !root.coverageIds.includes(canonicalCoverage.id)
    || !canonicalCoverage.fixtureIds.includes(root.id)
  ) {
    fail("fixture_inventory_invalid", "aggregate compatibility root must own compatibility-gate coverage");
  }
  const coverageStatuses = root.coverageIds.map((coverageId) => coverageById(registry, coverageId).status);
  const blockedStatus = coverageStatuses.find((status) => status !== "ready")
    ?? (root.status === "pending" ? "pending" : undefined);
  if (blockedStatus) {
    // A pending root has no artifact to load by design. Keep the aggregate
    // compatibility record explicit and bounded instead of inventing evidence
    // or reporting the empty manifest as an unregistered artifact.
    return blockedCompatibilityRecord(blockedStatus);
  }

  const artifact = await loadArtifact(await canonicalRepositoryRoot(repoRoot), root);
  const status = validateCompatibilityArtifact(artifact);
  return {
    compatible: false,
    liveRun: false,
    deploymentAttestation: boundedOutputString(status.deployment_attestation, "compatibility deployment attestation"),
    behavioralProbe: boundedOutputString(status.behavioral_probe, "compatibility behavioral probe"),
    proxyProof: boundedOutputString(status.proxy_proof, "compatibility proxy proof"),
    parityEvidence: boundedOutputString(status.parity_evidence, "compatibility parity evidence"),
    benchmarkEvidence: boundedOutputString(status.benchmark_evidence, "compatibility benchmark evidence"),
  };
}

function sorted(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(sorted);
  }
  if (isRecord(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key] ?? null)]));
  }
  return value;
}

function decision(expected: JsonRecord): string {
  for (const key of ["decision", "state", "final_state", "attestation_result", "runtime_gate", "valid"]) {
    const value = expected[key];
    if (typeof value === "string") {
      return boundedOutputString(value, `expected.${key}`);
    }
    if (typeof value === "boolean") {
      return value ? "valid" : "blocked";
    }
  }
  for (const key of ["pty_bytes_logged", "raw_bytes_logged"]) {
    const value = expected[key];
    if (typeof value === "boolean") {
      return value ? "logged" : "redacted";
    }
  }
  fail("malformed_input", "representative expected result has no semantic decision");
}

function project(family: Family, platformName: Platform, fixtureCase: FixtureCase): ProjectedOutcome {
  return {
    family,
    caseId: fixtureCase.id,
    platform: platformName,
    decision: decision(fixtureCase.expected),
    semantic: record(sorted(fixtureCase.expected), "semantic expected result"),
  };
}

function equalJson(left: JsonValue, right: JsonValue): boolean {
  return JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
}

async function runRepresentative(
  repoRoot: string,
  registry: FixtureRegistry,
  representative: Representative,
): Promise<ParityCaseResult[]> {
  const coverage = coverageById(registry, representative.coverageId);
  if (!coverage.fixtureIds.includes(representative.rootId)) {
    fail("incompatible_input", "coverage row does not own its representative fixture root");
  }
  const root = rootById(registry, representative.rootId);
  if (coverage.status !== "ready") {
    const results: ParityCaseResult[] = [];
    for (const caseId of representative.caseIds) {
      if (coverage.status === "pending" && root.status === "ready") {
        const fixtureCase = await loadCase(repoRoot, registry, representative.rootId, caseId);
        if (representative.family === "chat" && !["delivery_uncertain", "automatic_prompt_retry_blocked"].includes(decision(fixtureCase.expected))) {
          fail("incompatible_input", "pending chat coverage contains an unexpected success decision");
        }
      }
      results.push({
        family: representative.family,
        coverageId: representative.coverageId,
        caseId,
        status: "blocked",
        platforms: coverage.platforms,
      });
    }
    return results;
  }

  if (root.status !== "ready") {
    fail("coverage_pending", "ready coverage references a pending fixture root");
  }
  const results: ParityCaseResult[] = [];
  for (const caseId of representative.caseIds) {
    const fixtureCase = await loadCase(repoRoot, registry, representative.rootId, caseId);
    const web = coverage.platforms.includes("web") ? project(representative.family, "web", fixtureCase) : undefined;
    const applePlatform = coverage.platforms.includes("ios") ? "ios" : coverage.platforms.includes("ipados") ? "ipados" : "macos";
    const apple = coverage.platforms.includes(applePlatform) ? project(representative.family, applePlatform, fixtureCase) : undefined;

    if (representative.family === "pty") {
      if (!web || coverage.platforms.length !== 1 || coverage.platforms[0] !== "web") {
        fail("incompatible_input", "PTY parity must be a web-only fixture");
      }
      results.push({
        family: representative.family,
        coverageId: representative.coverageId,
        caseId,
        status: "proven",
        platforms: coverage.platforms,
        webDecision: web.decision,
        appleDecision: "blocked_platform",
      });
      continue;
    }

    if (!web || !apple || !equalJson(web.semantic, apple.semantic)) {
      fail("parity_mismatch", "shared fixture semantic outcomes differ by platform");
    }
    results.push({
      family: representative.family,
      coverageId: representative.coverageId,
      caseId,
      status: "proven",
      platforms: coverage.platforms,
      webDecision: web.decision,
      appleDecision: apple.decision,
    });
  }
  return results;
}

export async function runParity(repoRoot: string): Promise<ParityReport> {
  const canonicalRoot = await canonicalRepositoryRoot(repoRoot);
  const registry = await loadRegistry(canonicalRoot);
  await validateRegistryInventory(canonicalRoot, registry);
  literal(registry.parity.ptyPolicy, "web_only_apple_blocked", "parity PTY policy");
  literal(registry.parity.missingResultPolicy, "block", "parity missing-result policy");
  literal(registry.parity.resultEquivalence, "semantic_outcomes_not_platform_specific_wire_bytes", "parity equivalence policy");

  const cases: ParityCaseResult[] = [];
  for (const representative of REPRESENTATIVES) {
    cases.push(...(await runRepresentative(canonicalRoot, registry, representative)));
  }
  const compatibility = await loadCompatibilityRecord(canonicalRoot, registry);
  if (cases.length > MAX_OUTPUT_CASES) {
    fail("output_limit", "parity report contains too many case results");
  }
  const blockedCoverage = registry.coverage.filter((entry) => entry.status !== "ready");
  if (blockedCoverage.length > MAX_OUTPUT_COVERAGE_IDS) {
    fail("output_limit", "parity report contains too many blocked coverage IDs");
  }
  const blockedCoverageIds = blockedCoverage.map((entry, index) =>
    boundedOutputString(entry.id, `blockedCoverageIds[${index}]`),
  );
  const report: ParityReport = {
    ok: true,
    contract: CONTRACT,
    hermesSourceSha: HERMES_SOURCE_SHA,
    syntheticOnly: true,
    liveClaim: false,
    networkCalls: 0,
    readyCaseCount: cases.filter((entry) => entry.status === "proven").length,
    blockedCoverageIds,
    cases,
    compatibility,
  };
  if (utf8Bytes(JSON.stringify(report)) > MAX_REPORT_BYTES) {
    fail("output_limit", "serialized parity report exceeds the bounded UTF-8 byte budget");
  }
  return report;
}

export function repoRootFromModule(moduleDirectory: string): string {
  return resolve(moduleDirectory, "../../..");
}

export function assertRejects(error: unknown, code: string): void {
  if (!(error instanceof ContractInputError) || error.code !== code) {
    fail("regression_failure", `expected ${code} rejection`);
  }
}

export function representativeIds(): readonly Representative[] {
  return REPRESENTATIVES;
}

export function assertNoNetworkImports(sourceText: string): void {
  if (/\b(fetch|WebSocket|XMLHttpRequest|net|https?\.request|connect)\s*\(/.test(sourceText)) {
    fail("network_boundary", "parity tooling must not open a network connection");
  }
}
