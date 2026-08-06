import { createHash } from "node:crypto";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { resolve, normalize, isAbsolute, join } from "node:path";

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
const MAX_OUTPUT_STRING_LENGTH = 256;
const MAX_OUTPUT_CASES = 64;
const MAX_OUTPUT_COVERAGE_IDS = 64;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

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

export class ContractInputError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ContractInputError";
    this.code = code;
  }
}

interface RegistryFile {
  readonly path: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

interface FixtureRoot {
  readonly id: string;
  readonly path: string;
  readonly status: "ready" | "pending";
  readonly contract: string;
  readonly hermesSourceSha: string;
  readonly syntheticOnly: true;
  readonly liveClaim: false;
  readonly platforms: readonly Platform[];
  readonly states: readonly string[];
  readonly coverageIds: readonly string[];
  readonly validator: string;
  readonly files: readonly RegistryFile[];
}

interface CoverageRow {
  readonly id: string;
  readonly status: "ready" | "pending";
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
  readonly fixtureRoots: readonly FixtureRoot[];
  readonly coverage: readonly CoverageRow[];
  readonly parity: RegistryParity;
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
const COMPATIBILITY_RECORD_KEYS = ["schema", "operation", "contract", "source", "merged_dev", "integration_dev", "artifacts", "observations", "status", "redaction", "blockers"] as const;
const COMPATIBILITY_SOURCE_KEYS = ["repository", "sha"] as const;
const COMPATIBILITY_STATUS_KEYS = ["compatible", "live_run", "deployment_attestation", "behavioral_probe", "proxy_proof", "parity_evidence", "benchmark_evidence"] as const;

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

function literal(value: JsonValue | undefined, expected: string, label: string): void {
  if (value !== expected) {
    fail("incompatible_input", `${label} does not match the reviewed contract`);
  }
}

function safeRelativePath(value: string, label: string): string {
  if (
    isAbsolute(value) ||
    value.includes("://") ||
    value.includes("\\") ||
    value === "" ||
    normalize(value) !== value ||
    value === "." ||
    value.startsWith("../") ||
    value.includes("/../")
  ) {
    fail("unsafe_path", `${label} is not a safe repository-relative path`);
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

// JSON.parse cannot reject duplicate keys and recursively consumes unbounded input.
// This parser accounts for every value before descending and never guesses on syntax.
class BoundedJsonParser {
  private index = 0;
  private nodes = 0;
  private arrays = 0;
  private objects = 0;
  private strings = 0;

  constructor(private readonly text: string, private readonly label: string) {}

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
    if (depth > MAX_JSON_DEPTH) {
      fail("json_depth_limit", `${this.label} exceeds the bounded JSON depth`);
    }
    this.nodes += 1;
    if (this.nodes > MAX_JSON_NODES) {
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
      if (result.length > MAX_JSON_STRING_LENGTH) {
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
    this.index += match[0].length;
    const value = Number(match[0]);
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

function parseJson(text: string, label: string): JsonValue {
  return new BoundedJsonParser(text, label).parse();
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// Check both the path and the opened handle. This closes the common replacement
// race without allocating or hashing bytes from an oversized or unregistered file.
async function readBoundedBytes(path: string, label: string, registered?: RegistryFile): Promise<Uint8Array> {
  let handle: FileHandle | undefined;
  try {
    let pathStats;
    try {
      pathStats = await lstat(path);
    } catch {
      fail("missing_artifact", `${label} is not checked in`);
    }
    if (!pathStats.isFile()) {
      fail("unsafe_artifact", `${label} is not a regular file`);
    }
    if (registered && pathStats.size !== registered.sizeBytes) {
      fail("artifact_size_mismatch", `${label} does not match its registered byte size`);
    }
    if (pathStats.size > MAX_JSON_BYTES) {
      fail("json_too_large", `${label} exceeds the bounded artifact size`);
    }

    try {
      handle = await open(path, "r");
    } catch {
      fail("artifact_read_failed", `${label} could not be opened`);
    }
    const stats = await handle.stat();
    if (!stats.isFile()) {
      fail("unsafe_artifact", `${label} is not a regular file`);
    }
    if (registered && stats.size !== registered.sizeBytes) {
      fail("artifact_size_mismatch", `${label} does not match its registered byte size`);
    }
    if (stats.size > MAX_JSON_BYTES) {
      fail("json_too_large", `${label} exceeds the bounded artifact size`);
    }

    const bytes = new Uint8Array(stats.size);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead === 0) {
        fail("artifact_changed", `${label} ended before its declared byte size`);
      }
      offset += result.bytesRead;
    }
    const finalStats = await handle.stat();
    if (finalStats.size !== stats.size) {
      fail("artifact_changed", `${label} changed while it was being read`);
    }
    if (registered && sha256(bytes) !== registered.sha256) {
      fail("artifact_hash_mismatch", `${label} does not match its registered SHA-256`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof ContractInputError) throw error;
    return fail("artifact_read_failed", `${label} could not be read as bounded UTF-8 JSON`);
  } finally {
    if (handle) await handle.close().catch(() => undefined);
  }
}

async function readJson(path: string, label: string, registered?: RegistryFile): Promise<JsonValue> {
  const bytes = await readBoundedBytes(path, label, registered);
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("malformed_utf8", `${label} is not valid UTF-8`);
  }
  return parseJson(text, label);
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
  return {
    id: string(entry.id, `fixture_roots[${index}].id`),
    path: safeRelativePath(string(entry.path, `fixture_roots[${index}].path`), `fixture_roots[${index}].path`),
    status,
    contract: string(entry.contract, `fixture_roots[${index}].contract`),
    hermesSourceSha: string(entry.hermes_source_sha, `fixture_roots[${index}].hermes_source_sha`),
    syntheticOnly: boolean(entry.synthetic_only, `fixture_roots[${index}].synthetic_only`) as true,
    liveClaim: boolean(entry.live_claim, `fixture_roots[${index}].live_claim`) as false,
    platforms: platforms(entry.platforms, `fixture_roots[${index}].platforms`),
    states: strings(entry.states, `fixture_roots[${index}].states`),
    coverageIds: strings(entry.coverage_ids, `fixture_roots[${index}].coverage_ids`),
    validator: string(entry.validator, `fixture_roots[${index}].validator`),
    files,
  };
}

function parseCoverage(value: JsonValue | undefined, index: number): CoverageRow {
  const entry = exactRecord(value, `coverage[${index}]`, COVERAGE_KEYS);
  const status = string(entry.status, `coverage[${index}].status`);
  if (status !== "ready" && status !== "pending") {
    fail("unknown_status", `coverage[${index}].status is unknown`);
  }
  return {
    id: string(entry.id, `coverage[${index}].id`),
    status,
    fixtureIds: strings(entry.fixture_ids, `coverage[${index}].fixture_ids`),
    platforms: platforms(entry.platforms, `coverage[${index}].platforms`),
    requiredStates: strings(entry.required_states, `coverage[${index}].required_states`),
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

export async function loadRegistry(repoRoot: string): Promise<FixtureRegistry> {
  const root = resolve(repoRoot);
  const raw = exactRecord(
    await readJson(join(root, "contracts/fixtures/index.json"), "fixture index"),
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

  const fixtureRoots = array(raw.fixture_roots, "fixture_roots").map(parseFixtureRoot);
  const coverage = array(raw.coverage, "coverage").map(parseCoverage);
  if (new Set(fixtureRoots.map((entry) => entry.id)).size !== fixtureRoots.length) {
    fail("malformed_input", "fixture root IDs are not unique");
  }
  if (new Set(coverage.map((entry) => entry.id)).size !== coverage.length) {
    fail("malformed_input", "coverage IDs are not unique");
  }
  for (const entry of fixtureRoots) {
    if (entry.contract !== CONTRACT || entry.hermesSourceSha !== HERMES_SOURCE_SHA) {
      fail("incompatible_input", "fixture root is not pinned to the reviewed contract");
    }
    if (entry.syntheticOnly !== true || entry.liveClaim !== false) {
      fail("live_input", "fixture root is not synthetic-only");
    }
  }
  const rootIds = new Set(fixtureRoots.map((entry) => entry.id));
  for (const entry of coverage) {
    if (entry.status === "ready" && entry.fixtureIds.some((id) => !rootIds.has(id))) {
      fail("unknown_fixture", "ready coverage references an unknown fixture root");
    }
  }
  const parity = parseParity(raw.parity);
  if (parity.liveClaim !== false || parity.fixtureSource !== "one_shared_registry") {
    fail("incompatible_input", "parity policy is not the shared synthetic policy");
  }
  return { fixtureRoots, coverage, parity };
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
  const artifact = record(
    await readJson(artifactPath(repoRoot, root), `fixture ${root.id}`, registeredArtifact(root)),
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
  const artifact = await loadArtifact(repoRoot, root);
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

export async function loadCompatibilityRecord(repoRoot: string, registry: FixtureRegistry): Promise<CompatibilityRecord> {
  const root = rootById(registry, "source-audit-compatibility-gate");
  const artifact = await loadArtifact(repoRoot, root);
  literal(artifact.schema, "hermternal.compatibility-gate.v1", "compatibility schema");
  const source = exactRecord(artifact.source, "compatibility source", COMPATIBILITY_SOURCE_KEYS);
  literal(source.sha, HERMES_SOURCE_SHA, "compatibility source revision");
  const status = exactRecord(artifact.status, "compatibility status", COMPATIBILITY_STATUS_KEYS);
  if (boolean(status.compatible, "compatibility status.compatible") !== false) {
    fail("live_claim", "compatibility record claims compatibility without live evidence");
  }
  if (boolean(status.live_run, "compatibility status.live_run") !== false) {
    fail("live_input", "compatibility record contains live-run evidence");
  }
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
  if (coverage.status === "pending") {
    const results: ParityCaseResult[] = [];
    for (const caseId of representative.caseIds) {
      const fixtureCase = await loadCase(repoRoot, registry, representative.rootId, caseId);
      if (representative.family === "chat" && !["delivery_uncertain", "automatic_prompt_retry_blocked"].includes(decision(fixtureCase.expected))) {
        fail("incompatible_input", "pending chat coverage contains an unexpected success decision");
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

  const root = rootById(registry, representative.rootId);
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
  const registry = await loadRegistry(repoRoot);
  literal(registry.parity.ptyPolicy, "web_only_apple_blocked", "parity PTY policy");
  literal(registry.parity.missingResultPolicy, "block", "parity missing-result policy");
  literal(registry.parity.resultEquivalence, "semantic_outcomes_not_platform_specific_wire_bytes", "parity equivalence policy");

  const cases: ParityCaseResult[] = [];
  for (const representative of REPRESENTATIVES) {
    cases.push(...(await runRepresentative(repoRoot, registry, representative)));
  }
  const compatibility = await loadCompatibilityRecord(repoRoot, registry);
  if (cases.length > MAX_OUTPUT_CASES) {
    fail("output_limit", "parity report contains too many case results");
  }
  const blockedCoverage = registry.coverage.filter((entry) => entry.status === "pending");
  if (blockedCoverage.length > MAX_OUTPUT_COVERAGE_IDS) {
    fail("output_limit", "parity report contains too many blocked coverage IDs");
  }
  const blockedCoverageIds = blockedCoverage.map((entry, index) =>
    boundedOutputString(entry.id, `blockedCoverageIds[${index}]`),
  );
  return {
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
