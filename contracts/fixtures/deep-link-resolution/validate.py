"""Validate deterministic synthetic deep-link resolver traces offline.

The proof reads checked-in JSON and one pinned grammar module. It never opens a
socket, contacts Hermes, reads a transcript store, creates a session, or shares
a link. Resolver state is reduced from inert event strings so fixture data
cannot execute code.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
import sys
from typing import Any, Callable, Mapping


FIXTURE_DIR = Path(__file__).resolve().parent
REPO_ROOT = FIXTURE_DIR.parents[2]
SCHEMA = "hermternal.deep-link-resolution.v1"
BASELINE_SCHEMA = "hermternal.deep-link-resolution-baseline.v1"
EVIDENCE_SCHEMA = "hermternal.deep-link-resolution-baseline-evidence.v1"
CONTRACT = "dashboard-v0.0.1"
OPERATION = "C-16"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PENDING_TTL_SECONDS = 300
ERROR_PAYLOAD = {"error": {"code": "contract", "message": "deep-link resolution fixture rejected"}}

MAX_FILE_BYTES = 1_048_576
MAX_STRING_BYTES = 4_096
MAX_CONTAINER_ITEMS = 256
MAX_NODES = 50_000
MAX_DEPTH = 32
MAX_INTEGER = 1_000_000_000
MAX_FLOAT = 1_000_000_000.0

DEPENDENCIES = {
    "deep-link-grammar/cases.json": "91fad69ec110ea8042678b963076056b4474072d24f9698067ed8bfc10c03d96",
    "deep-link-grammar/validate.py": "c01cc7958ebd573fa336d72de551e9c4b45e27397c6a38f5012eff35edff314e",
    "session-lineage/cases.json": "ebd320005dea1623b691346ef6b2b38a60fb510c7b4ed16855c02e9d395540ea",
    "session-lineage/validation-baseline.json": "c62ffce8836f873c03143d2716b83e99db1843083bef82d5697cd5a613f88b3d",
}

ROOT_ID = "session-root-0000000000000000000000000000000000000001"
BRANCH_ID = "session-branch-0000000000000000000000000000000000000002"
MESSAGE_ID = "synthetic-message-anchor-00000000000000000000000000000001"
CASE_IDS = (
    "authenticated-exact-root-direct-load",
    "authenticated-message-anchor-focus",
    "latest-descendant-preserves-lineage",
    "unknown-session-safe-not-found",
    "unauthorized-session-safe-not-found",
    "message-not-found-opens-session",
    "pending-auth-resolves-and-clears",
    "pending-target-expires",
    "logout-clears-pending-target",
    "direct-reload-idempotent-reopen",
    "interrupted-lookup-recovers",
    "invalid-private-https-origin",
    "invalid-hermternal-authority",
    "empty-no-target",
    "latest-descendant-message-focus",
)

# These identities are filled after reviewed generation. Source normalization
# replaces their values, so rebinding a manifest still changes the normalized
# validator digest unless the behavior itself is unchanged.
CASES_SHA256 = "114ddc9c752683a7c4604f0cbd04f05bb8e35f7df60aa24ebca0ec48653e3613"
BASELINE_SHA256 = "f144479c36852dd0193ef66669b6b67cd7b7f6d2f0e2aaf68596911c909ee313"
NORMALIZED_VALIDATOR_SHA256 = "f353f1aa534ccdfbeda335f83bbd3d740e692c924d7e0ee7645009a7cdf69561"


class ContractError(ValueError):
    """A fixed-output contract rejection."""


def require(condition: bool, message: str = "contract rejected") -> None:
    """Keep validation active in normal and optimized interpreters."""

    if not condition:
        raise ContractError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ContractError("non-finite number")


def validate_tree(root: Any) -> None:
    """Validate JSON bounds iteratively to avoid recursive parser walks."""

    stack: list[tuple[Any, int]] = [(root, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        require(nodes <= MAX_NODES, "node bound")
        require(depth <= MAX_DEPTH, "depth bound")
        value_type = type(value)
        if value is None or value_type is bool:
            continue
        if value_type is str:
            require(len(value.encode("utf-8")) <= MAX_STRING_BYTES, "string bound")
            continue
        if value_type is int:
            require(abs(value) <= MAX_INTEGER, "integer overflow")
            continue
        if value_type is float:
            require(math.isfinite(value) and abs(value) <= MAX_FLOAT, "float overflow")
            continue
        if value_type is list:
            require(len(value) <= MAX_CONTAINER_ITEMS, "list bound")
            for item in reversed(value):
                stack.append((item, depth + 1))
            continue
        if value_type is dict:
            require(len(value) <= MAX_CONTAINER_ITEMS, "object bound")
            for key, item in value.items():
                require(type(key) is str, "key type")
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
            continue
        raise ContractError("unsupported type")


def load_json(path: Path) -> Any:
    """Load bounded UTF-8 JSON with duplicate and non-finite rejection."""

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ContractError("read failed") from exc
    require(len(data) <= MAX_FILE_BYTES, "byte bound")
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ContractError) as exc:
        raise ContractError("json rejected") from exc
    validate_tree(document)
    return document


def strict_equal(actual: Any, expected: Any) -> bool:
    """Compare exact JSON types without bool/int coercion or recursion."""

    pending: list[tuple[Any, Any]] = [(actual, expected)]
    while pending:
        left, right = pending.pop()
        if type(left) is not type(right):
            return False
        if type(left) is dict:
            if list(left) != list(right):
                return False
            pending.extend((left[key], right[key]) for key in left)
        elif type(left) is list:
            if len(left) != len(right):
                return False
            pending.extend(zip(left, right))
        elif left != right:
            return False
    return True


def _dependency_path(name: str) -> Path:
    return REPO_ROOT / "contracts" / "fixtures" / name


def verify_dependencies(document: Mapping[str, Any]) -> None:
    """Bind resolver evidence to exact grammar and lineage artifact bytes."""

    identities = document["dependencies"]
    require(type(identities) is dict and list(identities) == list(DEPENDENCIES), "dependency inventory")
    for name, digest in DEPENDENCIES.items():
        path = _dependency_path(name)
        require(identities[name] == {"sha256": digest}, "dependency identity")
        require(sha256_bytes(path.read_bytes()) == digest, "dependency drift")


def load_grammar_module() -> Any:
    """Load only the pinned local parser; fixture event data remains inert."""

    path = _dependency_path("deep-link-grammar/validate.py")
    spec = importlib.util.spec_from_file_location("deep_link_grammar_contract", path)
    require(spec is not None and spec.loader is not None, "grammar unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def lineage_inventory() -> dict[str, tuple[str, str | None]]:
    """Extract reviewed exact identities from the pinned lineage cases."""

    document = load_json(_dependency_path("session-lineage/cases.json"))
    found: dict[str, tuple[str, str | None]] = {}
    for case in document["cases"]:
        expected = case["expected"]
        session_id = expected["session_id"]
        if session_id in {ROOT_ID, BRANCH_ID} and expected["durable"] is True:
            found[session_id] = (expected["root_id"], expected["parent_id"])
    require(found == {ROOT_ID: (ROOT_ID, None), BRANCH_ID: (ROOT_ID, ROOT_ID)}, "lineage binding")
    return found


@dataclass
class Resolver:
    """Small deterministic reducer for synthetic resolver events."""

    requested_session_id: str | None
    message_id: str | None
    authenticated: bool
    lookup_mode: str
    valid_target: bool
    state: str = "idle"
    pending_target: bool = False
    opened_session_id: str | None = None
    root_id: str | None = None
    parent_id: str | None = None
    focus: str = "none"
    decision: str = "pending"
    lookup_attempts: int = 0
    state_trace: list[str] | None = None
    effects: list[str] | None = None

    def __post_init__(self) -> None:
        self.state_trace = [self.state]
        self.effects = []

    def transition(self, state: str) -> None:
        if self.state != state:
            self.state = state
            self.state_trace.append(state)

    def clear(self, effect: str) -> None:
        self.pending_target = False
        self.effects.append(effect)

    def apply(self, event: str, lineage: Mapping[str, tuple[str, str | None]]) -> None:
        if event == "receive":
            if not self.valid_target:
                self.effects.append("grammar_rejected_before_lookup")
                self.decision = "invalid_link"
                self.transition("failed")
                self.clear("pending_target_cleared")
            elif self.authenticated:
                self.pending_target = True
                self.lookup_attempts += 1
                self.effects.extend(("validated_target_held_in_memory", "authenticated_lookup_started"))
                self.transition("lookup_pending")
            else:
                self.pending_target = True
                self.effects.append("validated_target_held_in_memory")
                self.transition("auth_pending")
            return
        if event == "authenticated":
            require(self.state == "auth_pending" and self.pending_target, "auth state")
            self.authenticated = True
            self.lookup_attempts += 1
            self.effects.append("authenticated_lookup_started")
            self.transition("lookup_pending")
            return
        if event == "lookup_present":
            require(self.state == "lookup_pending" and self.pending_target, "lookup state")
            target = BRANCH_ID if self.lookup_mode == "latest_descendant" else self.requested_session_id
            require(target in lineage, "lookup identity")
            self.opened_session_id = target
            self.root_id, self.parent_id = lineage[target]
            self.effects.append("exact_full_id_resolved")
            if self.lookup_mode == "latest_descendant":
                self.effects.extend(("latest_descendant_selected", "lineage_preserved"))
            self.transition("session_open")
            return
        if event in {"lookup_missing", "lookup_denied"}:
            require(self.state == "lookup_pending", "not-found state")
            self.opened_session_id = None
            self.root_id = None
            self.parent_id = None
            self.decision = "session_not_found"
            self.effects.extend(("authorization_safe_session_not_found", "no_session_created"))
            self.transition("failed")
            self.clear("pending_target_cleared")
            return
        if event == "message_present":
            require(self.state == "session_open" and self.message_id is not None, "message state")
            self.focus = "message"
            self.decision = "message_focused"
            self.effects.append("message_anchor_focused")
            self.transition("opened")
            self.clear("pending_target_cleared")
            return
        if event == "message_missing":
            require(self.state == "session_open" and self.message_id is not None, "message fallback state")
            self.focus = "session_start"
            self.decision = "message_not_found"
            self.effects.extend(("session_opened", "message_not_found_fallback"))
            self.transition("opened")
            self.clear("pending_target_cleared")
            return
        if event == "complete":
            require(self.state == "session_open" and self.message_id is None, "complete state")
            self.focus = "session"
            self.decision = "session_opened"
            self.effects.append("session_opened")
            self.transition("opened")
            self.clear("pending_target_cleared")
            return
        if event == "reload":
            require(self.state == "opened", "reload state")
            self.pending_target = True
            self.lookup_attempts += 1
            self.effects.extend(("direct_reload", "idempotent_reopen"))
            self.transition("lookup_pending")
            return
        if event == "interrupt":
            require(self.state == "lookup_pending", "interrupt state")
            self.effects.append("lookup_interrupted_safe_state")
            self.transition("interrupted")
            return
        if event == "recover":
            require(self.state == "interrupted" and self.pending_target, "recover state")
            self.lookup_attempts += 1
            self.effects.append("authenticated_lookup_retried_idempotently")
            self.transition("lookup_pending")
            return
        if event == "expire":
            require(self.pending_target and self.state in {"auth_pending", "lookup_pending", "interrupted"}, "expiry state")
            self.decision = "target_expired"
            self.transition("expired")
            self.clear("pending_target_cleared")
            return
        if event == "logout":
            require(self.pending_target, "logout state")
            self.authenticated = False
            self.decision = "signed_out"
            self.transition("signed_out")
            self.clear("pending_target_cleared")
            return
        raise ContractError("unknown event")

    def result(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "final_state": self.state,
            "state_trace": self.state_trace,
            "effects": self.effects,
            "requested_session_id": self.requested_session_id if self.valid_target else None,
            "opened_session_id": self.opened_session_id,
            "root_id": self.root_id,
            "parent_id": self.parent_id,
            "message_id": self.message_id if self.valid_target else None,
            "focus": self.focus,
            "pending_target": self.pending_target,
            "lookup_attempts": self.lookup_attempts,
            "session_creations": 0,
            "shares": 0,
            "transcript_mirror": False,
            "network": False,
        }


def reduce_case(case: Mapping[str, Any], grammar: Any, lineage: Mapping[str, tuple[str, str | None]]) -> dict[str, Any]:
    link = case["link"]
    if link is None:
        valid = False
        session_id = None
        message_id = None
    else:
        parsed = grammar.parse_link(link)
        valid = parsed.valid
        session_id = parsed.session_id
        message_id = parsed.message_id
    resolver = Resolver(session_id, message_id, case["authenticated"], case["lookup_mode"], valid)
    for event in case["events"]:
        resolver.apply(event, lineage)
    return resolver.result()


ROOT_KEYS = [
    "schema", "operation", "contract", "hermes_source_sha", "synthetic_only",
    "network", "pending_ttl_seconds", "dependencies", "invariants", "cases", "redaction",
]
CASE_KEYS = ["id", "link", "authenticated", "lookup_mode", "events", "expected", "notes"]
EXPECTED_KEYS = [
    "decision", "final_state", "state_trace", "effects", "requested_session_id",
    "opened_session_id", "root_id", "parent_id", "message_id", "focus",
    "pending_target", "lookup_attempts", "session_creations", "shares",
    "transcript_mirror", "network",
]
INVARIANTS = {
    "exact_ids": "full opaque IDs are preserved without normalization",
    "lookup": "authenticated Dashboard lookup only",
    "latest_descendant": "selected descendant keeps exact root and parent lineage",
    "authorization": "missing and denied share one session-not-found outcome",
    "message_anchor": "focus exact message or open session with message-not-found fallback",
    "pending_target": "memory only; clear on success, failure, expiry, cancellation, or logout",
    "creation": False,
    "sharing": False,
    "local_transcript_mirror": False,
}
REDACTION = {
    "synthetic_only": True,
    "raw_links_in_errors": False,
    "raw_ids_in_errors": False,
    "fixed_error": ERROR_PAYLOAD,
}


def validate_expected(value: Any) -> None:
    require(type(value) is dict and list(value) == EXPECTED_KEYS, "expected shape")
    string_or_none = ("requested_session_id", "opened_session_id", "root_id", "parent_id", "message_id")
    for key in string_or_none:
        require(value[key] is None or type(value[key]) is str, "identity type")
    for key in ("decision", "final_state", "focus"):
        require(type(value[key]) is str, "string type")
    for key in ("state_trace", "effects"):
        require(type(value[key]) is list and all(type(item) is str for item in value[key]), "list type")
    require(type(value["pending_target"]) is bool, "pending type")
    for key in ("lookup_attempts", "session_creations", "shares"):
        require(type(value[key]) is int and 0 <= value[key] <= 10, "counter type")
    require(value["transcript_mirror"] is False and value["network"] is False, "offline invariant")
    require(value["session_creations"] == 0 and value["shares"] == 0, "side-effect invariant")


def validate_document(document: Mapping[str, Any]) -> None:
    require(type(document) is dict and list(document) == ROOT_KEYS, "root shape")
    require(document["schema"] == SCHEMA and document["operation"] == OPERATION, "schema pin")
    require(document["contract"] == CONTRACT and document["hermes_source_sha"] == HERMES_SOURCE_SHA, "contract pin")
    require(document["synthetic_only"] is True and document["network"] is False, "scope pin")
    require(type(document["pending_ttl_seconds"]) is int and document["pending_ttl_seconds"] == PENDING_TTL_SECONDS, "ttl pin")
    require(strict_equal(document["invariants"], INVARIANTS), "invariant drift")
    require(strict_equal(document["redaction"], REDACTION), "redaction drift")
    verify_dependencies(document)
    cases = document["cases"]
    require(type(cases) is list and [case.get("id") if type(case) is dict else None for case in cases] == list(CASE_IDS), "case inventory")
    grammar = load_grammar_module()
    lineage = lineage_inventory()
    for case in cases:
        require(type(case) is dict and list(case) == CASE_KEYS, "case shape")
        require(type(case["id"]) is str and type(case["notes"]) is str, "case strings")
        require(case["link"] is None or type(case["link"]) is str, "link type")
        require(type(case["authenticated"]) is bool, "auth type")
        require(type(case["lookup_mode"]) is str and case["lookup_mode"] in {"exact", "latest_descendant"}, "lookup mode")
        require(type(case["events"]) is list and all(type(event) is str for event in case["events"]), "events type")
        validate_expected(case["expected"])
        require(strict_equal(reduce_case(case, grammar, lineage), case["expected"]), "trace drift")
        require(case["expected"]["requested_session_id"] in {None, ROOT_ID, BRANCH_ID}, "opaque ID binding")


def validate_mutations(document: Mapping[str, Any]) -> int:
    """Reject schema drift, dependency rebinding, unsafe results, and trace drift."""

    mutations: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
        ("extra root", lambda value: value.update({"extra": True})),
        ("synthetic false", lambda value: value.update({"synthetic_only": False})),
        ("ttl bool", lambda value: value.update({"pending_ttl_seconds": True})),
        ("dependency drift", lambda value: value["dependencies"]["deep-link-grammar/cases.json"].update({"sha256": "0" * 64})),
        ("dependency rebinding", lambda value: value["dependencies"].update({"deep-link-grammar/cases.json": value["dependencies"]["session-lineage/cases.json"]})),
        ("case order", lambda value: value["cases"].reverse()),
        ("case extra", lambda value: value["cases"][0].update({"extra": False})),
        ("auth exact type", lambda value: value["cases"][0].update({"authenticated": 1})),
        ("counter bool", lambda value: value["cases"][0]["expected"].update({"lookup_attempts": True})),
        ("event drift", lambda value: value["cases"][0]["events"].append("reload")),
        ("expected drift", lambda value: value["cases"][0]["expected"].update({"decision": "pending"})),
        ("creation side effect", lambda value: value["cases"][0]["expected"].update({"session_creations": 1})),
        ("sharing side effect", lambda value: value["cases"][0]["expected"].update({"shares": 1})),
        ("transcript mirror", lambda value: value["cases"][0]["expected"].update({"transcript_mirror": True})),
        ("raw error", lambda value: value["redaction"]["fixed_error"]["error"].update({"message": ROOT_ID})),
        ("lineage root drift", lambda value: value["cases"][2]["expected"].update({"root_id": BRANCH_ID})),
        ("authorization oracle", lambda value: value["cases"][4]["expected"].update({"decision": "denied"})),
        ("pending retained", lambda value: value["cases"][6]["expected"].update({"pending_target": True})),
    )
    count = 0
    for label, mutate in mutations:
        changed = copy.deepcopy(document)
        mutate(changed)
        try:
            validate_document(changed)
        except ContractError:
            count += 1
        else:
            raise ContractError(f"mutation accepted: {label}")
    return count


def normalized_validator_bytes() -> bytes:
    """Normalize only identity literals to break the validator self-hash cycle."""

    text = Path(__file__).read_text(encoding="utf-8")
    for name in ("CASES_SHA256", "BASELINE_SHA256", "NORMALIZED_VALIDATOR_SHA256"):
        text = __import__("re").sub(rf'^{name} = "[^"]+"$', f'{name} = "<REVIEWED>"', text, flags=__import__("re").MULTILINE)
    return text.encode("utf-8")


def distribution(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "min": round(min(samples), 6),
        "p50": round(statistics.median(samples), 6),
        "p95": round(ordered[28], 6),
        "max": round(max(samples), 6),
        "mean": round(statistics.mean(samples), 6),
    }


def validate_evidence(evidence: Any) -> None:
    require(type(evidence) is dict and list(evidence) == ["schema", "normal", "optimized"], "evidence shape")
    require(evidence["schema"] == EVIDENCE_SCHEMA, "evidence schema")
    for mode in ("normal", "optimized"):
        item = evidence[mode]
        require(type(item) is dict and list(item) == ["samples_ms", "distribution"], "mode shape")
        samples = item["samples_ms"]
        require(type(samples) is list and len(samples) == 30, "sample count")
        require(all(type(sample) is float and math.isfinite(sample) and 0 < sample <= MAX_FLOAT for sample in samples), "sample type")
        require(strict_equal(item["distribution"], distribution(samples)), "distribution drift")


def validate_baseline(baseline: Any, evidence: Any) -> None:
    keys = ["schema", "validator", "commands", "build_mode", "artifact_identities", "environment", "repetitions", "normal", "optimized", "threshold"]
    require(type(baseline) is dict and list(baseline) == keys, "baseline shape")
    require(baseline["schema"] == BASELINE_SCHEMA, "baseline schema")
    require(baseline["validator"] == "contracts/fixtures/deep-link-resolution/validate.py", "validator path")
    require(baseline["commands"] == {"normal": "python3 contracts/fixtures/deep-link-resolution/validate.py", "optimized": "python3 -O contracts/fixtures/deep-link-resolution/validate.py"}, "commands")
    require(baseline["build_mode"] == "N/A" and baseline["threshold"] is None, "threshold")
    require(type(baseline["repetitions"]) is int and baseline["repetitions"] == 30, "repetitions")
    require(strict_equal(baseline["normal"], evidence["normal"]) and strict_equal(baseline["optimized"], evidence["optimized"]), "sample binding")
    identities = baseline["artifact_identities"]
    identity_names = [
        "README.md",
        "cases.json",
        "test_validate.py",
        "baseline-evidence.json",
        "validate.py.normalized",
        "docs/architecture/deep-links.md",
    ]
    require(type(identities) is dict and list(identities) == identity_names, "artifact identities")
    require(identities["README.md"] == sha256_bytes((FIXTURE_DIR / "README.md").read_bytes()), "readme identity")
    require(identities["cases.json"] == CASES_SHA256, "cases identity")
    require(identities["test_validate.py"] == sha256_bytes((FIXTURE_DIR / "test_validate.py").read_bytes()), "tests identity")
    require(identities["baseline-evidence.json"] == sha256_bytes((FIXTURE_DIR / "baseline-evidence.json").read_bytes()), "evidence identity")
    require(identities["validate.py.normalized"] == NORMALIZED_VALIDATOR_SHA256, "validator identity")
    require(identities["docs/architecture/deep-links.md"] == sha256_bytes((REPO_ROOT / "docs/architecture/deep-links.md").read_bytes()), "architecture identity")
    require(sha256_bytes(normalized_validator_bytes()) == NORMALIZED_VALIDATOR_SHA256, "validator drift")


def validate_all(cases_path: Path, baseline_path: Path, evidence_path: Path) -> tuple[int, int]:
    cases_bytes = cases_path.read_bytes()
    require(len(cases_bytes) <= MAX_FILE_BYTES and sha256_bytes(cases_bytes) == CASES_SHA256, "cases bytes")
    document = load_json(cases_path)
    validate_document(document)
    evidence = load_json(evidence_path)
    validate_evidence(evidence)
    baseline_bytes = baseline_path.read_bytes()
    require(len(baseline_bytes) <= MAX_FILE_BYTES and sha256_bytes(baseline_bytes) == BASELINE_SHA256, "baseline bytes")
    baseline = load_json(baseline_path)
    validate_baseline(baseline, evidence)
    return len(document["cases"]), validate_mutations(document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=FIXTURE_DIR / "cases.json")
    parser.add_argument("--baseline", type=Path, default=FIXTURE_DIR / "validation-baseline.json")
    parser.add_argument("--evidence", type=Path, default=FIXTURE_DIR / "baseline-evidence.json")
    args = parser.parse_args(argv)
    try:
        case_count, mutation_count = validate_all(args.cases, args.baseline, args.evidence)
    except Exception:
        print(json.dumps(ERROR_PAYLOAD, separators=(",", ":"), sort_keys=True))
        return 1
    print(f"deep_link_resolution_validation=ok cases={case_count} mutations={mutation_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
