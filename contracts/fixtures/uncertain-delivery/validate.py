#!/usr/bin/env -S python3 -I
"""Validate the deterministic synthetic C-06 uncertain-delivery contract.

This is an offline reducer, not a Hermes client.  It reads only checked-in
semantic markers and never opens a WebSocket, calls a Dashboard, imports
Hermes, stores prompt text, or claims live compatibility.  Explicit
ContractError checks keep the fail-closed boundary active under ``python -O``.
"""

from __future__ import annotations

import argparse
import decimal
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.uncertain-delivery.v1"
BASELINE_SCHEMA = "hermternal.uncertain-delivery-baseline.v1"
OPERATION = "C-06"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"

# These identities are deliberately outside the JSON baseline. A mutable
# timing record or copied validator cannot authorize a different fixture,
# source file, or benchmark trace by rebinding its own metadata. The exact
# expected commit is supplied by protected review/CI input, never discovered
# from this tree, a branch, or a tag. Its Git-tree bytes bind every retained
# artifact independent of the current branch's parent shape. The non-release
# tag is only a secondary consistency marker. The validator source digest masks
# only self-referential binding literals, so changing validation logic still
# fails.
TRUST_ANCHOR_REF = "refs/tags/hermternal-c06-uncertain-delivery-cancel-restore-anchor"
CANONICAL_ARTIFACT_NAMES = ("README.md", "cases.json", "preflight.py", "validate.py", "test_validate.py", "chat.md")
CANONICAL_FIXTURE_NAMES = frozenset(("README.md", "cases.json", "preflight.py", "validate.py", "test_validate.py", "validation-baseline.json"))
CANONICAL_FIXTURE_RELATIVE = Path("contracts/fixtures/uncertain-delivery")
CANONICAL_CHAT_RELATIVE = Path("contracts/state-models/chat.md")
EXPECTED_BOUND_SHA256 = {
    "README.md": "d24d40cfbd9fa656176b3a6bede3a6f229f16869ad6527d0e7ce2ed0d442ad60",
    "cases.json": "47676157ea58bc628ff5302e7f033d86dcec6270b45a1f4c2d87ade7fa9652ed",
    "preflight.py": "5c8400ce1253d4993191751bb636ad97115bd603cb90f95480eb7055b48f715e",
    "validate.py": "8dc1a1de9e7393fa1bef1a8e0f007bb417f7adae3e45a77f1aff4c8f29b578b6",
    "test_validate.py": "6062ecaf07d71537cd71b7247b6aa8c1cbf1ded6b5e962830b76fabc754cbdea",
    "chat.md": "ad5798049b36ff9957ea4aaefdebcc79b349eb9d51844b35fbd81ea5871a7189",
}
EXPECTED_BASELINE_SHA256 = "a61644d85f15ae052c14b764c59d0e135bee72a10e26a2f44ff965cd646f1776"
EXPECTED_ENVIRONMENT = {
    "platform": "Darwin-25.5.0-arm64",
    "python": "3.14.6",
    "device": "Mac14,6",
    "build_mode": "N/A",
}

STATES = (
    "empty",
    "ready",
    "submitting",
    "streaming",
    "awaiting_approval",
    "awaiting_clarification",
    "interrupting",
    "delivery_uncertain",
    "restoring",
    "completed",
    "failed",
)
TRANSPORT_STATES = (
    "offline",
    "reconnecting",
    "ready",
    "handshaking",
    "incompatible",
)
AUTOMATIC_RETRY_METHODS = (
    "session.resume",
    "session.history",
    "session.status",
    "model.options",
)
NEVER_AUTOMATIC_RETRY_METHODS = (
    "prompt.submit",
    "session.create",
    "session.interrupt",
)
UNCERTAIN_REASONS = ("timeout", "websocket_close", "app_suspension", "process_loss")
RESTORE_PROMPT_PRESENCE = ("not_observed", "present", "absent", "unknown")
RESTORE_TURN_STATES = ("not_observed", "running", "streaming", "completed", "idle", "rejected", "unknown")
SUBMIT_RESULTS = ("accepted", "pending", "rejected", "unknown")
SERVER_EVENTS = (
    "message.delta",
    "reasoning.delta",
    "thinking.delta",
    "message.complete",
    "tool.start",
    "tool.complete",
    "approval.request",
    "clarify.request",
)
USER_ACTIONS = ("resend", "keep_draft", "retry_after_rejection")
EVENT_KEYS = {
    "gateway_ready": ("kind", "contract", "source_sha", "compatibility"),
    "submit": ("kind", "request_ref", "result"),
    "server_event": ("kind", "name", "request_ref", "turn_ref", "session_ref"),
    "transport_loss": ("kind", "reason"),
    "restore_begin": ("kind",),
    "restore_history": ("kind", "prompt_presence"),
    "restore_status": ("kind", "turn_state"),
    "user_decision": ("kind", "action"),
    "duplicate_submit": ("kind",),
    "automatic_retry": ("kind", "method"),
    "read_retry": ("kind", "method", "result"),
    "interrupt_request": ("kind",),
    "interrupt_result": ("kind", "result"),
    "cancel": ("kind", "where"),
    "sign_out": ("kind",),
    "compatibility_failure": ("kind", "reason"),
    "unknown_event": ("kind", "name"),
    "evidence_pending": ("kind",),
}
ACTION_INVENTORY = frozenset(
    {
        "start_session",
        "write_draft",
        "edit_draft",
        "attach_images",
        "send",
        "restore",
        "sign_out",
        "wait",
        "cancel",
        "interrupt",
        "answer_pending_input",
        "approve",
        "deny",
        "answer",
        "keep_draft",
        "read",
        "copy",
        "new_draft",
        "continue",
        "explicit_retry",
    }
)

CASE_IDS = (
    "empty-session",
    "accepted-present",
    "timeout-present-after-restore",
    "websocket-close-absent-idle",
    "app-suspension-absent-idle-explicit-resend",
    "process-loss-present-running",
    "confirmed-rejection",
    "restore-inconclusive",
    "idempotent-read-retry",
    "automatic-prompt-retry-blocked",
    "duplicate-submit-blocked",
    "resend-unknown-no-third-send",
    "interrupt-confirmed",
    "interrupt-unknown-after-close",
    "cancel-before-submit",
    "sign-out-during-uncertainty",
    "pending-restore-evidence",
    "incompatible-evidence",
    "unknown-interactive-event",
    "explicit-keep-draft-after-absent-idle",
    "confirmed-rejection-explicit-retry",
    "accepted-event-before-close",
    "stale-evidence-resend-blocked",
    "cancel-submitting",
    "cancel-submitting-absent-idle-resend",
    "keep-draft-before-restore",
    "restore-transient-without-recovery",
)
ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "source_observations",
    "states",
    "policies",
    "cases",
    "redaction",
    "accessibility",
)
STATE_KEYS = ("id", "meaning", "terminal", "allowed_actions")
SOURCE_OBSERVATION_KEYS = ("file", "anchor", "rule")
POLICY_KEYS = (
    "automatic_retry_methods",
    "never_automatic_retry_methods",
    "uncertain_transport_reasons",
    "restore_evidence_order",
    "explicit_resend_gate",
    "draft_policy",
    "duplicate_policy",
    "source_result_rule",
)
CASE_KEYS = ("id", "initial", "events", "expected", "notes")
INITIAL_KEYS = ("chat_state", "transport_state", "session_ref", "draft_state", "submission_count", "active_request_ref", "active_turn_ref")
EXPECTED_KEYS = (
    "trace",
    "final_state",
    "transport_trace",
    "final_transport_state",
    "selected_session",
    "draft_state",
    "submission_count",
    "duplicate_attempts",
    "restore_barrier",
    "prompt_retry",
    "automatic_retry",
    "explicit_action_required",
    "outward_changes",
    "idempotent_collection_retries",
    "server_prompt_presence",
    "server_turn_state",
    "decision",
    "contract_error",
)
DISTRIBUTION_KEYS = ("count", "minimum_ms", "maximum_ms", "mean_ms", "median_ms", "p95_ms")
REDACTION_KEYS = (
    "contains_prompt_text",
    "contains_transcript",
    "contains_credentials",
    "contains_hosts",
    "contains_paths",
    "contains_raw_transport",
    "diagnostic_max_chars",
)
ACCESSIBILITY_KEYS = ("applicable", "reason")

MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 96
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 16 * 1024
MAX_INTEGER_DIGITS = 1024
MAX_ERROR_LENGTH = 240
MAX_SAMPLE_MS = 1_000_000.0
MAX_GIT_OUTPUT_BYTES = MAX_JSON_BYTES + 1024
MAX_GIT_STATUS_BYTES = 64 * 1024
BENCHMARK_REPETITIONS = 30
EXPECTED_COMMIT_ENV = "HERMTERNAL_C06_EXPECTED_COMMIT"
TRUSTED_GIT_EXECUTABLE = Path("/usr/bin/git")
# This is a regression/reference copy only. Authoritative invocations receive
# the complete matching launcher from protected review or CI configuration
# before any checkout file is read or imported.
REFERENCE_EXTERNAL_LAUNCHER_CODE = '''import json,os,pathlib,selectors,signal,stat,subprocess,sys,time
E=json.dumps({"error":{"code":"contract","message":"uncertain delivery fixture rejected"}},separators=(",",":"))+chr(10)
P=None;S=None
# The reviewed preflight must be size-bounded before Python receives or compiles it.
def fail():
 if P is not None:
  try: os.killpg(P.pid,signal.SIGKILL)
  except BaseException: pass
  try: P.kill()
  except BaseException: pass
  try: P.wait(timeout=1)
  except BaseException: pass
 if S is not None:
  try: S.close()
  except BaseException: pass
 for stream in (() if P is None else (P.stdout,P.stderr)):
  if stream is not None:
   try: stream.close()
   except BaseException: pass
 sys.stderr.write(E);raise SystemExit(1)
try:
 r=pathlib.Path.cwd();p=pathlib.Path(sys.argv[1]);p=r/p if not p.is_absolute() else p;g=r/".git"
 bad=lambda x:(not x.is_absolute() or x.is_symlink() or x.resolve()!=x)
 q=("objects/info/alternates","objects/info/http-alternates","info/grafts","shallow");w=os.environ.get("PWD")
 if g.is_dir():
  metadata_ok=not bad(g) and not (g/"commondir").exists() and not (g/"commondir").is_symlink()
 elif g.is_file() and not bad(g) and g.stat().st_size<=4096:
  line=g.read_text(encoding="ascii").splitlines();gd=pathlib.Path(line[0][7:].strip()) if len(line)==1 and line[0].startswith("gitdir:") else pathlib.Path("/")
  gd=gd if gd.is_absolute() else r/gd;c=gd.parent.parent
  metadata_ok=(not bad(gd) and gd.parent==c/"worktrees" and c.name==".git" and not bad(c) and r.resolve().is_relative_to(c.parent.resolve()) and (gd/"commondir").is_file() and (gd/"gitdir").is_file() and not any((c/x).is_symlink() for x in ("objects","refs","config")) and not any((c/x).exists() or (c/x).is_symlink() for x in q))
 else: metadata_ok=False
 expected=os.environ.get("HERMTERNAL_C06_EXPECTED_COMMIT")
 targets=(r/pathlib.Path("contracts/fixtures/uncertain-delivery/validate.py"),r/pathlib.Path("contracts/fixtures/uncertain-delivery/test_validate.py"))
 ok=(not bad(r) and p in targets and not bad(p) and metadata_ok and not any((g/x).exists() or (g/x).is_symlink() for x in q) and (not w or (not bad(pathlib.Path(w)) and pathlib.Path(w)==r)) and isinstance(expected,str) and len(expected)==40 and all(x in "0123456789abcdef" for x in expected))
 if not ok: fail()
 env=os.environ.copy()
 for name in list(env):
  if name.startswith("GIT_"): env.pop(name,None)
 env.update({"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_SYSTEM":os.devnull,"GIT_CONFIG_COUNT":"0","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_NO_LAZY_FETCH":"1","GIT_NO_REPLACE_OBJECTS":"1"})
 git=pathlib.Path("/usr/bin/git");meta=git.stat()
 if bad(git) or not stat.S_ISREG(meta.st_mode) or not meta.st_mode&0o111: fail()
 P=subprocess.Popen([str(git),"--no-replace-objects","--no-lazy-fetch","-C",str(r),"show",expected+":contracts/fixtures/uncertain-delivery/preflight.py"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
 if P.stdout is None or P.stderr is None: fail()
 S=selectors.DefaultSelector();S.register(P.stdout,selectors.EVENT_READ,"stdout");S.register(P.stderr,selectors.EVENT_READ,"stderr")
 out=bytearray();err=bytearray();deadline=time.monotonic()+2
 while S.get_map():
  remaining=deadline-time.monotonic()
  if remaining<=0: fail()
  events=S.select(remaining)
  if not events: continue
  for key,event in events:
   target=out if key.data=="stdout" else err;limit=525312 if key.data=="stdout" else 4096
   chunk=os.read(key.fileobj.fileno(),min(8192,limit-len(target)+1))
   if not chunk: S.unregister(key.fileobj);continue
   target.extend(chunk)
   if len(target)>limit: fail()
 returncode=P.wait(timeout=1)
 if returncode!=0 or err: fail()
 S.close();S=None;P.stdout.close();P.stderr.close();source=bytes(out)
except SystemExit:
 raise
except BaseException:
 fail()
class Capture:
 def __init__(self,limit): self.data=[];self.size=0;self.limit=limit;self.buffer=self;self.encoding="utf-8"
 def write(self,value):
  if isinstance(value,bytes): value=value.decode("utf-8")
  if not isinstance(value,str): raise TypeError
  self.size+=len(value.encode("utf-8"))
  if self.size>self.limit: raise RuntimeError
  self.data.append(value);return len(value)
 def flush(self): pass
 def value(self): return "".join(self.data)
original_out=sys.stdout;original_err=sys.stderr;captured_out=Capture(4096);captured_err=Capture(4096)
try:
 sys.stdout=captured_out;sys.stderr=captured_err
 namespace={"__name__":"__main__","__file__":str(p.parent/"preflight.py"),"__package__":None,"__cached__":None}
 exec(compile(source,str(p.parent/"preflight.py"),"exec",optimize=sys.flags.optimize),namespace,namespace)
 raise RuntimeError
except SystemExit:
 sys.stdout=original_out;sys.stderr=original_err
 original_out.write(captured_out.value());original_err.write(captured_err.value())
 raise
except BaseException:
 sys.stdout=original_out;sys.stderr=original_err
 fail()
'''
EXTERNAL_LAUNCHER_SHA256 = "71315991b361057f6af4b902654d2385e4d283454cf0c040dc1bfa188cf57ae0"
APPROVED_MODE_EVIDENCE = {
    "normal": {"python_flags": "-I -B", "target": "validate.py"},
    "optimized": {"python_flags": "-I -B -O", "target": "validate.py"},
}

SYNTHETIC_REF = re.compile(r"^(?:session|request)-marker-[0-9]{3}$")
TURN_REF = re.compile(r"^turn-marker-[0-9]{3}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BASE64ISH = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
JWTISH = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
API_KEYISH = re.compile(r"(?i)\b(?:api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key|private[_-]?key|sk[-_])[=:][A-Za-z0-9._-]{8,}")
SK_PROJISH = re.compile(r"\bsk-proj-[A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
GH_TOKENISH = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{12,}\b")
RELATIVE_PATH = re.compile(r"(?:^|[\s])(?:\.{1,2}/|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.[A-Za-z0-9_-]+)?)")
ABSOLUTE_PATH = re.compile(r"(?:^|[\s])/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+")
WINDOWS_PATH = re.compile(r"(?i)(?:^|[\s])(?:[A-Z]:[/\\\\]|\\\\\\\\)[^\r\n]+")
ORDINARY_PROMPT_PROSE = re.compile(
    r"(?i)(?:\b(?:please|could you|would you|can you|tell me|summarize|explain|write|show me|give me|find me|help me|i need|i want|what is|how do|why do|when did|where is|who is|this is a prompt)\b|[?])"
)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9])")
DOMAIN = re.compile(r"(?:^|[\s:=/])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|test|local|example|invalid|internal)(?:$|[\s/:])", re.IGNORECASE)
# These fields may carry only the exact synthetic markers already bound by the
# schema. Allowing those markers avoids broad text heuristics without allowing
# caller-chosen path, host, credential, or transcript material.
SAFE_MARKER_FIELDS = frozenset({"session_ref", "selected_session", "active_request_ref", "active_turn_ref", "request_ref", "turn_ref"})
FORBIDDEN_KEYS = frozenset(
    {
        "prompt_text",
        "prompt_bytes",
        "raw_prompt",
        "transcript",
        "transcript_text",
        "transcript_bytes",
        "credential",
        "credentials",
        "password",
        "authorization",
        "authorization_header",
        "cookie",
        "cookies",
        "ticket",
        "secret",
        "secret_key",
        "api_key",
        "api_token",
        "access_token",
        "id_token",
        "private_key",
        "jwt",
        "base64",
        "refresh_token",
        "bearer",
        "attach_handle",
        "pty_input",
        "pty_output",
        "raw_transport",
        "host",
        "hostname",
        "url",
        "path",
        "file_path",
    }
)


class ContractError(Exception):
    """A bounded, non-sensitive contract failure."""

    def __init__(self, code: str = "contract_rejected") -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = "contract_rejected") -> None:
    raise ContractError(code)


def _reject_constant(_: str) -> None:
    _fail("non_finite_number")


def _parse_int(raw: str) -> int:
    digits = raw[1:] if raw.startswith("-") else raw
    if len(digits) > MAX_INTEGER_DIGITS:
        _fail("integer_too_large")
    try:
        return int(raw)
    except (TypeError, ValueError, OverflowError):
        _fail("invalid_integer")
    raise ContractError("invalid_integer")


def _parse_float(raw: str) -> float:
    try:
        exact = decimal.Decimal(raw)
        value = float(raw)
    except (decimal.InvalidOperation, TypeError, ValueError, OverflowError):
        _fail("invalid_number")
    if not math.isfinite(value):
        _fail("non_finite_number")
    # Python's binary float parser silently rounds sufficiently small nonzero
    # JSON numbers to signed zero. Preserve fail-closed numeric meaning instead.
    if exact != 0 and value == 0.0:
        _fail("number_underflow")
    return value


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_key")
        result[key] = value
    return result


def _check_bounds(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        _fail("input_too_deep_or_large")
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            _fail("string_too_large")
        return
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_LENGTH:
            _fail("array_too_large")
        for child in value:
            _check_bounds(child, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            _fail("object_too_large")
        for key, child in value.items():
            if not isinstance(key, str):
                _fail("object_key_type")
            if len(key) > MAX_STRING_LENGTH:
                _fail("string_too_large")
            _check_bounds(child, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, float) and not math.isfinite(value):
        _fail("non_finite_number")
    if value is not None and type(value) not in (bool, int, float):
        _fail("unsupported_json_type")


def _bounded_read_file(path: Path, limit: int, unavailable_code: str = "input_unavailable") -> bytes:
    try:
        resolved = path.resolve()
        metadata = resolved.stat()
        if not stat.S_ISREG(metadata.st_mode):
            _fail("input_not_regular_file")
        if metadata.st_size > limit:
            _fail("input_too_large")
        with resolved.open("rb") as stream:
            raw = stream.read(limit + 1)
    except ContractError:
        raise
    except (OSError, ValueError):
        _fail(unavailable_code)
    if len(raw) > limit:
        _fail("input_too_large")
    return raw


def load_json(path: Path, label: str) -> Any:
    raw = _bounded_read_file(path, MAX_JSON_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid_utf8")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        _fail("invalid_json")
    _check_bounds(value)
    if not isinstance(value, dict):
        _fail("root_shape")
    return value


def _keys(value: Any, expected: tuple[str, ...]) -> None:
    if not isinstance(value, dict) or tuple(value.keys()) != expected:
        _fail("schema_keys")


def _string(value: Any, code: str) -> str:
    if type(value) is not str:
        _fail(code)
    return value


def _bool(value: Any, code: str) -> bool:
    if type(value) is not bool:
        _fail(code)
    return value


def _int(value: Any, code: str) -> int:
    if type(value) is not int:
        _fail(code)
    return value


def _enum(value: Any, allowed: tuple[str, ...], code: str) -> str:
    value = _string(value, code + "_type")
    if value not in allowed:
        _fail(code)
    return value


def _nullable_string(value: Any, code: str) -> str | None:
    if value is None:
        return None
    return _string(value, code)


def _synthetic_ref(value: Any, code: str) -> str:
    value = _string(value, code + "_type")
    if SYNTHETIC_REF.fullmatch(value) is None:
        _fail(code)
    return value


def _distribution(samples: list[float]) -> dict[str, float | int]:
    if not samples or any(type(sample) is not float or not math.isfinite(sample) or not 0 < sample <= MAX_SAMPLE_MS for sample in samples):
        _fail("benchmark_sample_bounds")
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    try:
        mean = statistics.fmean(samples)
    except (OverflowError, ValueError, statistics.StatisticsError):
        _fail("baseline_arithmetic")
    return {
        "count": len(samples),
        "minimum_ms": round(min(samples), 6),
        "maximum_ms": round(max(samples), 6),
        "mean_ms": round(mean, 6),
        "median_ms": round(statistics.median(ordered), 6),
        "p95_ms": round(ordered[p95_index], 6),
    }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _source_binding_bytes(raw: bytes) -> bytes:
    """Normalize only self-referential digest literals before hashing source."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("source_identity")
    text = re.sub(r'(?m)^(EXPECTED_BASELINE_SHA256\s*=\s*)"[^"]+"', r'\1"<bound>"', text)
    text = re.sub(r'(?m)^(\s*"validate\.py"\s*:\s*)"[^"]+"', r'\1"<bound>"', text)
    return text.encode("utf-8")


def _source_digest(path: Path) -> tuple[int, str]:
    raw = _bounded_read_file(path, MAX_JSON_BYTES, "artifact_unavailable")
    normalized = _source_binding_bytes(raw)
    return len(normalized), _sha256_bytes(normalized)


def _git_env() -> dict[str, str]:
    """Build a neutral Git environment without inherited Git indirection."""
    env = os.environ.copy()
    # Remove every inherited GIT_* variable, including numbered config pairs,
    # helper hooks, grafts, shallow files, and replacement/object redirects.
    # Deleting by prefix prevents a future redirect name from bypassing this
    # proof. Only neutral values needed by the bounded Git calls are restored.
    for name in list(env):
        if name.startswith("GIT_"):
            env.pop(name, None)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return env


def _trusted_git_path() -> Path | None:
    """Use one fixed, authenticated system Git path, never caller PATH."""
    path = TRUSTED_GIT_EXECUTABLE
    try:
        if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
            return None
        metadata = path.stat()
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        return None
    return path


def _kill_git_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_git(
    repository: Path,
    arguments: list[str],
    *,
    output_limit: int = MAX_GIT_OUTPUT_BYTES,
) -> tuple[int, bytes, bytes] | None:
    """Run fixed Git with bounded pipes and complete timeout cleanup."""
    executable = _trusted_git_path()
    if executable is None or output_limit <= 0:
        return None
    command = [
        str(executable),
        "--no-replace-objects",
        "--no-lazy-fetch",
        "-C",
        str(repository),
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_env(),
            start_new_session=True,
        )
    except (OSError, ValueError):
        return None

    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        if process.stdout is None or process.stderr is None:
            _kill_git_process(process)
            return None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + 2
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_git_process(process)
                return None
            events = selector.select(remaining)
            if not events:
                continue
            for key, _ in events:
                stream_name = key.data
                try:
                    remaining_capacity = output_limit - len(output[stream_name])
                    chunk = os.read(key.fileobj.fileno(), min(8192, remaining_capacity + 1))
                except OSError:
                    _kill_git_process(process)
                    return None
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[stream_name].extend(chunk)
                if len(output[stream_name]) > output_limit:
                    _kill_git_process(process)
                    return None
        try:
            returncode = process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            _kill_git_process(process)
            return None
        return returncode, bytes(output["stdout"]), bytes(output["stderr"])
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def _git_text(repository: Path, arguments: list[str], *, output_limit: int = 4096) -> str | None:
    result = _run_git(repository, arguments, output_limit=output_limit)
    if result is None:
        return None
    returncode, stdout, stderr = result
    if returncode != 0 or stderr:
        return None
    try:
        return stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _git_optional_config(repository: Path, arguments: list[str]) -> tuple[bool, str | None]:
    result = _run_git(repository, ["config", "--local", *arguments], output_limit=MAX_GIT_STATUS_BYTES)
    if result is None:
        return False, None
    returncode, stdout, stderr = result
    if returncode == 1 and not stdout and not stderr:
        return True, None
    if returncode != 0 or stderr:
        return False, None
    try:
        return True, stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        return False, None


def _git_revision(repository: Path, expression: str) -> str | None:
    output = _git_text(repository, ["rev-parse", "--verify", expression], output_limit=128)
    if output is None or not output.endswith("\n"):
        return None
    value = output.strip()
    return value if HEX40.fullmatch(value) else None


def _git_object_type(repository: Path, object_name: str) -> str | None:
    output = _git_text(repository, ["cat-file", "-t", object_name], output_limit=64)
    if output is None or not output.endswith("\n"):
        return None
    return output.strip()


def _git_blob(repository: Path, object_name: str) -> bytes | None:
    if _git_object_type(repository, object_name) != "blob":
        return None
    result = _run_git(repository, ["cat-file", "blob", object_name], output_limit=MAX_JSON_BYTES + 1)
    if result is None:
        return None
    returncode, stdout, stderr = result
    if returncode != 0 or stderr or len(stdout) > MAX_JSON_BYTES:
        return None
    return stdout


def _git_is_shallow(repository: Path) -> bool | None:
    output = _git_text(repository, ["rev-parse", "--is-shallow-repository"], output_limit=64)
    if output is None:
        return None
    value = output.strip()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _external_expected_commit() -> str | None:
    value = os.environ.get(EXPECTED_COMMIT_ENV)
    return value if value is not None and HEX40.fullmatch(value) else None


def _trusted_anchor_commit(repository: Path) -> str | None:
    # This non-release tag is only a secondary availability/consistency check.
    # The external expected commit remains authoritative because tag refs can
    # be force-retagged by a mirror or local repository owner.
    if _git_object_type(repository, TRUST_ANCHOR_REF) != "tag":
        return None
    return _git_revision(repository, f"{TRUST_ANCHOR_REF}^{{commit}}")


def _repository_has_trust_anchor(candidate: Path) -> bool:
    return _trusted_anchor_commit(candidate) is not None


def _repository_root() -> Path:
    candidates: list[Path] = []
    for start in (Path(__file__).resolve(), Path.cwd().resolve()):
        candidates.extend((start, *start.parents))
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if (
            (candidate / ".git").exists()
            and (candidate / CANONICAL_FIXTURE_RELATIVE / "cases.json").is_file()
            and (candidate / CANONICAL_FIXTURE_RELATIVE / "validation-baseline.json").is_file()
            and (candidate / CANONICAL_CHAT_RELATIVE).is_file()
        ):
            return candidate
    _fail("canonical_binding")
    raise ContractError("canonical_binding")


def _trusted_fixture_directory() -> Path:
    return _repository_root() / CANONICAL_FIXTURE_RELATIVE


def _artifact_path(fixture_dir: Path, name: str) -> Path:
    if name == "chat.md":
        return fixture_dir.parents[1] / "state-models" / "chat.md"
    return fixture_dir / name


def _reject_unexpected_fixture_entries(fixture_dir: Path) -> None:
    """Reject sibling modules so path-scoped evidence cannot accept imports."""
    if fixture_dir.is_symlink() or not fixture_dir.is_dir():
        _fail("canonical_binding")
    try:
        entries = tuple(fixture_dir.iterdir())
    except (OSError, ValueError):
        _fail("canonical_binding")
    if {entry.name for entry in entries} != CANONICAL_FIXTURE_NAMES:
        _fail("canonical_binding")
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            _fail("canonical_binding")


def _artifact_digest(fixture_dir: Path, name: str) -> tuple[int, str]:
    path = _artifact_path(fixture_dir, name)
    if name == "validate.py":
        return _source_digest(path)
    raw = _bounded_read_file(path, MAX_JSON_BYTES, "artifact_unavailable")
    return len(raw), _sha256_bytes(raw)


def _require_exact_trusted_file(path: Path, trusted_path: Path, code: str) -> None:
    try:
        if path.is_symlink() or path.resolve() != trusted_path.resolve() or _bounded_read_file(path, MAX_JSON_BYTES, code) != _bounded_read_file(trusted_path, MAX_JSON_BYTES, code):
            _fail(code)
    except ContractError:
        raise
    except (OSError, ValueError):
        _fail(code)


def _git_metadata_dirs(root: Path) -> tuple[Path, Path] | None:
    """Accept a clone or a Git-managed linked worktree, not arbitrary redirection."""
    marker = root / ".git"
    try:
        if marker.is_symlink():
            return None
        if marker.is_dir():
            git_dir = marker.resolve()
            if git_dir != marker or not git_dir.is_dir():
                return None
            # A commondir file on a normal clone would redirect metadata outside
            # the checkout; linked worktrees are handled by the branch below.
            if (git_dir / "commondir").exists() or (git_dir / "commondir").is_symlink():
                return None
            return git_dir, git_dir
        if not marker.is_file():
            return None
        raw = _bounded_read_file(marker, 4096, "canonical_binding").decode("ascii")
        lines = raw.splitlines()
        if len(lines) != 1 or not lines[0].startswith("gitdir:"):
            return None
        git_dir = Path(lines[0][7:].strip())
        if not git_dir.is_absolute():
            git_dir = root / git_dir
        git_dir = git_dir.resolve()
        common_dir = (git_dir.parent.parent).resolve()
        if not git_dir.is_dir() or git_dir.parent != common_dir / "worktrees":
            return None
        commondir_file = git_dir / "commondir"
        if commondir_file.is_symlink() or not commondir_file.is_file():
            return None
        relative = _bounded_read_file(commondir_file, 4096, "canonical_binding").decode("ascii").strip()
        if (git_dir / relative).resolve() != common_dir:
            return None
        linked_marker = git_dir / "gitdir"
        if linked_marker.is_symlink() or not linked_marker.is_file():
            return None
        linked_path = Path(_bounded_read_file(linked_marker, 4096, "canonical_binding").decode("ascii").strip()).resolve()
        if linked_path != marker.resolve():
            return None
        if not common_dir.is_dir() or common_dir.is_symlink():
            return None
        return git_dir, common_dir
    except (ContractError, OSError, UnicodeError, IndexError, RuntimeError, ValueError):
        return None


def _reject_repository_metadata(root: Path) -> None:
    metadata = _git_metadata_dirs(root)
    if metadata is None:
        _fail("canonical_binding")
    git_dir, common_dir = metadata
    for metadata_dir in {git_dir, common_dir}:
        for relative in (
            Path("HEAD"),
            Path("config"),
            Path("index"),
            Path("packed-refs"),
            Path("objects"),
            Path("objects/info"),
            Path("refs"),
            Path("refs/tags"),
            Path("info"),
            Path("objects/info/alternates"),
            Path("objects/info/http-alternates"),
            Path("info/grafts"),
            Path("shallow"),
            Path("refs/replace"),
        ):
            path = metadata_dir / relative
            if path.is_symlink():
                _fail("canonical_binding")
        for relative in (
            Path("objects/info/alternates"),
            Path("objects/info/http-alternates"),
            Path("info/grafts"),
            Path("shallow"),
        ):
            path = metadata_dir / relative
            if path.exists() or path.is_symlink():
                _fail("canonical_binding")
        for relative in (Path("config"), Path("config.worktree")):
            path = metadata_dir / relative
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_file():
                    _fail("canonical_binding")
                _bounded_read_file(path, MAX_GIT_STATUS_BYTES, "canonical_binding")

    local_config = _git_text(root, ["config", "--local", "--null", "--list"], output_limit=MAX_GIT_STATUS_BYTES)
    if local_config is None or (local_config and not local_config.endswith("\0")):
        _fail("canonical_binding")
    dangerous_prefixes = (
        "include",
        "core.alternaterefs",
        "core.askpass",
        "core.fsmonitor",
        "core.gitproxy",
        "core.hookspath",
        "core.sshcommand",
        "core.usereplacerefs",
        "credential.",
        "diff.",
        "filter.",
        "http.",
        "ssh.",
        "submodule.",
        "url.",
    )
    for record in local_config.split("\0"):
        if not record:
            continue
        key, separator, value = record.partition("\n")
        if not separator:
            _fail("canonical_binding")
        normalized = key.casefold()
        if normalized == "core.repositoryformatversion" and value != "0":
            _fail("canonical_binding")
        if normalized.startswith(dangerous_prefixes):
            _fail("canonical_binding")
        if normalized.startswith("extensions."):
            _fail("canonical_binding")
        if normalized.endswith(".promisor") or normalized.endswith(".partialclonefilter"):
            _fail("canonical_binding")

    replace_refs = _git_text(
        root,
        ["for-each-ref", "--count=1", "--format=%(refname)", "refs/replace"],
        output_limit=1024,
    )
    if replace_refs is None or replace_refs.strip():
        _fail("canonical_binding")

    bare_ok, bare = _git_optional_config(root, ["--get", "core.bare"])
    if not bare_ok or (bare is not None and bare.casefold() not in {"false", "0", "no"}):
        _fail("canonical_binding")
    worktree_ok, worktree = _git_optional_config(root, ["--get", "core.worktree"])
    if not worktree_ok:
        _fail("canonical_binding")
    if worktree:
        configured = Path(worktree)
        configured_root = (git_dir / configured if not configured.is_absolute() else configured).resolve()
        if configured_root != root:
            _fail("canonical_binding")
    partial_ok, partial = _git_optional_config(root, ["--get-regexp", r"^extensions\.partialClone$"])
    promisor_ok, promisor = _git_optional_config(root, ["--get-regexp", r"^remote\..*\.promisor$"])
    if not partial_ok or not promisor_ok or partial or promisor:
        _fail("canonical_binding")


def _reject_path_aliases(root: Path) -> None:
    """Reject symlinked checkout paths before canonical evidence is trusted."""
    try:
        if not root.is_absolute() or root.is_symlink() or root.resolve() != root:
            _fail("canonical_binding")
        pwd = os.environ.get("PWD")
        if pwd:
            lexical = Path(pwd)
            if not lexical.is_absolute() or lexical.is_symlink() or lexical.resolve() != root or lexical.resolve() != lexical:
                _fail("canonical_binding")
    except (OSError, RuntimeError, ValueError):
        _fail("canonical_binding")


def _require_clean_bound_worktree(root: Path) -> None:
    _reject_path_aliases(root)
    root = root.resolve()
    paths = [
        str(CANONICAL_FIXTURE_RELATIVE / name)
        for name in ("README.md", "cases.json", "preflight.py", "validate.py", "test_validate.py", "validation-baseline.json")
    ] + [str(CANONICAL_CHAT_RELATIVE)]
    expected = _external_expected_commit()
    if expected is None:
        _fail("canonical_binding")
    if _git_revision(root, f"{expected}^{{commit}}") != expected:
        _fail("canonical_binding")
    if _trusted_anchor_commit(root) != expected:
        _fail("canonical_binding")
    if _git_revision(root, "HEAD^{commit}") is None:
        _fail("canonical_binding")
    bare_state = _git_text(root, ["rev-parse", "--is-bare-repository"], output_limit=64)
    inside_state = _git_text(root, ["rev-parse", "--is-inside-work-tree"], output_limit=64)
    if bare_state is None or bare_state.strip() != "false":
        _fail("canonical_binding")
    if inside_state is None or inside_state.strip() != "true":
        _fail("canonical_binding")
    shown_root = _git_text(root, ["rev-parse", "--show-toplevel"], output_limit=4096)
    if shown_root is None or Path(shown_root.strip()).resolve() != root:
        _fail("canonical_binding")
    shallow = _git_is_shallow(root)
    if shallow is None or shallow:
        _fail("canonical_binding")
    _reject_repository_metadata(root)

    fixture_dir = root / CANONICAL_FIXTURE_RELATIVE
    _reject_unexpected_fixture_entries(fixture_dir)
    expected_paths = {
        "README.md": CANONICAL_FIXTURE_RELATIVE / "README.md",
        "cases.json": CANONICAL_FIXTURE_RELATIVE / "cases.json",
        "preflight.py": CANONICAL_FIXTURE_RELATIVE / "preflight.py",
        "validate.py": CANONICAL_FIXTURE_RELATIVE / "validate.py",
        "test_validate.py": CANONICAL_FIXTURE_RELATIVE / "test_validate.py",
        "validation-baseline.json": CANONICAL_FIXTURE_RELATIVE / "validation-baseline.json",
        "chat.md": CANONICAL_CHAT_RELATIVE,
    }
    for name, relative in expected_paths.items():
        current_path = _artifact_path(fixture_dir, name)
        if current_path.is_symlink():
            _fail("canonical_binding")
        expected_bytes = _git_blob(root, f"{expected}:{relative.as_posix()}")
        if expected_bytes is None or _bounded_read_file(current_path, MAX_JSON_BYTES, "canonical_binding") != expected_bytes:
            _fail("canonical_binding")

    status = _git_text(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--", *paths],
        output_limit=MAX_GIT_STATUS_BYTES,
    )
    if status is None or status:
        _fail("canonical_binding")
    index_listing = _git_text(root, ["ls-files", "-v", "--", *paths], output_limit=MAX_GIT_STATUS_BYTES)
    if index_listing is None:
        _fail("canonical_binding")
    for line in index_listing.splitlines():
        if line[:1] in {"h", "s", "S"}:
            _fail("canonical_binding")
    diff = _run_git(
        root,
        ["diff", "--no-ext-diff", "--no-textconv", "--quiet", "HEAD", "--", *paths],
        output_limit=1024,
    )
    if diff is None or diff[0] != 0 or diff[1] or diff[2]:
        _fail("canonical_binding")


def _require_bound_artifacts(root: Path) -> None:
    _require_clean_bound_worktree(root)
    fixture_dir = root / CANONICAL_FIXTURE_RELATIVE
    for name in CANONICAL_ARTIFACT_NAMES:
        size, digest = _artifact_digest(fixture_dir, name)
        expected = EXPECTED_BOUND_SHA256[name]
        if not HEX64.fullmatch(expected) or digest != expected or size <= 0:
            _fail("artifact_identity")
    baseline = root / CANONICAL_FIXTURE_RELATIVE / "validation-baseline.json"
    if _sha256_bytes(_bounded_read_file(baseline, MAX_JSON_BYTES, "baseline_identity")) != EXPECTED_BASELINE_SHA256:
        _fail("baseline_identity")


def _load_trusted_document() -> dict[str, Any]:
    return load_json(_trusted_fixture_directory() / "cases.json", "trusted cases")


def _load_trusted_baseline() -> dict[str, Any]:
    return load_json(_trusted_fixture_directory() / "validation-baseline.json", "trusted baseline")


def _artifact_manifest(fixture_dir: Path) -> tuple[dict[str, dict[str, int | str]], str]:
    artifacts: dict[str, dict[str, int | str]] = {}
    for name in CANONICAL_ARTIFACT_NAMES:
        size, digest = _artifact_digest(fixture_dir, name)
        artifacts[name] = {"bytes": size, "sha256": digest}
    material = "".join(f"{name}:{artifacts[name]['bytes']}:{artifacts[name]['sha256']}\n" for name in CANONICAL_ARTIFACT_NAMES)
    return artifacts, _sha256_bytes(material.encode("utf-8"))


def _validate_redaction(value: Any, *, in_source_observation: bool = False, key: str | None = None) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            normalized = child_key.casefold().replace("-", "_").replace(".", "_")
            if not in_source_observation and normalized in FORBIDDEN_KEYS:
                _fail("redaction_key")
            _validate_redaction(child, in_source_observation=in_source_observation or child_key == "source_observations", key=child_key)
        return
    if isinstance(value, list):
        for child in value:
            _validate_redaction(child, in_source_observation=in_source_observation, key=key)
        return
    if not isinstance(value, str):
        return
    if len(value) > MAX_STRING_LENGTH:
        _fail("redaction_value")
    if in_source_observation or value == HERMES_SOURCE_SHA:
        return
    if key in SAFE_MARKER_FIELDS and (
        (key in ("session_ref", "selected_session") and value.startswith("session-marker-") and SYNTHETIC_REF.fullmatch(value))
        or (key in ("request_ref", "active_request_ref") and value.startswith("request-marker-") and SYNTHETIC_REF.fullmatch(value))
        or (key in ("turn_ref", "active_turn_ref") and value.startswith("turn-marker-") and TURN_REF.fullmatch(value))
    ):
        return
    lowered = value.casefold()
    if key == "notes":
        if ORDINARY_PROMPT_PROSE.search(value) or any(marker in lowered for marker in (
            "prompt text", "raw prompt", "prompt body", "prompt bytes", "transcript", "raw payload", "tool output", "prompt content", "user message",
        )):
            _fail("redaction_value")
    if any(marker in lowered for marker in (
        "http://", "https://", "file://", "bearer ", "basic ", "cookie:", "authorization:", "password=", "api_key=", "api-key=", "api_token=", "api-token=",
    )):
        _fail("redaction_value")
    if JWTISH.search(value) or API_KEYISH.search(value) or SK_PROJISH.search(value) or GH_TOKENISH.search(value):
        _fail("redaction_value")
    if value.startswith(("/", "~/", "\\")) or ABSOLUTE_PATH.search(value) or WINDOWS_PATH.search(value) or RELATIVE_PATH.search(value) or IPV4.search(value) or IPV6.search(value) or DOMAIN.search(value):
        _fail("redaction_value")
    has_upper = any(character.isupper() for character in value)
    has_lower = any(character.islower() for character in value)
    has_digit = any(character.isdigit() for character in value)
    if BASE64ISH.fullmatch(value) and (
        "=" in value
        or (has_upper and has_lower and has_digit and len(value) >= 8)
        or (value.isdigit() and len(value) >= 8)
        or value in {"abcdef"}
    ) and "-" not in value and "_" not in value:
        _fail("redaction_value")


def validate_document(document: dict[str, Any]) -> None:
    _keys(document, ROOT_KEYS)
    if document["schema"] != SCHEMA or document["operation"] != OPERATION or document["contract"] != CONTRACT:
        _fail("identity_mismatch")
    if document["hermes_source_sha"] != HERMES_SOURCE_SHA or not HEX40.fullmatch(document["hermes_source_sha"]):
        _fail("source_mismatch")
    if _bool(document["synthetic_only"], "synthetic_only") is not True:
        _fail("synthetic_only")

    observations = document["source_observations"]
    if type(observations) is not list or len(observations) != 4:
        _fail("source_observations")
    expected_observations = (
        ("tui_gateway/ws.py", "gateway.ready", "ready_before_application_rpc"),
        ("tui_gateway/ws.py", "WebSocketDisconnect", "disconnect_detaches_transport"),
        ("tui_gateway/methods_prompt.py", "prompt.submit", "server_starts_prompt_turn"),
        ("tui_gateway/methods_session.py", "session.resume", "restore_server_owned_session"),
    )
    for observation, expected in zip(observations, expected_observations):
        _keys(observation, SOURCE_OBSERVATION_KEYS)
        actual = tuple(_string(observation[field], "source_observation_value") for field in SOURCE_OBSERVATION_KEYS)
        if actual != expected:
            _fail("source_observations")

    states = document["states"]
    if type(states) is not list or len(states) != len(STATES):
        _fail("states")
    state_ids: list[str] = []
    for state in states:
        _keys(state, STATE_KEYS)
        state_id = _enum(state["id"], STATES, "state_id")
        if state_id in state_ids:
            _fail("duplicate_state")
        state_ids.append(state_id)
        _string(state["meaning"], "state_meaning")
        _bool(state["terminal"], "state_terminal")
        actions = state["allowed_actions"]
        if type(actions) is not list or not actions or any(type(action) is not str for action in actions):
            _fail("state_actions")
        if len(set(actions)) != len(actions) or any(action not in ACTION_INVENTORY for action in actions):
            _fail("state_action_inventory")
    if tuple(state_ids) != STATES:
        _fail("state_inventory")
    trusted_states = _load_trusted_document()["states"]
    if states != trusted_states:
        _fail("state_identity")

    policies = document["policies"]
    _keys(policies, POLICY_KEYS)
    for key in ("automatic_retry_methods", "never_automatic_retry_methods", "uncertain_transport_reasons", "restore_evidence_order", "explicit_resend_gate"):
        values = policies[key]
        if type(values) is not list or not values or any(type(item) is not str for item in values):
            _fail("policy_values")
    if tuple(policies["automatic_retry_methods"]) != AUTOMATIC_RETRY_METHODS:
        _fail("automatic_retry_inventory")
    if tuple(policies["never_automatic_retry_methods"]) != NEVER_AUTOMATIC_RETRY_METHODS:
        _fail("never_retry_inventory")
    if tuple(policies["uncertain_transport_reasons"]) != UNCERTAIN_REASONS:
        _fail("uncertain_reason_inventory")
    if tuple(policies["restore_evidence_order"]) != ("session.history", "session.status"):
        _fail("restore_order")
    if tuple(policies["explicit_resend_gate"]) != ("restore_complete", "prompt_absent", "turn_idle", "user_confirmed"):
        _fail("resend_gate")
    if policies["draft_policy"] != "preserve_original_until_server_presence_or_user_discard":
        _fail("draft_policy")
    if policies["duplicate_policy"] != "one_submission_per_explicit_send":
        _fail("duplicate_policy")
    if policies["source_result_rule"] != "correlate_reply_by_request_identifier_and_events_by_event_name":
        _fail("source_result_rule")

    cases = document["cases"]
    if type(cases) is not list or len(cases) != len(CASE_IDS):
        _fail("case_count")
    seen_ids: list[str] = []
    for case, expected_id in zip(cases, CASE_IDS):
        _keys(case, CASE_KEYS)
        _validate_redaction(case)
        case_id = _string(case["id"], "case_id")
        if case_id != expected_id or case_id in seen_ids:
            _fail("case_inventory")
        seen_ids.append(case_id)
        _validate_initial(case["initial"])
        _validate_events(case["events"])
        _validate_expected(case["expected"])
        _string(case["notes"], "case_notes")
        result = evaluate_case(case)
        if result != case["expected"]:
            _fail("case_semantics")

    redaction = document["redaction"]
    _keys(redaction, REDACTION_KEYS)
    for key in REDACTION_KEYS[:-1]:
        if _bool(redaction[key], "redaction_flag") is not False:
            _fail("redaction_flag")
    if _int(redaction["diagnostic_max_chars"], "diagnostic_max_chars") != MAX_ERROR_LENGTH:
        _fail("diagnostic_limit")
    accessibility = document["accessibility"]
    _keys(accessibility, ACCESSIBILITY_KEYS)
    if _bool(accessibility["applicable"], "accessibility_applicable") is not False:
        _fail("accessibility_scope")
    _string(accessibility["reason"], "accessibility_reason")
    _validate_redaction(document)


def _validate_initial(initial: Any) -> None:
    _keys(initial, INITIAL_KEYS)
    _enum(initial["chat_state"], STATES, "initial_chat_state")
    _enum(initial["transport_state"], TRANSPORT_STATES, "initial_transport_state")
    _nullable_string(initial["session_ref"], "session_ref")
    if initial["session_ref"] is not None:
        _synthetic_ref(initial["session_ref"], "session_ref")
    _enum(initial["draft_state"], ("present", "absent"), "draft_state")
    count = _int(initial["submission_count"], "submission_count")
    if count < 0 or count > 4:
        _fail("submission_count")
    active_request = initial["active_request_ref"]
    active_turn = initial["active_turn_ref"]
    if active_request is not None:
        _synthetic_ref(active_request, "active_request_ref")
    if active_turn is not None and TURN_REF.fullmatch(active_turn) is None:
        _fail("active_turn_ref")
    active_state = initial["chat_state"] in ("submitting", "streaming", "awaiting_approval", "awaiting_clarification", "interrupting", "delivery_uncertain")
    if active_state and (count < 1 or initial["session_ref"] is None or active_request is None or active_turn is None):
        _fail("active_submission_required")
    if initial["chat_state"] == "delivery_uncertain" and initial["draft_state"] != "present":
        _fail("uncertain_draft_required")
    if not active_state and (active_request is not None or active_turn is not None):
        _fail("inactive_submission_reference")
    if initial["chat_state"] != "empty" and initial["session_ref"] is None:
        _fail("session_required")
    if initial["chat_state"] == "empty" and initial["session_ref"] is not None:
        _fail("empty_session_reference")
    if initial["chat_state"] == "ready" and initial["transport_state"] != "ready":
        _fail("ready_transport")
    if initial["chat_state"] == "empty" and initial["transport_state"] not in ("offline", "ready"):
        _fail("empty_transport")


def _validate_events(events: Any) -> None:
    if type(events) is not list or len(events) > 32:
        _fail("events")
    request_refs: set[str] = set()
    for event in events:
        if not isinstance(event, dict) or "kind" not in event:
            _fail("event_shape")
        kind = _string(event["kind"], "event_kind")
        if kind not in EVENT_KEYS:
            _fail("event_kind")
        _keys(event, EVENT_KEYS[kind])
        if kind == "gateway_ready":
            if event["contract"] != CONTRACT or event["source_sha"] != HERMES_SOURCE_SHA:
                _fail("gateway_identity")
            _enum(event["compatibility"], ("passed",), "gateway_compatibility")
        elif kind == "submit":
            ref = _synthetic_ref(event["request_ref"], "request_ref")
            if ref in request_refs:
                _fail("duplicate_request_ref")
            request_refs.add(ref)
            _enum(event["result"], SUBMIT_RESULTS, "submit_result")
        elif kind == "server_event":
            _enum(event["name"], SERVER_EVENTS, "server_event_name")
            _synthetic_ref(event["request_ref"], "server_request_ref")
            if TURN_REF.fullmatch(event["turn_ref"]) is None:
                _fail("server_turn_ref")
            _synthetic_ref(event["session_ref"], "server_session_ref")
        elif kind == "transport_loss":
            _enum(event["reason"], UNCERTAIN_REASONS, "transport_loss_reason")
        elif kind == "restore_history":
            _enum(event["prompt_presence"], RESTORE_PROMPT_PRESENCE[1:], "prompt_presence")
        elif kind == "restore_status":
            _enum(event["turn_state"], RESTORE_TURN_STATES[1:], "turn_state")
        elif kind == "user_decision":
            _enum(event["action"], USER_ACTIONS, "user_action")
        elif kind == "automatic_retry":
            _string(event["method"], "retry_method")
        elif kind == "read_retry":
            method = _string(event["method"], "read_method")
            if method not in AUTOMATIC_RETRY_METHODS:
                _fail("read_method")
            _enum(event["result"], ("transient_error", "success"), "read_result")
        elif kind == "interrupt_result":
            _enum(event["result"], ("confirmed", "rejected", "unknown"), "interrupt_result")
        elif kind == "cancel":
            _enum(event["where"], ("before_submit", "submitting", "restoring"), "cancel_where")
        elif kind == "compatibility_failure":
            _enum(event["reason"], ("attestation_mismatch", "probe_failure", "required_surface_missing"), "compatibility_reason")
        elif kind == "unknown_event":
            if event["name"] != "unknown.interactive":
                _fail("unknown_event_name")


def _validate_expected(expected: Any) -> None:
    _keys(expected, EXPECTED_KEYS)
    trace = expected["trace"]
    if type(trace) is not list or not trace or any(item not in STATES for item in trace):
        _fail("trace")
    _enum(expected["final_state"], STATES, "final_state")
    if expected["final_state"] != trace[-1]:
        _fail("trace_final_state")
    transport_trace = expected["transport_trace"]
    if type(transport_trace) is not list or not transport_trace or any(item not in TRANSPORT_STATES for item in transport_trace):
        _fail("transport_trace")
    _enum(expected["final_transport_state"], TRANSPORT_STATES, "final_transport_state")
    if expected["final_transport_state"] != transport_trace[-1]:
        _fail("transport_trace_final_state")
    _nullable_string(expected["selected_session"], "selected_session")
    if expected["selected_session"] is not None:
        _synthetic_ref(expected["selected_session"], "selected_session")
    _enum(expected["draft_state"], ("present", "absent"), "expected_draft_state")
    if expected["final_state"] == "delivery_uncertain" and expected["draft_state"] != "present":
        _fail("uncertain_draft_required")
    for key in ("submission_count", "duplicate_attempts", "outward_changes", "idempotent_collection_retries"):
        value = _int(expected[key], key)
        if value < 0 or value > 8:
            _fail(key)
    _enum(expected["restore_barrier"], ("not_required", "pending", "passed", "inconclusive"), "restore_barrier")
    _enum(expected["prompt_retry"], ("none", "explicit_user_only", "blocked"), "prompt_retry")
    _bool(expected["automatic_retry"], "automatic_retry")
    _bool(expected["explicit_action_required"], "explicit_action_required")
    _enum(expected["server_prompt_presence"], RESTORE_PROMPT_PRESENCE, "expected_prompt_presence")
    _enum(expected["server_turn_state"], RESTORE_TURN_STATES, "expected_turn_state")
    _string(expected["decision"], "decision")
    _nullable_string(expected["contract_error"], "contract_error")


def _append_state(trace: list[str], state: str) -> None:
    if trace[-1] != state:
        trace.append(state)


def _append_transport(trace: list[str], state: str) -> None:
    if trace[-1] != state:
        trace.append(state)


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    initial = case["initial"]
    state = initial["chat_state"]
    transport = initial["transport_state"]
    selected_session = initial["session_ref"]
    draft_state = initial["draft_state"]
    submission_count = initial["submission_count"]
    duplicate_attempts = 0
    restore_barrier = "pending" if state == "delivery_uncertain" else "not_required"
    prompt_retry = "none"
    automatic_retry = False
    explicit_action_required = False
    # An initial uncertain/active state represents an already-recorded outward
    # submission. New changes are counted only when this trace sends one.
    outward_changes = 1 if submission_count > 0 and state in ("delivery_uncertain", "streaming", "awaiting_approval", "awaiting_clarification", "interrupting") else 0
    idempotent_collection_retries = 0
    server_prompt_presence = "present" if state in ("streaming", "awaiting_approval", "awaiting_clarification", "interrupting") else "not_observed"
    server_turn_state = "running" if server_prompt_presence == "present" else "not_observed"
    decision = "pending"
    contract_error: str | None = None
    intent: str | None = "interrupt" if state == "interrupting" else ("prompt" if state in ("submitting", "streaming", "delivery_uncertain") else None)
    pending_result: str | None = None
    resend_armed = False
    rejection_retry_armed = False
    resend_reason: str | None = None
    duplicate_blocked = False
    active_request_ref = initial["active_request_ref"]
    active_turn_ref = initial["active_turn_ref"]
    seen_requests: set[str] = {active_request_ref} if active_request_ref is not None else set()
    gateway_ready_seen = False
    compatibility_state = "unknown"
    # History and status are separate restore reads. A successful retry of one
    # must never erase a transient failure recorded for the other.
    history_read_failed = False
    status_read_failed = False
    restore_history_seen = False
    restore_status_seen = False
    signed_out = False
    state_trace = [state]
    transport_trace = [transport]

    def transition(next_state: str) -> None:
        nonlocal state
        state = next_state
        _append_state(state_trace, next_state)

    def change_transport(next_transport: str) -> None:
        nonlocal transport
        transport = next_transport
        _append_transport(transport_trace, next_transport)

    def contract_failure(error: str) -> None:
        nonlocal contract_error, decision, prompt_retry, restore_barrier
        previous_state = state
        contract_error = error
        prompt_retry = "blocked"
        if error == "prompt_retry_requires_restore":
            decision = "automatic_prompt_retry_blocked"
        else:
            decision = error
        if previous_state == "restoring":
            restore_barrier = "inconclusive"
        transition("failed")
        change_transport("incompatible")

    def reject_after_sign_out() -> None:
        nonlocal contract_error, decision, prompt_retry, explicit_action_required
        nonlocal resend_armed, rejection_retry_armed, restore_barrier, intent, pending_result
        nonlocal active_request_ref, active_turn_ref, gateway_ready_seen, compatibility_state
        nonlocal history_read_failed, status_read_failed
        nonlocal restore_history_seen, restore_status_seen, server_prompt_presence, server_turn_state
        contract_error = "signed_out_latch"
        decision = "signed_out_latch"
        prompt_retry = "blocked"
        explicit_action_required = False
        resend_armed = False
        rejection_retry_armed = False
        restore_barrier = "pending"
        active_request_ref = None
        active_turn_ref = None
        gateway_ready_seen = False
        compatibility_state = "unknown"
        history_read_failed = False
        status_read_failed = False
        restore_history_seen = False
        restore_status_seen = False
        server_prompt_presence = "not_observed"
        server_turn_state = "not_observed"
        intent = None
        pending_result = None
        seen_requests.clear()

    for event in case["events"]:
        kind = event["kind"]
        if signed_out:
            reject_after_sign_out()
            continue
        if contract_error is not None:
            _fail("events_after_contract_error")
        if kind == "gateway_ready":
            if signed_out or transport in ("offline", "incompatible"):
                contract_failure("gateway_not_allowed")
                continue
            if state not in ("ready", "submitting", "streaming", "delivery_uncertain", "interrupting", "restoring"):
                contract_failure("gateway_not_allowed")
                continue
            gateway_ready_seen = True
            compatibility_state = "passed"
            change_transport("ready")
        elif kind == "submit":
            ref = event["request_ref"]
            if ref in seen_requests:
                _fail("duplicate_request_ref")
            seen_requests.add(ref)
            allowed = (
                state == "ready"
                and selected_session is not None
                and transport == "ready"
                and gateway_ready_seen
                and compatibility_state == "passed"
                and draft_state == "present"
                and restore_barrier in ("not_required", "passed")
            )
            if not allowed:
                contract_failure("prompt_submit_not_ready")
                continue
            submission_count += 1
            outward_changes += 1
            active_request_ref = ref
            active_turn_ref = "turn-marker-" + ref.rsplit("-", 1)[-1]
            server_prompt_presence = "not_observed"
            server_turn_state = "not_observed"
            history_read_failed = False
            status_read_failed = False
            restore_history_seen = False
            restore_status_seen = False
            intent = "prompt"
            pending_result = event["result"]
            resend_armed = False
            rejection_retry_armed = False
            transition("submitting")
            if event["result"] == "rejected":
                server_prompt_presence = "absent"
                server_turn_state = "rejected"
                prompt_retry = "explicit_user_only"
                explicit_action_required = True
                rejection_retry_armed = True
                decision = "confirmed_rejection"
                transition("failed")
            elif event["result"] == "accepted":
                server_prompt_presence = "present"
            elif event["result"] == "pending":
                server_prompt_presence = "not_observed"
            elif event["result"] == "unknown":
                server_prompt_presence = "unknown"
                server_turn_state = "unknown"
        elif kind == "server_event":
            name = event["name"]
            correlated = (
                state in ("submitting", "streaming", "awaiting_approval", "awaiting_clarification")
                and transport == "ready"
                and gateway_ready_seen
                and compatibility_state == "passed"
                and selected_session == event["session_ref"]
                and active_request_ref == event["request_ref"]
                and active_turn_ref == event["turn_ref"]
            )
            if not correlated:
                contract_failure("server_event_not_correlated")
                continue
            if name in ("message.delta", "reasoning.delta", "thinking.delta", "tool.start", "tool.complete"):
                server_prompt_presence = "present"
                server_turn_state = "running"
                transition("streaming")
                if decision == "pending":
                    decision = "accepted_present"
            elif name == "message.complete":
                server_prompt_presence = "present"
                server_turn_state = "completed"
                draft_state = "absent"
                transition("completed")
                if resend_reason == "absent_idle":
                    decision = "resent_after_absent_idle"
                elif resend_reason == "rejection":
                    decision = "accepted_after_confirmed_rejection"
                elif duplicate_blocked:
                    decision = "duplicate_blocked"
                elif state_trace.count("delivery_uncertain") > 0:
                    decision = "accepted_present_after_restore"
                else:
                    decision = "accepted_present"
            elif name == "approval.request":
                server_prompt_presence = "present"
                server_turn_state = "running"
                transition("awaiting_approval")
            elif name == "clarify.request":
                server_prompt_presence = "present"
                server_turn_state = "running"
                transition("awaiting_clarification")
        elif kind == "transport_loss":
            gateway_ready_seen = False
            compatibility_state = "unknown"
            restore_history_seen = False
            restore_status_seen = False
            history_read_failed = False
            status_read_failed = False
            change_transport("reconnecting")
            if state in ("submitting", "streaming") and intent == "prompt":
                transition("delivery_uncertain")
                restore_barrier = "pending"
                draft_state = "present"
                server_prompt_presence = "unknown"
                server_turn_state = "unknown"
                pending_result = "unknown"
                resend_armed = False
                rejection_retry_armed = False
                explicit_action_required = False
            elif state == "interrupting":
                restore_barrier = "pending"
                server_prompt_presence = "unknown"
                server_turn_state = "unknown"
            elif state in ("awaiting_approval", "awaiting_clarification"):
                contract_failure("interactive_result_unknown")
        elif kind == "restore_begin":
            if state not in ("delivery_uncertain", "interrupting", "restoring"):
                contract_failure("restore_not_required")
                continue
            if transport not in ("reconnecting", "handshaking", "offline"):
                contract_failure("restore_transport_not_reconnecting")
                continue
            gateway_ready_seen = False
            compatibility_state = "unknown"
            restore_history_seen = False
            restore_status_seen = False
            history_read_failed = False
            status_read_failed = False
            server_prompt_presence = "not_observed"
            server_turn_state = "not_observed"
            transition("restoring")
            restore_barrier = "pending"
        elif kind == "read_retry":
            method = event["method"]
            read_gate = (
                transport == "ready"
                and gateway_ready_seen
                and compatibility_state == "passed"
                and selected_session is not None
            )
            state_gate = state == "restoring" if method in ("session.history", "session.status") else state in (
                "ready",
                "restoring",
                "streaming",
                "awaiting_approval",
                "awaiting_clarification",
                "interrupting",
            )
            if not read_gate or not state_gate:
                contract_failure("read_retry_without_restore")
                continue
            automatic_retry = True
            if event["result"] == "transient_error":
                if method == "session.history":
                    history_read_failed = True
                    # A failed history read invalidates the prior presence and
                    # any status paired with it. A later status cannot reuse it.
                    restore_history_seen = False
                    restore_status_seen = False
                    server_prompt_presence = "unknown"
                    server_turn_state = "unknown"
                elif method == "session.status":
                    status_read_failed = True
                    restore_status_seen = False
                    server_turn_state = "unknown"
            elif method == "session.history" and history_read_failed:
                idempotent_collection_retries += 1
                history_read_failed = False
            elif method == "session.status" and status_read_failed:
                idempotent_collection_retries += 1
                status_read_failed = False
        elif kind == "restore_history":
            if state != "restoring" or transport != "ready" or not gateway_ready_seen or compatibility_state != "passed":
                contract_failure("history_without_restore")
                continue
            if history_read_failed:
                contract_failure("restore_history_read_failed")
                continue
            restore_history_seen = True
            server_prompt_presence = event["prompt_presence"]
        elif kind == "restore_status":
            if state != "restoring" or transport != "ready" or not gateway_ready_seen or compatibility_state != "passed":
                contract_failure("status_without_restore")
                continue
            if status_read_failed:
                contract_failure("restore_status_read_failed")
                continue
            if not restore_history_seen:
                contract_failure("history_required_before_status")
                continue
            restore_status_seen = True
            server_turn_state = event["turn_state"]
            if server_prompt_presence == "unknown" or server_turn_state == "unknown":
                restore_barrier = "inconclusive"
                transition("delivery_uncertain" if intent == "prompt" else "interrupting")
                decision = "restore_inconclusive"
            elif intent == "prompt" and server_prompt_presence == "present" and server_turn_state in ("running", "streaming"):
                restore_barrier = "passed"
                transition("streaming")
                decision = "accepted_present_after_restore"
            elif intent == "prompt" and server_prompt_presence == "present" and server_turn_state == "completed":
                restore_barrier = "passed"
                draft_state = "absent"
                transition("completed")
                decision = "accepted_present_after_restore"
            elif intent == "prompt" and server_prompt_presence == "absent" and server_turn_state == "idle":
                restore_barrier = "passed"
                transition("ready")
                prompt_retry = "explicit_user_only"
                explicit_action_required = True
                resend_armed = True
                decision = "absent_idle_wait_user"
            elif intent == "interrupt" and server_turn_state in ("running", "streaming"):
                restore_barrier = "passed"
                transition("streaming")
                decision = "interrupt_unknown_after_restore"
            elif intent == "interrupt" and server_turn_state in ("completed", "idle"):
                restore_barrier = "passed"
                transition("completed")
                decision = "interrupt_confirmed_after_restore"
            else:
                contract_failure("restore_evidence_mismatch")
        elif kind == "user_decision":
            action = event["action"]
            if action == "resend" and resend_armed and restore_barrier == "passed" and server_prompt_presence == "absent" and server_turn_state == "idle" and transport == "ready" and gateway_ready_seen and compatibility_state == "passed":
                resend_armed = False
                resend_reason = "absent_idle"
                explicit_action_required = True
                transition("ready")
            elif action == "retry_after_rejection" and rejection_retry_armed and state == "failed" and transport == "ready" and gateway_ready_seen and compatibility_state == "passed":
                rejection_retry_armed = False
                resend_reason = "rejection"
                explicit_action_required = True
                contract_error = None
                prompt_retry = "explicit_user_only"
                transition("ready")
            elif action == "keep_draft" and (resend_armed or state == "delivery_uncertain"):
                had_resend_evidence = resend_armed
                resend_armed = False
                rejection_retry_armed = False
                explicit_action_required = True
                decision = "user_kept_draft"
                if had_resend_evidence or restore_barrier == "passed":
                    transition("ready")
                else:
                    # Keeping a draft before restore does not prove delivery.
                    # Remain uncertain so the declared restore action remains
                    # legal and can later authorize one explicit resend.
                    transition("delivery_uncertain")
            else:
                contract_failure("user_decision_not_allowed")
        elif kind == "duplicate_submit":
            if state not in ("submitting", "streaming"):
                contract_failure("duplicate_submit_not_allowed")
                continue
            duplicate_attempts += 1
            duplicate_blocked = True
            decision = "duplicate_blocked"
        elif kind == "automatic_retry":
            method = event["method"]
            if method == "prompt.submit":
                explicit_action_required = False
                contract_failure("prompt_retry_requires_restore")
                continue
            if method not in AUTOMATIC_RETRY_METHODS:
                contract_failure("retry_method_not_idempotent")
                continue
            retry_gate = (
                transport == "ready"
                and gateway_ready_seen
                and compatibility_state == "passed"
                and selected_session is not None
            )
            if method in ("session.history", "session.status"):
                retry_gate = retry_gate and state == "restoring"
            else:
                retry_gate = retry_gate and state in (
                    "ready",
                    "restoring",
                    "streaming",
                    "awaiting_approval",
                    "awaiting_clarification",
                    "interrupting",
                )
            if not retry_gate:
                contract_failure("automatic_retry_not_ready")
                continue
            automatic_retry = True
        elif kind == "interrupt_request":
            if state != "streaming" or transport != "ready" or not gateway_ready_seen or compatibility_state != "passed":
                contract_failure("interrupt_not_active")
                continue
            intent = "interrupt"
            outward_changes += 1
            transition("interrupting")
        elif kind == "interrupt_result":
            if state != "interrupting" or transport != "ready" or not gateway_ready_seen or compatibility_state != "passed":
                contract_failure("interrupt_result_not_pending")
                continue
            if event["result"] == "confirmed":
                server_prompt_presence = "present"
                server_turn_state = "completed"
                transition("completed")
                decision = "interrupt_confirmed"
            elif event["result"] == "rejected":
                transition("failed")
                decision = "interrupt_rejected"
            else:
                decision = "interrupt_unknown"
        elif kind == "cancel":
            where = event["where"]
            if where == "before_submit" and state == "ready" and submission_count == 0:
                decision = "cancelled_before_submit"
            elif where == "submitting" and state == "submitting":
                # A local cancellation does not prove whether prompt.submit
                # reached Hermes. Force the same restore barrier as a lost
                # transport before any later user-authorized resend.
                draft_state = "present"
                gateway_ready_seen = False
                compatibility_state = "unknown"
                restore_history_seen = False
                restore_status_seen = False
                history_read_failed = False
                status_read_failed = False
                server_prompt_presence = "unknown"
                server_turn_state = "unknown"
                pending_result = "unknown"
                resend_armed = False
                rejection_retry_armed = False
                explicit_action_required = False
                restore_barrier = "pending"
                change_transport("reconnecting")
                transition("delivery_uncertain")
                decision = "cancelled_submission_uncertain"
            elif where == "restoring" and state == "restoring":
                transition("delivery_uncertain")
                restore_barrier = "pending"
                explicit_action_required = False
                decision = "cancelled_restore"
            else:
                contract_failure("cancel_not_safe")
        elif kind == "sign_out":
            # Signing out is a terminal local boundary for this authenticated
            # session. Clear every armed retry/read/request reference before
            # latching offline so stale callbacks cannot rearm a send.
            signed_out = True
            selected_session = None
            gateway_ready_seen = False
            compatibility_state = "unknown"
            resend_armed = False
            rejection_retry_armed = False
            explicit_action_required = False
            prompt_retry = "blocked"
            history_read_failed = False
            status_read_failed = False
            restore_history_seen = False
            restore_status_seen = False
            active_request_ref = None
            active_turn_ref = None
            server_prompt_presence = "not_observed"
            server_turn_state = "not_observed"
            restore_barrier = "pending"
            intent = None
            pending_result = None
            seen_requests.clear()
            change_transport("offline")
            transition("empty")
            decision = "signed_out_safe"
        elif kind == "compatibility_failure":
            contract_error = "compatibility_evidence_required"
            prompt_retry = "blocked"
            restore_barrier = "inconclusive" if state == "restoring" else restore_barrier
            decision = "incompatible_evidence"
            transition("failed")
            change_transport("incompatible")
        elif kind == "unknown_event":
            contract_error = "unsupported_interactive_event"
            prompt_retry = "blocked"
            decision = "unknown_interactive_event_blocked"
            transition("failed")
            change_transport("incompatible")
        elif kind == "evidence_pending":
            if state != "restoring":
                contract_failure("evidence_not_pending")
                continue
            decision = "evidence_pending"
            transition("restoring")

    if decision == "pending":
        if state == "empty":
            decision = "empty_noop"
        elif state == "submitting":
            decision = "submission_pending"
        elif state == "delivery_uncertain":
            decision = "delivery_uncertain"
    if intent == "prompt" and state == "delivery_uncertain" and restore_barrier == "not_required":
        restore_barrier = "pending"
    if state == "delivery_uncertain" and prompt_retry == "none" and contract_error is None and decision != "restore_inconclusive":
        prompt_retry = "none"

    return {
        "trace": state_trace,
        "final_state": state,
        "transport_trace": transport_trace,
        "final_transport_state": transport,
        "selected_session": selected_session,
        "draft_state": draft_state,
        "submission_count": submission_count,
        "duplicate_attempts": duplicate_attempts,
        "restore_barrier": restore_barrier,
        "prompt_retry": prompt_retry,
        "automatic_retry": automatic_retry,
        "explicit_action_required": explicit_action_required,
        "outward_changes": outward_changes,
        "idempotent_collection_retries": idempotent_collection_retries,
        "server_prompt_presence": server_prompt_presence,
        "server_turn_state": server_turn_state,
        "decision": decision,
        "contract_error": contract_error,
    }


def _validate_distribution(distribution: Any, samples: list[float]) -> None:
    _keys(distribution, DISTRIBUTION_KEYS)
    if type(distribution["count"]) is not int or distribution["count"] != len(samples):
        _fail("baseline_distribution")
    for key in DISTRIBUTION_KEYS[1:]:
        value = distribution[key]
        if type(value) is not float or not math.isfinite(value) or not 0 < value <= MAX_SAMPLE_MS:
            _fail("baseline_distribution")
    try:
        expected = _distribution(samples)
    except ContractError:
        raise
    except (OverflowError, ValueError, TypeError, statistics.StatisticsError):
        _fail("baseline_arithmetic")
    if distribution != expected:
        _fail("baseline_distribution")


def validate_baseline(
    baseline: dict[str, Any],
    *,
    fixture_dir: Path | None = None,
    trusted_baseline: dict[str, Any] | None = None,
) -> int:
    expected_keys = ("schema", "operation", "contract", "hermes_source_sha", "synthetic_only", "metric", "deterministic_fixture", "environment", "threshold", "artifacts", "artifact_manifest_sha256", "normal", "optimized")
    _keys(baseline, expected_keys)
    if baseline["schema"] != BASELINE_SCHEMA or baseline["operation"] != OPERATION or baseline["contract"] != CONTRACT:
        _fail("baseline_identity")
    if baseline["hermes_source_sha"] != HERMES_SOURCE_SHA or _bool(baseline["synthetic_only"], "baseline_synthetic_only") is not True:
        _fail("baseline_identity")
    if baseline["metric"] != "validator_process_duration_ms" or baseline["deterministic_fixture"] != "cases.json":
        _fail("baseline_metric")
    environment = baseline["environment"]
    if not isinstance(environment, dict) or tuple(environment.keys()) != tuple(EXPECTED_ENVIRONMENT.keys()):
        _fail("baseline_environment")
    for key, expected in EXPECTED_ENVIRONMENT.items():
        if type(environment[key]) is not str or environment[key] != expected:
            _fail("baseline_environment")
    if baseline["threshold"] is not None:
        _fail("baseline_threshold")
    artifacts = baseline["artifacts"]
    if not isinstance(artifacts, dict) or tuple(artifacts.keys()) != CANONICAL_ARTIFACT_NAMES:
        _fail("baseline_artifacts")
    for name in CANONICAL_ARTIFACT_NAMES:
        entry = artifacts[name]
        if not isinstance(entry, dict) or tuple(entry.keys()) != ("bytes", "sha256"):
            _fail("baseline_artifact_entry")
        if type(entry["bytes"]) is not int or entry["bytes"] <= 0 or not HEX64.fullmatch(str(entry["sha256"])):
            _fail("baseline_artifact_entry")
    directory = fixture_dir or _trusted_fixture_directory()
    actual_artifacts, actual_manifest = _artifact_manifest(directory)
    if actual_artifacts != artifacts or actual_manifest != baseline["artifact_manifest_sha256"]:
        _fail("baseline_artifacts")
    total_samples = 0
    for mode in ("normal", "optimized"):
        record = baseline[mode]
        if not isinstance(record, dict) or tuple(record.keys()) != (
            "external_launcher_sha256",
            "python_flags",
            "target",
            "repetitions",
            "samples_ms",
            "distribution",
        ):
            _fail("baseline_mode")
        expected_mode = APPROVED_MODE_EVIDENCE[mode]
        if record["external_launcher_sha256"] != EXTERNAL_LAUNCHER_SHA256:
            _fail("baseline_launcher")
        if record["python_flags"] != expected_mode["python_flags"] or record["target"] != expected_mode["target"]:
            _fail("baseline_invocation")
        if type(record["repetitions"]) is not int or record["repetitions"] != BENCHMARK_REPETITIONS:
            _fail("baseline_repetitions")
        samples = record["samples_ms"]
        if type(samples) is not list or len(samples) != BENCHMARK_REPETITIONS:
            _fail("baseline_samples")
        if any(type(sample) is not float or not math.isfinite(sample) or not 0 < sample <= MAX_SAMPLE_MS for sample in samples):
            _fail("baseline_samples")
        _validate_distribution(record["distribution"], samples)
        total_samples += len(samples)
    trusted = trusted_baseline or _load_trusted_baseline()
    if baseline != trusted:
        _fail("baseline_identity")
    return total_samples


def validate_canonical_identity(
    document: dict[str, Any],
    baseline: dict[str, Any],
    *,
    cases_path: Path | None = None,
    baseline_path: Path | None = None,
    executing_path: Path | None = None,
) -> None:
    root = _repository_root()
    trusted = root / CANONICAL_FIXTURE_RELATIVE
    _require_bound_artifacts(root)
    _require_exact_trusted_file(cases_path or CASES_PATH, trusted / "cases.json", "cases_identity")
    _require_exact_trusted_file(baseline_path or BASELINE_PATH, trusted / "validation-baseline.json", "baseline_identity")
    _require_exact_trusted_file(executing_path or Path(__file__), trusted / "validate.py", "source_identity")
    trusted_document = _load_trusted_document()
    trusted_baseline = _load_trusted_baseline()
    if document != trusted_document:
        _fail("cases_identity")
    validate_baseline(baseline, fixture_dir=trusted, trusted_baseline=trusted_baseline)
    artifacts, manifest = _artifact_manifest(trusted)
    if baseline["artifacts"] != artifacts or baseline["artifact_manifest_sha256"] != manifest:
        _fail("artifact_identity")


def validate_all(
    document: dict[str, Any],
    baseline: dict[str, Any],
    *,
    fixture_dir: Path | None = None,
    cases_path: Path | None = None,
    baseline_path: Path | None = None,
    executing_path: Path | None = None,
) -> int:
    validate_document(document)
    validate_canonical_identity(
        document,
        baseline,
        cases_path=cases_path or (fixture_dir / "cases.json" if fixture_dir else None),
        baseline_path=baseline_path or (fixture_dir / "validation-baseline.json" if fixture_dir else None),
        executing_path=executing_path,
    )
    return len(document["cases"])


class _SilentArgumentParser(argparse.ArgumentParser):
    """Keep invalid CLI input on the fixed, bounded diagnostic path."""

    def error(self, message: str) -> None:
        _fail("invalid_arguments")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = _SilentArgumentParser(add_help=False)
    parser.add_argument("--cases", default=str(CASES_PATH))
    parser.add_argument("--baseline", default=str(BASELINE_PATH))
    parser.add_argument("--help", action="store_true")
    try:
        return parser.parse_args(argv)
    except SystemExit:
        _fail("invalid_arguments")
    raise ContractError("invalid_arguments")


def _error_line(code: str) -> str:
    # Keep errors stable and caller-independent.  Never include a path, flag,
    # parser detail, duplicate key, or untrusted semantic marker.
    return json.dumps({"error": {"code": "contract", "message": "uncertain delivery fixture rejected"}}, separators=(",", ":"))[:MAX_ERROR_LENGTH]


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(list(sys.argv[1:] if argv is None else argv))
        if args.help:
            return 0
        cases_path = Path(args.cases)
        baseline_path = Path(args.baseline)
        document = load_json(cases_path, "cases")
        baseline = load_json(baseline_path, "baseline")
        count = validate_all(
            document,
            baseline,
            cases_path=cases_path,
            baseline_path=baseline_path,
            executing_path=Path(__file__),
        )
        print(f"uncertain_delivery_validation=ok cases={count} benchmark_samples={BENCHMARK_REPETITIONS * 2}")
        return 0
    except ContractError as exc:
        sys.stderr.write(_error_line(exc.code) + "\n")
        return 1
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, statistics.StatisticsError):
        sys.stderr.write(_error_line("contract_rejected") + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
