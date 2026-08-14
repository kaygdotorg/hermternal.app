# Scripts

This directory contains small, deterministic repository tools. The roadmap
validator is a planning-only source check; it does not contact GitHub, Paper,
Hermes, or any other service.

## Roadmap template validator

Run it from the repository root:

```text
python3 scripts/validate_roadmap_template.py
```

Pass another local file when testing a mutation:

```text
python3 scripts/validate_roadmap_template.py path/to/roadmap.md
```

The command reads bytes, rejects invalid UTF-8, accepts a consistent LF or CRLF
style, and emits one JSON object. Invalid input exits non-zero and reports
stable error codes with one-based line numbers. The contract covers the exact
front matter, ten ordered H2 sections, required subsections and fields, the
canonical Paper URL, the `text` verification fence, and twelve ordered
unchecked definition-of-done items.

`test_validate_roadmap_template.py` runs the checked-in template plus 14
mutation families covering missing, duplicate, reordered, unknown, malformed,
checked, line-ending, and invalid-UTF-8 cases. It also proves that one stateful
Markdown scan ignores multiline HTML comments and arbitrary backtick or tilde
fences while retaining the visible section-8 command fence contract. Keep
fixtures synthetic and local. Do not add live Hermes calls, credentials,
cookies, WebSocket tickets, transcripts, provider data, secrets, hostnames,
user data, or deployment configuration to a script or test.

## Implementation proof-gate validator

Run the fail-closed implementation checklist validator from the repository root:

```text
python3 scripts/validate_proof_gates.py
```

The four-file proof-gate contract is owned by
`docs/product/implementation-proof-gates.md`, `scripts/validate_proof_gates.py`,
`scripts/test_validate_proof_gates.py`, and this README. The checklist maps the
M0 planning, source-audit, issue-template, route, fixture, Paper,
deployment/security, benchmark, accessibility, no-network, review, evidence,
and dev-integration requirements to their roadmap issues. Runtime, deployment,
live-adjacent, and release proofs remain later ordered gates; they are not M0
prerequisites.

The validator is standard-library-only and offline. It checks exact section and
subsection order, canonical roadmap keys and links, gate and evidence rows,
dependency direction, required fields, inline N/A rationales, the explicit
no-threshold statement, no live/production success claims, no-network command
shapes, and parity with the atomic issue-template contract. Measured evidence may
report observations, but target, budget, SLO, limit, and bound prose still fails
when embedded in the same value. Live claims are checked per punctuation and
conjunction clause, and preservation evidence must name a concrete accessibility
surface plus a non-circular mechanism or reason. Indented Markdown field
continuations are folded before field and semantic checks, including Unicode
numeric comparators; circular or generic reasons such as `because non-UI`
remain blocked. A single stateful Markdown scan hides multiline HTML comments
and arbitrary-length backtick or tilde fences, so hidden or fenced decoys
cannot satisfy a gate.

Success and every failure emit exactly one JSON object. Unknown CLI arguments,
invalid UTF-8, read errors, malformed input, checked or waived gates, and type
confusion fail closed without argparse usage or a traceback. The focused test
suite covers hidden/fenced content, duplicates, reorder, missing/unknown gates
and evidence, wrong issue links, stale blockers, waived status, N/A and
threshold mutations, line endings, invalid UTF-8, CLI failures, and input
boolean/type confusion. Keep all proof fixtures synthetic, redacted, local, and
free of credentials, cookies, tickets, transcripts, provider data, hostnames,
tokens, secrets, or user data.

## Accessibility evidence

- Accessibility is **N/A** for this non-UI command-line artifact: it has no
  focus order, semantic control names, screen-reader surface, VoiceOver,
  Switch Control, Dynamic Type, browser zoom, contrast theme, motion, or touch
  target to exercise.
- Preservation evidence: the validator reads the template bytes and emits
  diagnostics only; it never rewrites the template or removes the template's
  keyboard, semantic, screen-reader, contrast, reduced-motion, or touch-target
  fields. Structural failures remain fail-closed instead of silently accepting
  an inaccessible or incomplete issue contract.

## Reproducible benchmark evidence

This is artifact and local validator evidence, not a product performance budget.
No threshold is claimed.

- Environment: macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.14.6.
- Build mode: N/A — this is a standard-library source script with no production
  or release build.
- Repetitions and distribution: 10 fresh subprocess runs; report min, median,
  and max validator duration in milliseconds.
- Artifact-size evidence from the same checkout: validator `38,208` bytes,
  tests `16,715` bytes, and this README `5,807` bytes.
- Validator-duration evidence from the same checkout: min `41.527` ms, median
  `42.870` ms, max `45.918` ms; every run returned the valid-template JSON result.
- Raw command:

```sh
python3 - <<'PY'
import json, platform, statistics, subprocess, sys, time
from pathlib import Path
paths = [Path('scripts/validate_roadmap_template.py'),
         Path('scripts/test_validate_roadmap_template.py'),
         Path('scripts/README.md')]
durations = []
for _ in range(10):
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, 'scripts/validate_roadmap_template.py',
         '.github/ISSUE_TEMPLATE/roadmap.md'],
        check=False, capture_output=True)
    durations.append((time.perf_counter() - start) * 1000)
    assert result.returncode == 0
print(json.dumps({
    'environment': {'platform': platform.platform(),
                    'python': sys.version.split()[0]},
    'repetitions': 10,
    'distribution_ms': {'min': min(durations),
                        'median': statistics.median(durations),
                        'max': max(durations)},
    'artifact_size_bytes': {str(path): path.stat().st_size for path in paths},
}))
PY
```

Keep the product milestone `v0.0.1` separate from date-based git tags
`vYYYY.MM.DD.<patch-num>`.

## Official Hermes Agent test launcher

`scripts/hermes_agent.py` launches disposable official Hermes Agent instances
for Hermternal browser and Playwright tests. It uses Python's standard library
and direct rootless Podman. Direct `podman run` matches the validated upstream
image path and avoids Compose-provider ambiguity without changing the image's
entrypoint or command behavior.

The default image is pinned by tag and immutable digest:

```text
docker.io/nousresearch/hermes-agent:v2026.8.3@sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e
```

This launcher source pin is an execution input, not Caddy evidence. The issue
#156 retained evidence does not repeat it as a validated deployment identity;
that requires a separate bounded collection and verification step.

The launcher preserves `/opt/hermes/docker/entrypoint-dispatch.sh` and runs
`gateway run`. It publishes only `127.0.0.1:<requested-port>:9119`, creates one
host data directory per instance, and enables a synthetic Basic provider. It
does not build, adapt, retag, relabel, use host networking, mount a host Hermes
profile or container socket, or apply custom capability, CPU, memory, PID,
security, or log settings. The dedicated test VM may use its available
resources.

The marker, launcher-result, and credential-handoff correction suites are
synthetic and mock-only. They use local private files, synthetic credential
bytes, fake Podman responses, and mocked process boundaries; they do not start
Hermes, contact a Dashboard, or read a real credential. The VM command below is
an explicit opt-in lane and is not evidence produced by those offline fixtures.

Run one instance from the repository root on the authorized VM. The caller
must create one existing private `0700` runs directory and choose one exact
canonical absolute marker path inside it. The marker is the only lifecycle
capability; do not enumerate the directory, copy a marker, infer recency, or
reuse a port from an older proof:

```sh
RUNS_DIR="${HERMES_RUNS_DIR:?set an existing private 0700 runs directory}"
MARKER_PATH="${HERMES_MARKER_PATH:?set the exact absolute marker path under that directory}"
INSTANCE="${HERMES_INSTANCE:?set the exact launcher instance name}"
PORT="${HERMES_PORT:?set a free loopback port for this instance}"
if launcher_output="$(
  python3 scripts/hermes_agent.py start \
    --instance "$INSTANCE" \
    --port "$PORT" \
    --marker "$MARKER_PATH"
)"; then
  :
else
  start_status=$?
  # Do not let a failed mutation fall through to an older valid marker proof.
  printf '%s\n' 'Hermes start failed; endpoint handoff skipped.' >&2
  return "$start_status" 2>/dev/null || exit "$start_status"
fi
# `endpoint` is the fail-closed handoff gate. It re-inspects the exact
# persisted container ID and accepts only a running, launcher-owned container
# with one 127.0.0.1:<requested-port>:9119 mapping.
launcher_output="$(python3 scripts/hermes_agent.py endpoint --marker "$MARKER_PATH")"
# Command substitution strips all trailing LF bytes; append exactly one LF for canonical parsing.
endpoint="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
marker_path="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py marker-path)"
run_id="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py run-id)"
credential_file="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
credential_identity="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-identity)"
```

A successful `start` result has `.result.status` `ready`; it is not a handoff
permit. Immediately before credential handoff, `endpoint` freshly pins the
retained immutable container ID to a running launcher-owned container and its
sole explicit `127.0.0.1:<requested-port>:9119` mapping. It also revalidates the
caller-selected marker, credential inode, mode, size, link count, and content
generation. A stopped tombstone, missing/stale mapping, container replacement,
ownership mismatch, rebound port, non-loopback mapping, or changed credential
identity aborts before credential-file use.

Run any requested count with unique names, consecutive loopback ports, and
one caller-supplied marker per instance. Every marker path must be a distinct
canonical path in the same private `0700` runs directory:

```sh
if python3 scripts/hermes_agent.py start-many \
  --prefix "${HERMES_INSTANCE_PREFIX:?set the fleet prefix}" \
  --count 2 \
  --base-port "${HERMES_BASE_PORT:?set the first free loopback port}" \
  --marker "${HERMES_MARKER_1:?set marker 1}" \
  --marker "${HERMES_MARKER_2:?set marker 2}"; then
  :
else
  start_many_status=$?
  # Stop the batch before any per-marker endpoint can select stale proof.
  printf '%s\n' 'Hermes start-many failed; endpoint handoff skipped.' >&2
  return "$start_many_status" 2>/dev/null || exit "$start_many_status"
fi
# This example requests exactly two instances; changing `--count` requires
# the same number of distinct `--marker` options. All markers must remain under
# this one canonical private runs directory; split-parent batches are rejected
# before either marker is opened or any lifecycle operation is dispatched.
```

Before Podman preflight, image pull, or data-root creation, the launcher rejects
non-finite readiness controls, unsupported image pins, malformed existing marker
records, noncanonical or broad private roots, private-root symlinks, stale
sibling records, and occupied new-run ports. Data roots must be absolute,
lexically canonical, and free of `.` or `..` segments. Darwin `/tmp` and `/var`
symlink aliases, alternate `//` spellings, filesystem anchors, and broad roots
such as `/private/tmp`, `/private/var`, and `/usr/local` are rejected. Use a
sufficiently nested canonical caller-specific descendant, such as
`/private/tmp/<private-root>`, instead. Missing private components are created
only through descriptor-relative `openat` operations, with mode `0700` and
identity checks after every open/create; the launcher never pathname-
`mkdir`/`chmod`s the caller-supplied root. New instance leaves are created
beneath a held data-root descriptor, and the parent identity is checked before
and after the child boundary. Failed-create cleanup compares the opened child
device, inode, and mode again, then preserves the leaf and reports bounded
`owned_path_cleanup_failed` evidence: Python exposes no descriptor-atomic exact
-directory deletion operation, so this adapter never enters a pathname `rmdir`
boundary. Subprocess vectors are validated before dispatch:
the executable and every argument must be a non-empty string without NUL bytes,
and malformed or non-string argv produces one bounded launcher error.

`start-many` repeats that record/root/port preflight for every marker before
dispatching the first instance; the batch holds one descriptor-bound parent
lease while each individual start repeats its checks. The preflight is advisory
and the batch remains non-atomic. If a marker parent or data path is replaced
between iterations, the affected marker fails before its next lifecycle
boundary; earlier marker evidence is not rediscovered, adopted, or broadly
rolled back. A later per-marker failure preserves only bounded exact
`partial_results`, adds the `batch_partial_results` secondary code, and leaves
earlier owned runs available for their caller-selected markers. The failed
per-marker transaction retains its own bounded `cleanup_failed` evidence when
exact cleanup cannot finish; callers stop or retry each returned marker
explicitly. Podman accepts a pathname rather than a held host fd, so the
launcher revalidates the canonical data-directory identity immediately before
and after bind/start and mount inspection. An inspect `Mounts[].Source` string
is consistency evidence, not inode proof. A same-user replacement racing the
final pathname syscall is outside this pathname-based adapter's proof boundary;
any replacement observed by the surrounding checks fails closed. Before a
successful ready, endpoint, or status result, the launcher runs a final
all-record fence after its publication hook: marker and state inode/generation,
credential identity/generation, retained parent, stable data identity, and the
exact engine-witnessed container plus cidfile content binding are checked as
applicable. If that hook observes
replacement, new-start cleanup removes the exact immutable container when its
data proof remains valid or retains bounded `cleanup_failed` evidence when it
does not. Stop keeps its final hook inside the evidence-removal transaction and
proves the exact marker, state, credential, and cidfile names remain absent.

Other operations receive the same exact marker path; they never select by
instance name, port, recency, or directory contents. Run them only after the
guarded mutation succeeds:

```sh
# This verifies the immutable container ID, running state, and exact loopback mapping.
launcher_output="$(python3 scripts/hermes_agent.py endpoint --marker "$MARKER_PATH")"
# Command substitution strips all trailing LF bytes; append exactly one LF for canonical parsing.
endpoint="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
marker_path="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py marker-path)"
run_id="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py run-id)"
credential_file="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
credential_identity="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-identity)"
python3 scripts/hermes_agent.py stop --marker "$MARKER_PATH"
```

To stop more than one owned instance, run independently verified exact-marker
stops in sequence:

```sh
python3 scripts/hermes_agent.py stop \
  --marker "${HERMES_MARKER_1:?set marker 1}"
python3 scripts/hermes_agent.py stop \
  --marker "${HERMES_MARKER_2:?set marker 2}"
```

This sequence is intentionally not atomic: a failure may stop between commands,
so inspect and retry each remaining marker explicitly. Cleanup removes only the
marker-pinned container, credential, and state, then
removes the marker last. `--purge-data` is intentionally unsupported by this
strict ownership path; data is never removed by a broad prune or glob. The CLI
rejects that flag before opening the marker lease, so invalid input does not
create `.lifecycle.lock` state.

A successfully parsed operation emits one JSON object. Start, status, stop, and
batch results contain only bounded instance/status/marker metadata. A verified
endpoint result contains exactly six fields: `status`, `endpoint`,
`marker_path`, `run_id`, `credential_file`, and `credential_identity`; it never
contains the password. `run_id` is 64 lowercase
hexadecimal characters. `credential_identity` contains `device`, `inode`,
`mode`, `size`, `nlink`, and a 64-character lowercase hexadecimal `generation`.
The generation is a one-way SHA-256 of the bounded credential bytes, not the
credential itself; it detects same-inode, same-size replacement. Credentials
use mode `0600`. The live credential, state file, and cidfile paths are derived
as siblings beside the exact caller-selected marker, under that marker's
existing private `0700` runs directory. For example, a marker named
`run.json` derives `run.credential`, `run.state.json`, and `run.cidfile` in the
same directory. `--credential-root` does not control live credential placement.
The container data directory defaults to
`~/.local/share/hermternal-tests/hermes-agent/`; that data root is separate from
the marker-bound live files. Each state record also persists the data
directory's stable `device`, `inode`, and `mode` identity; the marker retains
the same identity as an independent witness. Future load, reuse, status,
recovery, cleanup, and endpoint paths require the state and marker witnesses to
match the currently opened directory and reject a replacement under the same
pathname. A state file cannot rewrite its own data identity to authorize a new
replacement tree. Records without `data_identity` are rejected as
`instance_state_invalid`; this prototype has no approved/live records to
migrate, so it never recaptures or adopts an unknown data pathname.

A successful `start` result is `ready`, not a handoff permit. The following
`endpoint` command is the source of truth for the exact caller-selected marker:
it freshly inspects the persisted immutable container ID, requires `running`,
and requires exactly one `127.0.0.1:<requested-port>:9119` Dashboard mapping. It
rejects a stopped tombstone, absent or stale ID, replacement, label/image/mount
mismatch, missing or rebound port, additional mapping, non-loopback publication,
or changed credential identity before any credential-file read.
`read_launcher_result.py` accepts only the closed successful `endpoint` result
with `.result.status` `running` and exposes exactly five selectable fields:
`endpoint`, `marker-path`, `run-id`, `credential-file`, and
`credential-identity`. It requires the producer's canonical compact framing:
`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=True`, and exactly one
trailing LF, with no leading whitespace, pretty-printing, alternate escapes, or
concatenated JSON documents. It reads at most the exact `25,068`-byte maximum
serialized six-key endpoint result from stdin before JSON parsing. This parser-
wide bound is auditable: each of the two path fields independently permits an
absolute 4,096-UTF-8-byte path, whose largest canonical JSON string field is
12,287 bytes (`/` + 2,047 U+07FF scalars plus one escaped backslash, including
quotes); the endpoint uses port `65535`, IDs use their fixed 64-character
widths, and `device` and `inode` use the parser's full accepted 64 decimal
digits rather than a producer or platform-width assumption. With both path
slots set to `/`, the fixed compact document is 500 bytes including its LF; the
exact bound is `500 + 2 * (12,287 - 3) = 25,068`. Fixed status, operation,
identity fields, sorted-key framing, and the final LF account for the remainder. The two paths are independent parser values, so this bound does not
assume producer sibling suffixes. The 4,497-byte producer-shaped sibling case
remains a lower-bound compatibility regression, not the maximum. The parser
rejects duplicate keys, non-finite constants, floats, integers longer than 64
digits, excessive nesting, malformed UTF-8, and lone-surrogate text, and emits
only `launcher_result_invalid` for those failures. Endpoint handoff uses the
exact canonical spelling `http://127.0.0.1:<port>` with no leading-zero port,
path, query, fragment, alternate host, or case variation. The helper never
selects a run, reads a marker, infers a port, or substitutes a remembered
listener. `credential-identity` is emitted as compact JSON and must be handed
to the next command unchanged:

```sh
# Preserve the producer LF that command substitution removed.
run_id="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py run-id)"
credential_file="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
credential_identity="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-identity)"
HERMES_LIVE_TARGET="$endpoint" \
  python3 scripts/with_live_credential.py \
    --marker "$marker_path" \
    --run-id "$run_id" \
    --credential-file "$credential_file" \
    --credential-identity "$credential_identity" \
    -- \
    bun run --cwd apps/web test:e2e:live --grep "browser UI reaches the official Hermes gateway through completion"
```

`with_live_credential.py` requires all four proof options before `--`: the
exact marker path, the matching 64-character lowercase `run_id`, the matching
credential path, and the generation-bearing `credential_identity` object. Each
proof value is bounded, the identity JSON is limited to 4096 bytes, and the
parser rejects duplicate keys, constants, floats, pathological integers, deep
nesting, malformed Unicode, and unknown or repeated options before marker access
or child execution. It loads only that marker, requires a `running` marker,
revalidates the private parent and marker identity, then revalidates credential
inode/mode/size/link count and generation immediately before opening a pinned
non-following non-blocking descriptor. Credential framing accepts a bare
password or one terminal `\n`, `\r`, or `\r\n`; repeated, mixed, or interior
line endings fail closed. The value must contain exactly 48 lowercase
hexadecimal characters. The helper then replaces itself with the child command
and supplies `HERMES_TEST_PASSWORD` only in that child process environment. It
never prints or writes the password; invalid, legacy identity-without-generation,
or replaced input fails locally before the child starts. The handoff resolves
only the reviewed bare `bun` or `node` command names (or exact fixed absolute
candidates), validates the canonical regular file and its parent chain, and
passes that absolute path directly to `execve`; ambient `PATH` lookup is not an
executable-selection boundary. `PW_RUNNER_DEBUG` and `PWDEBUG` are both rejected
before the marker or credential is read: the first can expose worker stderr
outside the redaction boundary and the second changes the deterministic
headless/UI boundary. The child receives an explicit allowlist only: `PATH`,
`HERMES_LIVE_TARGET`, optional `HERMES_TEST_USERNAME`, `PLAYWRIGHT_LIVE_PORT`,
`HERMTERNAL_LIVE_RECONCILIATION`, and the reviewed
screenshot capture/parity/client/review/destination selectors. Inherited
`HERMES_TEST_PASSWORD`, `NODE_OPTIONS`, preload controls, proxy variables,
other `HERMES_*` values, and unrelated secrets are dropped. The validated
password is injected after marker and credential checks. The
launcher-generated `password\n` file format is unchanged. When the optional
screenshot retention gate is enabled, set
`HERMTERNAL_LIVE_SCREENSHOT_REVIEW` to an existing private canonical JSON record
with exactly `{"schema":"hermternal.independent-image-review.v1","decision":"approved","review_kind":"independent-human-visual","image_sha256":"<exact scrubbed PNG SHA-256>"}`. The record is manual review input, but the screenshot helper checks its exact hash against the in-memory PNG before and immediately before publication. Git checkout provenance is read through a fixed canonical executable and an explicit environment that cannot inherit `HERMES_TEST_PASSWORD`, `NODE_OPTIONS`, proxy variables, or unrelated secrets.

Marker publication is a copy/evidence protocol, not a race-free publication
claim. The writer stages bounded bytes on a held descriptor. On Darwin,
`fclonefileat` clones into a fixed `replace-tmp` quarantine slot, not the final
marker name; the complete clone is synced, gated at mode `000`, revalidated by
held descriptor and content, restored to `0600`, and moved to the final name
with no-replace semantics. The fallback uses a direct destination `O_EXCL`
create and the same mode gate. The final pathname is not opened as a complete
readable marker until the Darwin gate and descriptor/content/identity checks
have completed. A destination pathname can still be raced by a non-cooperating
process; held descriptors, exact identities, no-follow opens, and bounded
quarantine preserve evidence or fail closed, but they do not make the pathname
race-free.

Normal launcher marker creation and cleanup publication use a new destination
inode. Existing marker, state, and credential entries are claimed into fixed
no-replace quarantine evidence; the launcher never unlinks a caller-selected
name by pathname alone, overwrites a replacement, or adopts a raced inode. Only
when the bounded quarantine quota is exhausted may cleanup use a held-descriptor
same-inode rewrite for its already-owned marker/state fallback. That fallback
also fails closed on replacement and never turns a foreign pathname into proof.

The private `0700` runs directory is the cooperating-process boundary, not a
privileged isolation boundary. It limits ordinary access by other users; it
does not make a same-user or privileged pathname writer harmless. Readers that
hit the transient mode-`000` marker, an incomplete copy, or a permission/open
error fail closed as invalid (`marker_invalid` or the operation-specific
credential/state error). They do not retry by scanning, infer a different run,
or treat the transient entry as proof; rerun the exact caller-selected
`endpoint` operation after publication settles.

`start` first requires local rootless Podman and verifies the requested official
repository digest. It then polls bounded `GET /api/auth/providers` responses.
Readiness requires HTTP 200 and a `basic` provider with
`supports_password: true`. A failed start with a trusted detached-run adapter receipt and matching
cidfile content proof removes only the exact invocation-owned container, fresh
credential, state, and marker after the immutable run binding is published when
every identity fence allows it. Data remains for diagnosis or retry; if exact
cleanup fails, the private marker and state are retained as a bounded
`cleanup_failed` tombstone. A data-path proof failure can block container
removal, so the tombstone preserves the exact ID and stable data witness for a
later retry after the original tree is restored; it never authorizes the
replacement tree. The receipt is authorized only for the exact adapter-created `CommandResult`
and its exact `InvocationReceipt` object. Both are consumed once: the same
receipt cannot grant authority to another result through rebinding across runner
calls or concurrent adapters, and validation returns a private immutable snapshot rather than the
adapter-owned object. A copied result, separately registered matching receipt,
dataclass replacement, reconstruction, copy/deepcopy, subclass, or field
mutation therefore fails closed. The direct local subprocess
adapter parses the canonical detached-run ID inside its own call, while the
offline FakePodman adapter creates an equivalent bound result from the synthetic
engine object at run time. The ordinary subprocess result, stdout, cidfile,
mutable name, and copied labels do not prove causality by themselves. If no
trusted receipt is present, the launcher fails with
`container_invocation_unproven` before any post-run inspect, publication, start,
stop, or rm target is selected. It retains any existing cidfile and a bounded
`cleanup_failed` tombstone with `UNPROVEN_CONTAINER_ID`. Name-based
`container_exists` is only a pre-run collision gate; it never discovers or
adopts an ID. If an exact-ID inspect is ambiguous, cleanup preserves the marker,
state, credential, and cidfile evidence instead of treating absence as proven.
Stop never sends the sentinel or a cidfile-only ID to Podman; an unknown
tombstone returns `stop_evidence_unproven` without contacting the engine. This
strict marker path does not expose a broad purge operation.
Active rebind of an already-running container is intentionally unsupported;
ordinary running-container reuse is non-destructive. Cleanup never runs a
broad prune or glob and never removes data implicitly.

An existing container is reused only after its launcher labels prove the exact
instance, loopback port, and immutable image identity. A stopped owned
container is started only after the requested port is available, then readiness
is checked. A new run must receive a trusted detached-run adapter receipt bound
to the exact successful `CommandResult`; validation consumes that one-shot
authority and returns an immutable downstream snapshot before selecting any
immutable container ID. The receipt ID must equal the strict canonical stdout
claim and the private cidfile ID; stdout and cidfile remain claims, never
identity sources. The launcher then inspects only that snapshot ID and validates
the copied labels, image, data mount, running state, and loopback mapping. It
never inspects the mutable deterministic name to discover or adopt an ID. A
hostile runner can replace the name with B and copy every label while returning
B in stdout and the cidfile; without an independent receipt for the actual A
invocation, this fails with `container_id_mismatch` or
`container_invocation_unproven` before B reaches inspect, publication, start,
stop, or rm. A nonzero subprocess result preserves `container_start_failed` and
never selects a cidfile-only ID. A runner exception or any untrusted/invalid
result likewise never adopts or destructively removes a cidfile-only ID: it
retains bounded `cleanup_failed` evidence with `UNPROVEN_CONTAINER_ID` and
retains any existing cidfile for later investigation. A malformed, missing,
replaced, or foreign cidfile fails closed and retains bounded private cleanup
evidence rather than publishing `ready`. Each start,
status, endpoint, stop, and credential-read operation captures the runs-directory
device, inode, and `0700` mode at entry, keeps that descriptor through all marker,
state, credential, cidfile, cleanup, and tombstone work, and rechecks that the
caller-selected pathname still names the held directory around every fake-engine
boundary. The data-directory identity is also rechecked immediately before every
successful public start, reuse, recovery, endpoint, and status return; stop
rechecks it immediately before deleting marker/state/credential evidence. If a
created child cannot be removed with a descriptor-atomic operation, cleanup
preserves it and reports bounded `cleanup_failed` evidence rather than risking a
same-name replacement. Marker and state records are capped at 16 KiB before publication.
Quarantine evidence uses 16 fixed slots per kind (`cleanup`, `replace`, and
`replace-tmp`), with at most 48 occupied entries and 131,072 aggregate bytes;
occupied, foreign, inaccessible, or raced slots are retained rather than removed.
When no safe slot remains, cleanup fails closed and rewrites only the already
owned marker/state descriptors into `cleanup_failed` evidence; it never creates
an unbounded name or deletes a raced foreign inode. Marker and state snapshots
also carry bounded content generations. After every fake-engine action, cleanup
and recovery revalidate both the exact identity and generation before deleting,
quarantining, or replacing either record; a same-inode, same-size mutation stays
private evidence rather than being adopted into a tombstone.
Lifecycle actions use the freshly inspected immutable container ID, not the
mutable container name, and rollback re-inspects that same ID before stopping
it. If start, readiness, or state persistence fails, the recovery transaction
attempts one bounded exact-container stop, so an initially stopped container is
not left running. An initially running container is never stopped by the
ordinary reuse path. Foreign or mismatched containers fail closed before any
lifecycle mutation. This is disposable proof tooling for the authorized Hermes
test lane, not production infrastructure; it never prunes unrelated
containers, binds, sockets, listeners, or provider configuration.

Launcher readiness proves only that the configured Dashboard boundary is
available. It does not prove Hermternal chat behavior. Run the separate
Playwright browser-to-Hermes journey before reporting app compatibility.

Offline verification:

```sh
python3 -m py_compile scripts/live_run_marker.py scripts/test_live_run_marker.py
python3 -m py_compile scripts/hermes_agent.py scripts/test_hermes_agent.py
python3 -m py_compile scripts/with_live_credential.py scripts/test_with_live_credential.py
python3 -m py_compile scripts/read_launcher_result.py scripts/test_read_launcher_result.py
python3 scripts/test_live_run_marker.py
python3 scripts/test_hermes_agent.py
python3 scripts/test_with_live_credential.py
python3 scripts/test_read_launcher_result.py
python3 -O scripts/test_live_run_marker.py
python3 -O scripts/test_hermes_agent.py
python3 -m unittest scripts.test_live_run_marker scripts.test_hermes_agent scripts.test_with_live_credential scripts.test_read_launcher_result
python3 -O -m unittest scripts.test_live_run_marker scripts.test_hermes_agent scripts.test_with_live_credential scripts.test_read_launcher_result
```

These suites use local synthetic files, synthetic credential bytes, mocked
process boundaries, and a fake Podman boundary. None starts Hermes, contacts an
endpoint, or reads a real credential. Coverage includes strict closed schemas,
private mode-gated descriptor copies, exact caller-selected marker proof,
run-ID/container binding, generation-bearing credential identity at handoff and
cleanup claim, private cidfile provenance, runs-directory replacement around
status/stop/endpoint windows, credential and state identity replacement,
held-descriptor erasure, partial-write rollback, inter-process lifecycle and
quarantine leases, fixed-slot count/byte saturation, foreign quarantine
preservation, oversized marker/state publication rejection, no-name-unlink
quarantine retention, FIFO and symlink rejection, bounded launcher-result and
proof input, duplicate-free JSON, canonical endpoint spelling, exact one-line
credential framing, Darwin clone-boundary mode gating, malformed runner
normalization, rootless checks, environment cleanup, stopped-container recovery,
exact-once cleanup, and the marker-bound lifecycle commands documented by the
Hermes deployment skill. The handoff tests exercise the real shell quoting for
`credential_identity`, reject the obsolete positional helper form, validate the
skill's `.claude` symlink alias, and parse corrected launcher argv without
crossing the Podman boundary. This command-line artifact has no UI, focus,
screen-reader, browser-zoom, contrast, motion, or touch-target surface;
accessibility checks are N/A.

## Disposable Caddy proof renderer

`scripts/caddy_proof.py` is a proof-only renderer for issue #156. It is not a
production deployment file and it does not implement Traefik. It emits exact
method/path matchers for the PR #291 static client at `/`, the reviewed Hermes
routes under one `/hermes` prefix, and separate chat and PTY WebSocket
contracts. Chat accepts one non-empty safe opaque ticket bounded to 512
characters; bare query markers are denied. Canonical session and message deep
links rewrite to `200.html`; only the reviewed root
`scenario=success|empty|failure` selector and exact OAuth callback forms accept a
query: either non-empty safe ASCII `code` and `state` values, or literal
`error=access_denied` with non-empty safe ASCII `error_description` and `state`;
each value is bounded to 512 characters and key order is independent. Static
assets, client routes, and other REST routes reject query mutations. The
current browser PTY client sends only ticket plus resume with optional non-empty
attach, accepts any key order, and rejects duplicate, extra, empty, and
unsupported `fresh` parameters at the edge. The renderer strips
all inbound `Forwarded`, `X-Forwarded-*`, and `X-Real-IP` headers before
rebuilding trusted public metadata, and applies the private upstream
Host/Origin mapping and current `Secure` cookie rewrite. The local mock emits
no `Set-Cookie`, so `cookie_proof.status` remains `not_proven`; `HttpOnly`,
`SameSite`, and `Path` attributes are not proven by this fixture. Caddy's
canonical formatter uses tabs, so the renderer emits
that form directly; the runtime digest therefore covers the exact file that
was validated.

The evidence also records a deterministic runtime-input manifest and the
SHA-256 identities of the shared static-route grammar and deep-link fixture.
The black-box test starts local Caddy beside a recording mock upstream and
checks actual paths, bodies, prefixes, headers, deep links, query denials, and
upgrade results. It does not contact Hermes or the disposable VM during this
correction lane. The black-box check requires an available `caddy` tool and
`openssl`; missing tools are a hard failure, not a skip, and a skipped check is
not evidence.

Offline verification from the repository root:

```sh
python3 scripts/test_caddy_proof.py
python3 -O scripts/test_caddy_proof.py
python3 -m unittest discover -s scripts -p 'test_caddy_proof.py'
python3 -O -m unittest discover -s scripts -p 'test_caddy_proof.py'
python3 -m py_compile \
  scripts/caddy_proof.py \
  scripts/test_caddy_proof.py
```

The CLI supports `render`, `digest`, `build-digest`, and `evidence`. The
evidence command has two bounded JSON workflows; neither workflow is a browser
execution attestation. JSON-only output is labeled
`historical_non_execution`/`not_proven`, and a caller-authored event map cannot
produce `browser_journey=passed`.

Retained evidence uses a descriptor-verified canonical path and identity: the
committed file and its fixed anchor are checked before any JSON field is
consumed. Copies, aliases, replacements, symlinks, and anchor mismatches fail
closed. This retained trust root is historical only. Direct library calls are
explicitly untrusted by default; selecting retained mode requires the private
canonical-loader token, so caller-supplied runtime inputs cannot appear as
anchored historical provenance.

For a new standalone observation, keep the browser map outside the static
output directory because the static digest covers every file in that tree:

```sh
python3 scripts/caddy_proof.py evidence \
  --static-build-root apps/web/build \
  --caddyfile-digest <rendered-caddyfile-sha256> \
  --browser-evidence /tmp/browser-evidence.json
```

`--static-build-root` must contain the reviewed `index.html`, `200.html`,
`manifest.webmanifest`, and `service-worker.js` entry points. The command
derives the checked-out Git `HEAD` and the digest of the actual static bytes;
optional `--build-sha` and `--build-digest` values are compatibility
assertions only and fail when they differ from those derived values.

Current product/static/Git provenance is a separate trust path from the
historical task-244 parity fixtures referenced by the retained manifest. Those
fixtures do not establish current product identity, and task-244 parity binding
remains a blocker until an independent check verifies it; this lane must not
silently claim parity. Static-tree and Git trust boundaries have explicit
resource and special-file limits: static provenance accepts only bounded
regular-file data, rejects symlinks and other special files, and applies one
monotonic deadline from root resolution through the final digest return. Git
provenance uses one total monotonic operation deadline beginning before
repository-root and metadata discovery; that same deadline covers link scans,
recursive snapshots, validation, Git spawn, output collection, and post-command
assertions. Output and diagnostics are bounded. Its local metadata scan rejects
nested symlink escapes, include/includeIf directives, and every promisor or
partial-clone selector, including key-only booleans and active
`config.worktree`; external Git configuration is disabled. The checkout root is pinned by descriptor identity and every Git command
fchdirs from that retained descriptor; no command uses pathname-based `git -C`
rediscovery. Both the metadata link scan and the bounded recursive
descriptor-relative snapshot use DFS frames that close exhausted subtrees,
keeping live directory descriptors O(depth), not O(directory count). The
snapshot covers `HEAD`, all nested refs including the loose
`refs/replace/<object-id>` namespace, loose objects, pack metadata, and nested
type/symlink topology. Each entry compares device, inode, type, size, and
bounded content, and retains explicit absence pins for missing metadata. One
aggregate metadata-content budget is reused across every pre/post root scan;
it is never reset for an individual root.
Every provenance command asserts the root
and complete metadata snapshot immediately before and after execution and
fails closed on any swap or same-inode byte rewrite. A closed stdout/stderr
pair that leaves Git running is normalized to the same bounded proof timeout;
a direct-child success with a live descendant group is rejected after bounded
TERM/KILL cleanup and reaping. Any limit, identity, malformed-output, or
command failure fails closed. Renderer path
inputs are literal absolute filesystem paths; Caddy placeholders are rejected
rather than retained as dynamic configuration.

The browser map must use the fixed
`hermternal.caddy-proof.browser-evidence.v1` schema and bind its status to the
verified build pair, Caddyfile digest, and runtime-input digest. Reads are
bounded to 4096 bytes, require UTF-8 JSON, reject duplicate object keys and
non-finite numbers at every nesting level, and fail closed on malformed Git
output or diagnostics. A complete `passed` map is rejected:
release proof requires a verifier-controlled browser harness or separately
trusted signed attestation, neither of which exists in this local lane. The
required `message.complete` observation remains unproven in this JSON-only
workflow.

For the reviewed historical fixture, use the retained workflow explicitly and
only with the canonical committed path:

```sh
REPO_ROOT="$(git rev-parse --show-toplevel)"
python3 "$REPO_ROOT/scripts/caddy_proof.py" evidence \
  --retained-input "$REPO_ROOT/tests/integration/hermes-caddy/caddy-proof-evidence.json"
```

`REPO_ROOT` expands to the checked-out absolute repository path. The retained
loader intentionally rejects a relative pathname, so this command is the
reproducible canonical invocation rather than a shorthand path example.

Retained mode verifies the exact canonical file bytes against the fixed
`caddy-proof-evidence-sha256.txt` anchor before consuming any fields, checks the
historical build pair against that anchored file, and uses its deterministic
runtime-input map. A copied or edited temporary manifest is rejected, and the
workflow does not require a local static-build directory. Standalone assertion
flags cannot be combined with retained input. The committed browser state is
`blocked_provider` with only the semantic marker `provider_unavailable`; it
contains no browser event payload, credential, cookie, ticket, ticket fragment,
provider payload, or transcript. A Caddy binary version or image digest is not
retained or validated by this local fixture. The local Caddy/mock-upstream suite
proves only synthetic edge/upstream behavior, not live Hermes or browser
execution.
