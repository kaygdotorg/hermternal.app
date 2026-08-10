---
name: deploy-hermes-agent
description: "Launch, inspect, and remove disposable official Hermes Agent instances for Hermternal browser tests. Use for Playwright lanes, browser-auth checks, REST or WebSocket compatibility probes, and any request to run Hermes correctly under rootless Podman."
---

# Deploy official Hermes Agent test instances

Use `scripts/hermes_agent.py`. Do not rediscover or redesign the container
boundary. The launcher uses the official immutable image, preserves its
entrypoint, runs `gateway run`, enables a synthetic Basic provider, and exposes
the Dashboard only on VM loopback.

## Execution boundary

Run on the dedicated authorized VM as the non-privileged account:

```text
hermternal-test@hermternal-dev
```

The launcher requires local rootless Podman. Docker is not a correctness
substitute. Do not point Podman at a remote engine.

Never:

- build Hermes from source;
- adapt a Dockerfile or create an adapter image;
- retag or relabel the upstream image;
- replace the image entrypoint;
- add capability, CPU, memory, PID, security, or log-policy flags;
- use host networking or publish Dashboard on a public address;
- publish port `8642` for this browser test lane;
- mount `~/.hermes`, a Podman socket, or a Docker socket;
- print, paste, log, or commit the generated password.

## Start one instance

From the repository root on the VM, provide the exact instance name, free
loopback port, and caller-selected marker under an existing private `0700` runs
directory. Do not copy a port or marker from an old proof:

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
# `endpoint` is the fail-closed selection gate immediately before credential
# handoff. It pins the immutable launcher container ID to running state and the
# sole explicit 127.0.0.1:<requested-port>:9119 mapping.
launcher_output="$(python3 scripts/hermes_agent.py endpoint --marker "$MARKER_PATH")"
# Command substitution strips all trailing LF bytes; append exactly one LF for canonical parsing.
endpoint="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
marker_path="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py marker-path)"
run_id="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py run-id)"
credential_file="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
credential_identity="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-identity)"
```

The launcher emits public metadata under `.result`. A successful `start` result
has `.result.status` `ready`, not a credential-handoff permit. Immediately
before handoff, `endpoint` re-inspects the stored immutable container ID and
requires the launcher-owned container to be `running` with exactly one
`127.0.0.1:<requested-port>:9119` mapping. It rejects stopped tombstones,
missing/stale IDs, replacements, ownership mismatches, rebound or extra ports,
and non-loopback mappings before any credential-file read.
`read_launcher_result.py` accepts only the closed successful `endpoint` result
with `status` `running`, its canonical launcher loopback endpoint, matching
marker and credential metadata. It never prints the password or infers a port.

Do not print the credential file or the `credential_identity` value. A local test
process may read the credential through the repository helper. The helper
requires the exact marker, run ID, credential path, and generation-bearing
identity before it reads the file. It removes only terminal CR/LF bytes, requires
exactly 48 lowercase hexadecimal characters, and replaces itself with the proof
command. The password is never printed or written by the helper; it is present
only in the child process environment:

```sh
HERMES_LIVE_TARGET="$endpoint" \
  python3 scripts/with_live_credential.py \
    --marker "$marker_path" \
    --run-id "$run_id" \
    --credential-file "$credential_file" \
    --credential-identity "$credential_identity" \
    -- \
    node /path/to/browser-smoke.mjs
```

Invalid, empty, overlong, uppercase, or whitespace-padded files fail locally
before the browser command starts. Do not put the password in a command argument,
repository file, fixture, report, terminal output, or retained log.

## Start N independent instances

Each instance gets a unique deterministic name, data directory, credential
file, loopback port, and caller-selected marker:

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

Before dispatching the first instance, `start-many` validates every marker's
private records, canonical absolute data-root path, readiness controls, and
new-run port. The batch holds one descriptor-bound parent lease while each
per-marker transaction repeats those checks; the preflight is advisory and the
batch remains non-atomic. If a marker parent or data path is replaced between
iterations, that marker fails closed before its next lifecycle boundary; the
earlier marker is not rediscovered, adopted, or rolled back by a broad batch
cleanup. A later per-marker failure reports only bounded exact `partial_results`
with the `batch_partial_results` secondary code. The failed marker retains its
own bounded `cleanup_failed` evidence when exact cleanup cannot finish; earlier
owned runs remain available under their caller-selected markers and must be
stopped or retried explicitly.

Data roots must use canonical absolute spellings with no `.` or `..` segments
and must not traverse symlink aliases. Darwin `/tmp` and `/var` aliases,
alternate `//` spellings, filesystem anchors, and broad roots such as
`/private/tmp`, `/private/var`, and `/usr/local` are rejected. Use a
sufficiently nested caller-specific descendant such as
`/private/tmp/<private-root>` or `/private/var/<private-root>`. Missing private
components are created and mode-checked through descriptor-relative
`openat`-style directory operations; pathname `mkdir` and `chmod` are never
used on the caller-supplied root. The instance child is created beneath a held
data-root descriptor with parent and child identity checks before and after the
boundary. Cleanup rechecks the child identity but preserves it when the only
available `os.rmdir(name, dir_fd=...)` call is not descriptor-atomic; it reports
bounded cleanup evidence instead of risking a same-name replacement. Podman
receives the canonical pathname rather than a held host fd. The launcher
revalidates the expected directory identity immediately before and after
relevant bind/start and mount-inspection boundaries. An inspect `Mounts[].Source`
string is consistency evidence, not inode proof. Persisted state stores only the
data directory's stable `device`/`inode`/`mode` identity; the marker retains an
independent matching witness. Records without that field are rejected as
invalid because this prototype has no approved migration or safe pathname
adoption path. A same-user replacement racing the final pathname syscall
remains outside this pathname-based adapter's proof boundary; an observed
replacement fails closed. Before a successful ready, endpoint, or status return,
the launcher performs a final all-record fence after the publication hook:
marker/state inode and generation, credential identity and generation, retained
parent, stable data identity, and the exact container/cidfile binding are checked
as applicable. A start-new or stopped recovery hook failure removes the exact
immutable container when its data proof remains valid, or retains bounded
`cleanup_failed` evidence when exact rollback is blocked. Stop keeps its final
hook inside evidence cleanup and proves marker, state, credential, and cidfile
absence before reporting removal. Launcher command vectors are validated before
engine dispatch; the executable and each argument must be a non-empty NUL-free
string. A new detached run selects its cidfile ID only after strict independent
proof from the same successful Podman invocation: stdout must be exactly one
canonical full lowercase ID line, and it must equal the cidfile ID before
inspection, publication, or cleanup. Missing, extra, malformed, or mismatched
stdout fails closed. Nonzero results preserve `container_start_failed` without
selecting a cidfile-only ID. Runner exceptions or invalid/untrusted results
never adopt or destructively remove a cidfile-only ID; they retain bounded
`cleanup_failed` evidence with `UNPROVEN_CONTAINER_ID` and leave the cidfile as
private evidence.

The `start-many` result contains bounded batch status and marker metadata, not
handoff endpoint or credential metadata. Only after the guarded mutation
succeeds, for each marker run the exact `endpoint --marker` operation, extract
all five fields with `read_launcher_result.py`, and use the four proof fields for
any credential handoff. Keep those per-marker results together; do not
reconstruct a port from a prefix, count, or remembered deployment.

## Inspect an instance

```sh
RUNS_DIR="${HERMES_RUNS_DIR:?set an existing private 0700 runs directory}"
MARKER_PATH="${HERMES_MARKER_PATH:?set the exact absolute marker path under that directory}"
# This freshly verifies the immutable container ID, running state, and loopback mapping.
launcher_output="$(python3 scripts/hermes_agent.py endpoint --marker "$MARKER_PATH")"
# Command substitution strips all trailing LF bytes; append exactly one LF for canonical parsing.
endpoint="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
marker_path="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py marker-path)"
run_id="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py run-id)"
credential_file="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
credential_identity="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-identity)"
```

A successful `start` result is `ready`, not a handoff permit. The `endpoint`
command freshly proves the retained immutable ID still belongs to a running,
launcher-owned container with its exact single loopback Dashboard mapping before
returning selection metadata. If a browser runs outside the VM, use the approved
tunnel with the endpoint selected from that verified output; do not replace it
with a sample port or an unrelated listener. Retained stop metadata is never a
live endpoint permit. The launcher performs a final data-directory identity
fence immediately before every successful start, running-reuse, stopped-recovery,
endpoint, and status return. Stop performs its final identity fence immediately
before deleting marker, state, and credential evidence. A created data child is
preserved when cleanup cannot prove descriptor-atomic removal; the bounded
cleanup failure remains observable instead of deleting a raced replacement.

## Stop and clean up

Stop only the exact marker-bound instance you own:

```sh
python3 scripts/hermes_agent.py stop \
  --marker "${HERMES_MARKER_PATH:?set the exact absolute marker path}"
```

The marker-bound stop removes only the exact container, credential, state, and
marker records. It retains the container data for diagnosis or retry; the strict
path does not support `--purge-data` or broad cleanup.

To stop more than one owned instance, run independent exact-marker commands in
sequence:

```sh
python3 scripts/hermes_agent.py stop \
  --marker "${HERMES_MARKER_1:?set marker 1}"
python3 scripts/hermes_agent.py stop \
  --marker "${HERMES_MARKER_2:?set marker 2}"
```

This sequence is intentionally not atomic: a failure may stop between commands,
so inspect and retry each remaining marker explicitly. Repeat individual stop
commands to verify idempotent cleanup. Never use broad Podman prune commands.

## Completion boundary

A successful launcher result means the official Dashboard answered bounded
`GET /api/auth/providers` discovery and exposed the expected synthetic Basic
provider. This is only deployment readiness.

Hermternal compatibility still requires the browser journey: provider
discovery, password login, protected cookie use, `/api/auth/me`, sessions,
WebSocket ticket acquisition, `/api/ws`, `gateway.ready`, chat operations, and
cleanup. Do not report app completion from container readiness alone.
