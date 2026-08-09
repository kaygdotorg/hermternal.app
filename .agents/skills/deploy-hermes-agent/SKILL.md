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

From the repository root on the VM, provide the exact instance name and the
free loopback port owned by that instance. Do not copy a port from an old proof:

```sh
INSTANCE="${HERMES_INSTANCE:?set the exact launcher instance name}"
PORT="${HERMES_PORT:?set a free loopback port for this instance}"
launcher_output="$(
  python3 scripts/hermes_agent.py start \
    --instance "$INSTANCE" \
    --port "$PORT"
)"
# `endpoint` is the fail-closed selection gate immediately before credential
# handoff. It pins the immutable launcher container ID to running state and the
# sole explicit 127.0.0.1:<requested-port>:9119 mapping.
launcher_output="$(python3 scripts/hermes_agent.py endpoint --instance "$INSTANCE")"
endpoint="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
credential_file="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
```

The launcher emits public metadata under `.result`. A successful `start` result
has `.result.status` `ready`, not a credential-handoff permit. Immediately
before handoff, `endpoint` re-inspects the stored immutable container ID and
requires the launcher-owned container to be `running` with exactly one
`127.0.0.1:<requested-port>:9119` mapping. It rejects stopped tombstones,
missing/stale IDs, replacements, ownership mismatches, rebound or extra ports,
and non-loopback mappings before any credential-file read.
`read_launcher_result.py` accepts only the canonical launcher loopback endpoint
and matching credential-file metadata; it never prints the password or infers a
port.

Do not print the credential file. A local test process may read it through the
repository helper. `with_live_credential.py` removes only terminal CR/LF bytes,
requires exactly 48 lowercase hexadecimal characters, and replaces itself with
the proof command. The password is never printed or written by the helper; it is
present only in the child process environment:

```sh
HERMES_LIVE_TARGET="$endpoint" \
  python3 scripts/with_live_credential.py "$credential_file" -- \
  node /path/to/browser-smoke.mjs
```

Invalid, empty, overlong, uppercase, or whitespace-padded files fail locally
before the browser command starts. Do not put the password in a command argument,
repository file, fixture, report, terminal output, or retained log.

## Start N independent instances

Each instance gets a unique deterministic name, data directory, credential
file, and loopback port:

```sh
python3 scripts/hermes_agent.py start-many \
  --prefix "${HERMES_INSTANCE_PREFIX:?set the fleet prefix}" \
  --count "${HERMES_INSTANCE_COUNT:?set the fleet count}" \
  --base-port "${HERMES_BASE_PORT:?set the first free loopback port}"
```

The launcher reports each instance's endpoint and credential-file path in its
JSON results. Keep those results together; do not reconstruct a port from a
prefix, count, or remembered deployment.

## Inspect an instance

```sh
INSTANCE="${HERMES_INSTANCE:?set the exact launcher instance name}"
# This freshly verifies the immutable container ID, running state, and loopback mapping.
launcher_output="$(python3 scripts/hermes_agent.py endpoint --instance "$INSTANCE")"
endpoint="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
credential_file="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
```

A successful `start` result is `ready`, not a handoff permit. The `endpoint`
command freshly proves the retained immutable ID still belongs to a running,
launcher-owned container with its exact single loopback Dashboard mapping before
returning selection metadata. If a browser runs outside the VM, use the approved
tunnel with the endpoint selected from that verified output; do not replace it
with a sample port or an unrelated listener. Retained stop metadata is never a
live endpoint permit.

## Stop and clean up

Stop only the exact instance you own:

```sh
python3 scripts/hermes_agent.py stop \
  --instance "${HERMES_INSTANCE:?set the exact launcher instance name}"
```

Keep data and the synthetic credential when a retry needs the same instance.
Remove both only when the disposable lane is finished:

```sh
python3 scripts/hermes_agent.py stop \
  --instance "${HERMES_INSTANCE:?set the exact launcher instance name}" \
  --purge-data
```

Stop an exact batch:

```sh
python3 scripts/hermes_agent.py stop-many \
  --prefix "${HERMES_INSTANCE_PREFIX:?set the fleet prefix}" \
  --count "${HERMES_INSTANCE_COUNT:?set the fleet count}" \
  --base-port "${HERMES_BASE_PORT:?set the first free loopback port}" \
  --purge-data
```

Repeat stop commands to verify idempotent cleanup. Never use broad Podman prune
commands.

## Completion boundary

A successful launcher result means the official Dashboard answered bounded
`GET /api/auth/providers` discovery and exposed the expected synthetic Basic
provider. This is only deployment readiness.

Hermternal compatibility still requires the browser journey: provider
discovery, password login, protected cookie use, `/api/auth/me`, sessions,
WebSocket ticket acquisition, `/api/ws`, `gateway.ready`, chat operations, and
cleanup. Do not report app completion from container readiness alone.
