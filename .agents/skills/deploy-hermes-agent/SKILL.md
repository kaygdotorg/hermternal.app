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

From the repository root on the VM:

```sh
python3 scripts/hermes_agent.py start \
  --instance playwright-auth \
  --port 19119
```

The command prints one JSON object. Keep these fields:

- `endpoint` — the private loopback Dashboard URL;
- `credential_file` — the local password-file path;
- `container` — the exact launcher-owned container;
- `image` — the immutable official image reference.

Do not print the credential file. A local test process may read it through the
repository helper. `with_live_credential.py` removes only terminal CR/LF bytes,
requires exactly 48 lowercase hexadecimal characters, and replaces itself with
the proof command. The password is never printed or written by the helper; it is
present only in the child process environment:

```sh
python3 scripts/with_live_credential.py /path/from/credential_file -- \
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
  --prefix playwright \
  --count 4 \
  --base-port 19120
```

This creates `playwright-1` through `playwright-4` on ports `19120` through
`19123`. The launcher has no custom fleet resource budget. The VM may use its
available resources. Separate agents may run `start` in parallel when each agent
owns a distinct instance name and port.

## Inspect an instance

```sh
python3 scripts/hermes_agent.py endpoint --instance playwright-auth
python3 scripts/hermes_agent.py credential-file --instance playwright-auth
python3 scripts/hermes_agent.py status --instance playwright-auth
```

If a browser runs outside the VM, use an SSH tunnel to the reported loopback
port. Do not change the container publication address:

```sh
ssh -N -L 19119:127.0.0.1:19119 hermternal-test@hermternal-dev
```

## Stop and clean up

Stop only the exact instance you own:

```sh
python3 scripts/hermes_agent.py stop --instance playwright-auth
```

Keep data and the synthetic credential when a retry needs the same instance.
Remove both only when the disposable lane is finished:

```sh
python3 scripts/hermes_agent.py stop \
  --instance playwright-auth \
  --purge-data
```

Stop an exact batch:

```sh
python3 scripts/hermes_agent.py stop-many \
  --prefix playwright \
  --count 4 \
  --base-port 19120 \
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
