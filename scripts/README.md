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

Run one instance from the repository root on the authorized VM:

```sh
python3 scripts/hermes_agent.py start \
  --instance playwright-auth \
  --port 19119
```

Run any requested count with unique names and consecutive loopback ports:

```sh
python3 scripts/hermes_agent.py start-many \
  --prefix playwright \
  --count 4 \
  --base-port 19120
```

Other operations are:

```sh
python3 scripts/hermes_agent.py status --instance playwright-auth
python3 scripts/hermes_agent.py endpoint --instance playwright-auth
python3 scripts/hermes_agent.py credential-file --instance playwright-auth
python3 scripts/hermes_agent.py stop --instance playwright-auth
python3 scripts/hermes_agent.py stop --instance playwright-auth --purge-data
python3 scripts/hermes_agent.py stop-many \
  --prefix playwright --count 4 --base-port 19120 --purge-data
```

Every result is one JSON object. Public output may contain the instance,
container, loopback endpoint, immutable image, data path, and credential-file
path. It never contains the generated password. Credentials use mode `0600`
and live outside Git under `~/.config/hermternal-tests/hermes-agent/` by
default. Data defaults to `~/.local/share/hermternal-tests/hermes-agent/` and
non-secret launcher state defaults to
`~/.local/state/hermternal/hermes-agent/`. Tests may override all three roots.

`start` first requires local rootless Podman and verifies the requested official
repository digest. It then polls bounded `GET /api/auth/providers` responses.
Readiness requires HTTP 200 and a `basic` provider with
`supports_password: true`. A failed start removes only the container created by
that invocation. Data and credentials remain for diagnosis or retry until an
explicit `--purge-data` stop. Active rebind of an already-running container is
intentionally unsupported; ordinary running-container reuse is non-destructive.
If the official entrypoint created mapped container-owned files, purge uses
exact-path rootless `podman unshare rm` for
that one validated instance directory; it never runs a broad prune.

An existing container is reused only after its launcher labels prove the exact
instance, loopback port, and immutable image identity. A stopped owned
container is started only after the requested port is available, then readiness
is checked. Lifecycle actions use the freshly inspected immutable container ID,
not the mutable container name, and rollback re-inspects that same ID before
stopping it. If start, readiness, or state persistence fails, the recovery
transaction attempts one bounded exact-container stop, so an initially stopped
container is not left running. An initially running container is never stopped
by the ordinary reuse path. Foreign or mismatched containers fail closed before
any lifecycle mutation. This is disposable proof tooling for the authorized
Hermes test lane, not production infrastructure; it never prunes unrelated
containers, binds, sockets, listeners, or provider configuration.

Launcher readiness proves only that the configured Dashboard boundary is
available. It does not prove Hermternal chat behavior. Run the separate
Playwright browser-to-Hermes journey before reporting app compatibility.

Offline verification:

```sh
python3 -m py_compile scripts/hermes_agent.py scripts/test_hermes_agent.py
python3 scripts/test_hermes_agent.py
python3 -O scripts/test_hermes_agent.py
python3 -m unittest scripts.test_hermes_agent
python3 -O -m unittest scripts.test_hermes_agent
```

The 28-test suite uses a fake Podman boundary and local synthetic HTTP server.
It never starts Hermes or reads a real credential. It covers immutable image
binding, rootless checks, environment cleanup, deterministic scaling, upstream
command preservation, absence of custom policy flags, credential redaction,
provider readiness, existing stopped-container recovery and exact-once rollback,
partial failure rollback, and exact idempotent teardown. This command-line
artifact has no UI, focus, screen-reader, browser-zoom, contrast, motion, or
touch-target surface; accessibility checks are N/A.

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
no `Set-Cookie`, so `HttpOnly`, `SameSite`, and `Path` attributes are not proven
by this fixture. Caddy's canonical formatter uses tabs, so the renderer emits
that form directly; the runtime digest therefore covers the exact file that
was validated.

The evidence also records a deterministic runtime-input manifest and the
SHA-256 identities of the shared static-route grammar and deep-link fixture.
The black-box test starts local Caddy beside a recording mock upstream and
checks actual paths, bodies, prefixes, headers, deep links, query denials, and
upgrade results. It does not contact Hermes or the disposable VM during this
correction lane.

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

The CLI supports `render`, `digest`, `build-digest`, and `evidence`. The checked-
in redacted evidence is
`tests/integration/hermes-caddy/caddy-proof-evidence.json`. It binds
build commit `521ede32b904a42e22eebb279fd7d404074cd318`, static build digest
`77f6d0e8bb4977c16eb1f1eaec32000f84f346ddec9f474ebd873d7b9a833d21`, and
runtime Caddyfile digest
`342952687f19e425bd47126a47b5d17767c27aed99942252d6a6711b2b94f15c`.
The runtime input manifest digest is
`94a1c14439486a8e9302ad32400a8ec56ab0ef7f8b019dd8470f5f79c50a91c4`; its
paths are deterministic proof placeholders, not retained user or VM paths.
The retained browser state is `blocked_provider`: no browser event artifact is
retained, so the fixture does not claim `gateway.ready`, `session.resume`, or
`prompt.submit`; it also does not claim `message.delta` or `message.complete`.
It contains no credential, cookie, ticket, ticket fragment, provider payload,
or transcript. A Caddy binary version or image digest is not retained or
validated by this local fixture.
