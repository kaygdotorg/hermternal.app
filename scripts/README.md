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

Run one instance from the repository root on the authorized VM. Provide the
exact instance name and the free loopback port owned by that instance; never
copy a port from an older proof:

```sh
INSTANCE="${HERMES_INSTANCE:?set the exact launcher instance name}"
PORT="${HERMES_PORT:?set a free loopback port for this instance}"
launcher_output="$(
  python3 scripts/hermes_agent.py start \
    --instance "$INSTANCE" \
    --port "$PORT"
)"
# The start result must report .result.status exactly "ready"; it is not the
# liveness probe. Separately, continue only when the status result is exactly
# "running".
python3 scripts/hermes_agent.py status --instance "$INSTANCE"
endpoint="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
credential_file="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
```

A successful `start` result has `.result.status` `ready`; the separate `status`
probe must report `running` immediately before the parsed endpoint and credential
file are used. A stopped, removed, or absent instance must abort the handoff;
retained endpoint metadata is not proof of a live listener. The status probe is
an operator check only, not liveness enforcement. Issue #345 remains open.

Run any requested count with unique names and consecutive loopback ports:

```sh
python3 scripts/hermes_agent.py start-many \
  --prefix "${HERMES_INSTANCE_PREFIX:?set the fleet prefix}" \
  --count "${HERMES_INSTANCE_COUNT:?set the fleet count}" \
  --base-port "${HERMES_BASE_PORT:?set the first free loopback port}"
```

Other operations are:

```sh
# Continue only when this separate status probe reports .result.status == "running".
python3 scripts/hermes_agent.py status --instance "$INSTANCE"
launcher_output="$(python3 scripts/hermes_agent.py endpoint --instance "$INSTANCE")"
endpoint="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
credential_file="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
python3 scripts/hermes_agent.py stop --instance "$INSTANCE"
python3 scripts/hermes_agent.py stop --instance "$INSTANCE" --purge-data
python3 scripts/hermes_agent.py stop-many \
  --prefix "${HERMES_INSTANCE_PREFIX:?set the fleet prefix}" \
  --count "${HERMES_INSTANCE_COUNT:?set the fleet count}" \
  --base-port "${HERMES_BASE_PORT:?set the first free loopback port}" \
  --purge-data
```

Every result is one JSON object. Public output may contain the instance,
container, loopback endpoint, immutable image, data path, and credential-file
path. It never contains the generated password. Credentials use mode `0600`
and live outside Git under `~/.config/hermternal-tests/hermes-agent/` by
default. Data defaults to `~/.local/share/hermternal-tests/hermes-agent/` and
non-secret launcher state defaults to
`~/.local/state/hermternal/hermes-agent/`. Tests may override all three roots.

The preceding `status` command must report `.result.status` as `running`
immediately before the endpoint and credential-file values are used. A successful
`start` result is `ready`, not `running`; the following `endpoint` command is the
source of truth for the selected instance only after the separate status probe.
`read_launcher_result.py` parses `.result.endpoint` and `.result.credential_file`;
it never infers a port or substitutes a remembered listener. Retained metadata
after a stop is not proof of a live listener. This status probe is an operator
check only, not liveness enforcement. Issue #345 remains open. Use the checked
values at the local live-proof handoff:

```sh
HERMES_LIVE_TARGET="$endpoint" \
  python3 scripts/with_live_credential.py "$credential_file" -- \
  bun run --cwd apps/web test:e2e:live
```

The helper reads the credential file as bytes, removes only trailing CR/LF, and
requires exactly 48 lowercase hexadecimal characters. It then replaces itself
with the child command and supplies `HERMES_TEST_PASSWORD` only in that child
process environment. It never prints or writes the password; invalid input
fails locally before the child starts. The launcher-generated `password\n` file
format is unchanged.

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
python3 -m py_compile scripts/with_live_credential.py scripts/test_with_live_credential.py
python3 -m py_compile scripts/read_launcher_result.py scripts/test_read_launcher_result.py
python3 scripts/test_hermes_agent.py
python3 scripts/test_with_live_credential.py
python3 scripts/test_read_launcher_result.py
python3 -O scripts/test_hermes_agent.py
python3 -m unittest scripts.test_hermes_agent scripts.test_with_live_credential scripts.test_read_launcher_result
python3 -O -m unittest scripts.test_hermes_agent scripts.test_with_live_credential scripts.test_read_launcher_result
```

The 29-test launcher suite uses a fake Podman boundary and local synthetic HTTP
server. The 6-test credential handoff and 6-test launcher-result suites use only
synthetic bytes and mocked local process boundaries. None of these suites starts
Hermes or reads a real credential. The launcher suite covers immutable image
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
provenance uses timed commands with bounded output and diagnostics. Its local metadata scan rejects
nested symlink escapes, include/includeIf directives, and every promisor or
partial-clone selector, including key-only booleans and active
`config.worktree`; external Git configuration is disabled. The checkout root is pinned by descriptor identity and every Git command
fchdirs from that retained descriptor; no command uses pathname-based `git -C`
rediscovery. A bounded recursive descriptor-relative snapshot covers `HEAD`,
all nested refs, loose objects, pack metadata, and their nested type/symlink
topology. Each entry compares device, inode, type, size, and bounded content;
the walker keeps only O(depth) directory descriptors open and retains explicit
absence pins for missing metadata. Every provenance command asserts the root
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
