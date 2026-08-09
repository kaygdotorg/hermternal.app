# Deployment topology

## Status

This directory contains deployment planning and proof requirements only. It has no deployable proxy, certificate, hostname, secret, or production configuration.

## Target topology

The supported self-hosted layout uses one HTTPS origin:

- `/` serves the static Hermternal web client;
- the Dashboard routes serve chat, auth, and WebSocket traffic; and
- the web-only full `/api/pty` Terminal is routed through the same protected deployment boundary.

Caddy and Traefik are equal supported proxy choices. Either must terminate HTTPS, serve the static client, preserve WebSocket upgrades, and forward the required host, scheme, and prefix information.

Hermes uses a fixed private, non-loopback bind on `:9119`. A firewall must restrict access to the approved private path. The bind must not be public and must not move between proof runs.

## Auth and compatibility

Browser sessions use protected server-issued HttpOnly cookies. Native clients may use the discovered username/password provider with an isolated `URLSession` cookie store and WebSocket tickets; they do not reuse browser cookies. Native OAuth/OIDC is allowed only when the callback transport is accepted by the pinned Hermes native route and target-platform proof passes. It is blocked when either condition is absent or fails. No upstream change is approved.

The supported Hermes revision is `f5be9236e00ddf2f2a412697f267078fc4ee068e`. Missing or mismatched deployment attestation, or a failed behavioral probe, blocks live operation. Private deep links use `/v1/c/...`; sharing is deferred to `v0.0.2`.

## Issue #156 Caddy proof lane

The disposable Caddy proof is recorded in
[`tests/integration/hermes-caddy/caddy-proof-evidence.json`](../../tests/integration/hermes-caddy/caddy-proof-evidence.json).
It binds the observed edge and upstream results to the exact PR #291 build
commit `521ede32b904a42e22eebb279fd7d404074cd318`, static build digest
`77f6d0e8bb4977c16eb1f1eaec32000f84f346ddec9f474ebd873d7b9a833d21`, and
runtime Caddyfile digest
`342952687f19e425bd47126a47b5d17767c27aed99942252d6a6711b2b94f15c`.
The committed runtime input manifest has digest
`94a1c14439486a8e9302ad32400a8ec56ab0ef7f8b019dd8470f5f79c50a91c4`, so the
runtime file can be reconstructed without retaining VM or user paths. The
static-route grammar and deep-link fixture identities are also recorded in the
evidence.

The renderer and offline regression tests are in
[`scripts/caddy_proof.py`](../../scripts/caddy_proof.py) and
[`scripts/test_caddy_proof.py`](../../scripts/test_caddy_proof.py). The proof
uses exact method/path matchers at `/` and under one `/hermes` prefix. Canonical
session and message deep links fall back to `200.html`; only the reviewed root
scenario selector and the exact OAuth callback forms accept a query: either
non-empty safe ASCII `code` and `state` values, or literal `error=access_denied`
with non-empty safe ASCII `error_description` and `state`; each value is bounded
to 512 characters and key order is independent. Bare query markers are denied.
Static assets, client routes, and other REST routes reject query mutations. Chat uses one
non-empty safe opaque ticket bounded to 512 characters. The current browser PTY
client sends only `ticket` plus `resume` and an optional non-empty `attach`, in
any key order; duplicates, extras, empty values, and the unsupported `fresh`
parameter are denied. Unknown
methods and paths, duplicate prefixes, traversal, encoded separators, and
malformed upgrades are edge-denied without an upstream request. Wrong Host is
`421`; wrong WebSocket Origin is `403`; missing tickets are edge `404`; and
invalid, expired, or reused tickets remain Hermes-layer results.

The proxy strips all inbound `Forwarded`, `X-Forwarded-*`, and `X-Real-IP`
headers before rebuilding trusted public metadata. The black-box test runs only
locally with Caddy and a recording mock upstream, and asserts the actual
upstream path, body, prefix, query policy, and rebuilt headers. It does not
contact the disposable VM during correction work. Local Caddy plus the recording
mock proves the edge/upstream boundary only; it does not prove live Hermes or
browser execution. The black-box check requires an available `caddy` tool and
`openssl`; missing tools are a hard failure, not a skip, and a skipped check is
not evidence.

The official launcher intentionally publishes Hermes only on VM loopback. The
browser proof has two explicit input workflows. A standalone browser map is a
temporary input and must be supplied with a static-build root; the verifier
derives the checked-out Git `HEAD` and the digest of the actual static bytes
before it accepts browser provenance. The optional CLI build SHA and digest
flags are assertions against those derived values, not trust roots. The static
root must contain `index.html`, `200.html`, `manifest.webmanifest`, and
`service-worker.js`, and the temporary browser map must remain outside that
root so it cannot alter the bytes being hashed.

Current product/static/Git provenance is separate from the historical task-244
parity fixtures referenced by the retained manifest. Those fixtures are not a
current product identity, and task-244 parity binding remains a blocker until
an independent check verifies it; retaining their digests must not silently
claim parity. Static-tree and Git trust boundaries have explicit resource and
special-file limits: static provenance is bounded to regular-file data and
rejects symlinks and other special files, with one monotonic deadline covering
root resolution through the final digest return. Git provenance uses timed
commands with bounded output and diagnostics. Its bounded local metadata scan
rejects nested symlink escapes, include/includeIf directives, and every
promisor or partial-clone selector, including key-only booleans and active
`config.worktree`; external Git configuration is disabled. If both Git pipes
close while the process continues, the path still returns the bounded proof
timeout after terminating and reaping the process group. Renderer path inputs
are literal absolute filesystem paths; Caddy placeholders are rejected. Any
limit, identity, malformed-output, or command failure fails closed.

The retained workflow must use the complete evidence file at the canonical
committed path `tests/integration/hermes-caddy/caddy-proof-evidence.json`.
Retained evidence uses a descriptor-verified canonical path and identity: it
checks the exact committed bytes against
`tests/integration/hermes-caddy/caddy-proof-evidence-sha256.txt` before parsing
any field. Copies, aliases, replacements, symlinks, and anchor mismatches fail
closed. It then checks the historical build pair and reconstructs the
deterministic runtime inputs; it
does not require the historical static build to exist locally. The fixed browser
schema binds either workflow's declared status to the verified build, static
manifest, rendered Caddyfile, and runtime-input digests. Browser JSON is
bounded to 4096 bytes, requires UTF-8, rejects duplicate object keys and
non-finite numbers at every nesting level, and fails closed on malformed Git
output. These caller-authored standalone and retained JSON maps are labeled
`historical_non_execution`/`not_proven`; they are historical non-execution
observations, not browser execution attestations, and cannot satisfy
`browser_journey=passed`. Passed release proof requires a
verifier-controlled browser harness or a separately trusted signed attestation;
neither is present in this no-live-VM/Hermes lane. The current retained map is
`blocked_provider` with only `provider_unavailable`; no browser event payload or
provider payload is retained. `blocked_empty_session` and `failed` statuses
require their matching validated evidence; a passed release claim is unavailable
without the trusted execution path described above. Missing, stale, mismatched,
malformed, oversized, or extra-key maps fail closed. No preview URL is valid.
This lane does not implement or attest Traefik.

The local Caddy/mock-upstream proof emits no `Set-Cookie`. Its renderer test
covers only the configured `Secure` rewrite; `HttpOnly`, `SameSite`, and `Path`
attributes remain unproven, so the retained evidence marks cookie proof as
`not_proven`. A Caddy binary version or image digest is also not retained or
validated by this local fixture and is not a deployment identity claim.

Before application or live integration, prove both proxy choices for HTTPS, HttpOnly cookies, WebSocket upgrades, private `:9119` reachability, firewall behavior, and the web-only `/api/pty` path. Also prove that missing or mismatched revision attestation and failed behavioral evidence block operation. Measure the performance baseline before setting optimization claims.

See the [security model](../security/README.md), [protocol plan](../protocol/README.md), and [architecture plan](../architecture/README.md).
