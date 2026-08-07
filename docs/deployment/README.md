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
`0c2626619ecd065b6a7c532162cdc046ec7dafd7300b47ed1ff082a19429c91f`.
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
scenario selector accepts a query; bare query markers are denied. Static
assets, client routes, and REST routes reject query mutations. Chat uses one
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
contact the disposable VM during correction work.

The official launcher intentionally publishes Hermes only on VM loopback. The
retained browser state is `blocked_provider`: the launcher supplied no provider
credential, so this fixture does not claim `gateway.ready`, `session.resume`, or
`prompt.submit`, and it does not claim `message.delta` or `message.complete`.
No browser event artifact or provider payload is retained. No preview URL is
valid. This lane does not implement or attest Traefik.

The local Caddy/mock-upstream proof emits no `Set-Cookie`. Its renderer test
covers only the configured `Secure` rewrite; `HttpOnly`, `SameSite`, and `Path`
attributes remain unproven, so the retained evidence marks cookie proof as
`not_proven`. A Caddy binary version or image digest is also not retained or
validated by this local fixture and is not a deployment identity claim.

Before application or live integration, prove both proxy choices for HTTPS, HttpOnly cookies, WebSocket upgrades, private `:9119` reachability, firewall behavior, and the web-only `/api/pty` path. Also prove that missing or mismatched revision attestation and failed behavioral evidence block operation. Measure the performance baseline before setting optimization claims.

See the [security model](../security/README.md), [protocol plan](../protocol/README.md), and [architecture plan](../architecture/README.md).
