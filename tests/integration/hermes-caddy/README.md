# Disposable Caddy proof evidence

**Operation:** issue #156 Caddy deployment proof
**Status:** redacted edge/upstream evidence; browser journey blocked by provider
**Proxy:** Caddy only; Traefik is not implemented by this lane

This directory retains the bounded, redacted observations from the authorized
disposable Caddy lane. The official Hermes launcher remained the only Hermes
boundary and published its Dashboard on VM loopback. No production deployment,
preview, provider credential, or live user data is represented here.

## Immutable bindings

The evidence is bound to:

- PR #291 build commit `521ede32b904a42e22eebb279fd7d404074cd318`;
- static build digest `77f6d0e8bb4977c16eb1f1eaec32000f84f346ddec9f474ebd873d7b9a833d21`;
- runtime Caddyfile SHA-256 `342952687f19e425bd47126a47b5d17767c27aed99942252d6a6711b2b94f15c`;
- deterministic runtime-input digest `94a1c14439486a8e9302ad32400a8ec56ab0ef7f8b019dd8470f5f79c50a91c4`;
- shared static-route grammar digest `f0542d97b363b8e2a921e93001d72dd0f56d5f30001f15e95bbca5b2f4165165`;
- deep-link fixture digest `91fad69ec110ea8042678b963076056b4474072d24f9698067ed8bfc10c03d96`;
- Hermes source SHA `f5be9236e00ddf2f2a412697f267078fc4ee068e`.

The retained fixture does not claim a Caddy binary version or official image
identity. Those values are external deployment metadata until a bounded,
reproducible collection step validates them; a VM-reported value is not a local
trust root.

The evidence file records only status codes, responding layers, upstream-request
booleans, fixed policy outcomes, and redaction markers. It has no passwords,
cookies, ticket values or fragments, Authorization values, provider payloads,
prompt text, transcripts, or live request URLs.

## Observed boundary

The exact Caddy renderer serves the PR #291 static client at `/`, maps the
reviewed Dashboard routes under one `/hermes` prefix, and rejects unknown
methods and paths at the edge. Canonical session and message links matching
`/v1/c/<opaque-id>` and `/v1/c/<opaque-id>/m/<opaque-id>` rewrite to
`/200.html`; reserved prefixes never use that fallback. Only the reviewed root
`scenario=success|empty|failure` selector and exact OAuth callback forms may
carry a query: either non-empty safe ASCII `code` and `state` values, or literal
`error=access_denied` with non-empty safe ASCII `error_description` and `state`;
each value is bounded to 512 characters and key order is independent. A bare
query marker is denied. Static assets, client routes, and other REST routes reject
query mutations. Chat upgrades accept one non-empty safe opaque ticket bounded to 512
characters. The current browser PTY client sends only ticket plus resume and an
optional non-empty attach value in any key order, with bounded safe opaque
values; duplicate, extra, empty, and `fresh` parameters are edge-denied.

Caddy removes inbound `Forwarded`, every `X-Forwarded-*` field, and `X-Real-IP`
before rebuilding trusted public forwarding metadata. Traversal, encoded
separators, duplicate prefixes, malformed upgrades, and missing tickets are
edge-denied without an upstream request. Invalid, expired, and reused tickets
remain Hermes-layer results. Direct access to the private Hermes port from the
untrusted path is connection-denied.

The local black-box test starts Caddy beside a recording mock upstream. It
checks actual response status, exact upstream path and body, one `/hermes`
prefix, rebuilt forwarding headers, canonical deep-link vectors, and separate
chat/PTY query grammars. The proof binds those parity vectors to the committed
static-route grammar and deep-link fixture digests above; it does not contact
Hermes or the VM during correction runs. The black-box check requires an
available `caddy` tool and `openssl`; missing tools are a hard failure, not a
skip, and a skipped check is not evidence.

Browser JSON has two bounded input workflows, but neither is an execution
attestation. For a standalone run, pass a temporary browser map and the
static-build output directory to the renderer; keep the map outside the static
directory because the verifier hashes every file in that tree. The static
output must contain `index.html`, `200.html`, `manifest.webmanifest`, and
`service-worker.js`. Git `HEAD` and the static-tree digest are derived locally
before the map is accepted. Optional CLI build SHA and digest flags are checked
assertions only; fabricated values, including all-zero or all-one values, are
rejected. A caller-authored complete event map is never enough to produce
`browser_journey=passed`.

Current product/static/Git provenance is separate from the historical task-244
parity fixtures referenced by the retained manifest. Those fixtures are not a
current product identity, and task-244 parity binding remains a blocker until
an independent check verifies it; retaining their digests must not silently
claim parity. Static-tree and Git trust boundaries have explicit resource and
special-file limits: static provenance is bounded to regular-file data and
rejects symlinks and other special files, while Git provenance uses timed
commands with bounded output and diagnostics. Any limit, identity,
malformed-output, or command failure fails closed.

For the historical proof retained here, pass only the complete evidence file at
the canonical committed path with `--retained-input`. Retained evidence uses a
descriptor-verified canonical path and identity: the committed file is checked
against `caddy-proof-evidence-sha256.txt` before parsing any field. Copies,
aliases, replacements, symlinks, and anchor mismatches fail closed. Retained
mode then checks the anchored historical build pair and uses deterministic
runtime-input placeholders, so it remains usable without a local copy of the
old static build. A copied or edited temporary manifest is rejected before any
browser fields are consumed. Do not combine retained input with standalone
assertion flags. Both workflows use the fixed
`hermternal.caddy-proof.browser-evidence.v1` schema, bind status to the exact
build, static manifest, rendered Caddyfile, and runtime-input digests, cap
browser JSON at 4096 bytes, and reject invalid UTF-8, duplicate object keys, and
non-finite numbers at any nesting level. Git nonzero exits, timeouts, malformed
output, and diagnostics also fail closed. JSON-only output is labeled
`historical_non_execution` and `not_proven`.

The retained status is `blocked_provider` with only the semantic blocker
`provider_unavailable`. No browser event payload is retained or claimed; no
gateway, session, or prompt event artifact is retained or claimed:
`gateway.ready`, `session.resume`, `prompt.submit`, `message.delta`, and
`message.complete` are all unproven. A `passed` release claim requires a
verifier-controlled browser harness or a separately trusted signed attestation;
neither is present in this no-live-VM/Hermes lane. `blocked_empty_session` and
`failed` require their matching fixed blocker or failure marker. Missing, stale,
mismatched, malformed, oversized, or extra-key maps fail closed. The official
launcher did not provide an inference credential. The browser journey therefore
remains an incomplete provider/API-key proof before `message.delta` or
`message.complete`; this is not a successful real-product journey and no
preview URL may be published.

The local mock emitted no `Set-Cookie`. The renderer test proves only that the
Caddyfile contains its current `Secure` rewrite; `HttpOnly`, `SameSite`, and
`Path` attributes are not proven by this fixture. The evidence records that
cookie proof as `not_proven` rather than claiming attributes.

The evidence SHA-256 is stored in `caddy-proof-evidence-sha256.txt`.
