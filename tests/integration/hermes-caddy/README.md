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
- runtime Caddyfile SHA-256 `0c2626619ecd065b6a7c532162cdc046ec7dafd7300b47ed1ff082a19429c91f`;
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
`scenario=success|empty|failure` selector may carry a query; a bare query marker
is denied. Static assets, client routes, and REST routes reject every query
mutation. Chat upgrades accept one non-empty safe opaque ticket bounded to 512
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
Hermes or the VM during correction runs.

The retained browser state is `blocked_provider`. No gateway, session, or
prompt event artifact is retained or claimed, and the official launcher did not
provide an inference credential. The browser journey therefore remains an
incomplete provider/API-key proof before `message.delta` or `message.complete`;
this is not a successful real-product journey and no preview URL may be
published.

The local mock emitted no `Set-Cookie`. The renderer test proves only that the
Caddyfile contains its current `Secure` rewrite; `HttpOnly`, `SameSite`, and
`Path` attributes are not proven by this fixture. The evidence records that
cookie proof as `not_proven` rather than claiming attributes.

The evidence SHA-256 is stored in `caddy-proof-evidence-sha256.txt`.
