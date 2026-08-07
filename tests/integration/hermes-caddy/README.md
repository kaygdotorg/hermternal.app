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
- runtime Caddyfile SHA-256 `b3585c4b91d7656d5bcb6adedda29af63d60ca488ec99ef162ec4f74e2611e82`;
- Hermes source SHA `f5be9236e00ddf2f2a412697f267078fc4ee068e`; and
- official Hermes image digest
  `sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e`.

The evidence file records only status codes, responding layers, upstream-request
booleans, fixed policy outcomes, and redaction markers. It has no passwords,
cookies, ticket values or fragments, Authorization values, provider payloads,
prompt text, transcripts, or live request URLs.

## Observed boundary

The exact Caddy renderer serves the PR #291 static client at `/`, maps the
reviewed Dashboard routes under one `/hermes` prefix, rejects unknown methods
and paths at the edge, rejects wrong Host with `421`, rejects wrong WebSocket
Origin with `403`, and requires a single ticket query for upgrades. Traversal,
encoded separators, duplicate prefixes, malformed upgrades, and missing tickets
were edge-denied without an upstream request. Invalid, expired, and reused
tickets remained Hermes-layer results. Direct access to the private Hermes port
from the untrusted path was connection-denied.

Authentication, cookie attributes, ticket acquisition, one WebSocket upgrade,
`gateway.ready`, `session.resume`, and `prompt.submit` were observed. The
official launcher did not provide an inference credential, so the browser
journey stopped in the provider/API-key class before `message.delta` or
`message.complete`. The retained browser state is `blocked_provider`; this is
not a successful real-product journey and no preview URL may be published.

The evidence SHA-256 is stored in `caddy-proof-evidence-sha256.txt`.
