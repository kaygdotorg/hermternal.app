# Disposable Traefik proof evidence

**Operation:** issue #92 / DEP-05 Traefik HTTPS and prefix-routing proof
**Status:** redacted edge/upstream policy evidence; browser journey blocked by provider
**Proxy:** Traefik only; this lane does not compare or replace the Caddy proof

This directory retains the bounded, synthetic observations for the first
Traefik proof unit. The renderer is a proof fixture, not a production
configuration. It does not contact Hermes, a provider, a VM, a firewall, or a
public address, and it does not retain credentials, cookies, tickets, ticket
fragments, Authorization values, provider payloads, prompts, transcripts, or
live request URLs.

## Scope and boundary

The renderer produces deterministic Traefik static and dynamic JSON. The
entry point binds to `127.0.0.1` and the upstreams are synthetic local services.
That loopback-only listener is the disposable issue #92 proof exception. The
normal deployment topology remains a fixed private non-loopback Hermes bind on
TCP `9119`, with a default-deny firewall that allows only the selected Caddy or
Traefik proxy identity. This artifact is not a public deployment approval.

Traefik's native `Query` and `QueryRegexp` matchers can require known query
keys but cannot reject every unknown key in a raw query. The dynamic config
therefore places a local `forwardAuth` policy gate before every service. The
policy gate applies the closed query grammar in `scripts/traefik_proof.py` and
returns the edge result before Hermes or the static server is contacted. It is
part of this disposable proof harness, not a production authentication
service. The retained evidence names this dependency instead of implying that
Traefik's native matchers alone prove exact query denial.

## Reviewed routing cases

The policy model and renderer cover:

- HTTPS on the synthetic `traefik-92.test` authority;
- the root static surface and the reviewed `scenario=success|empty|failure`
  selector only;
- canonical session and message deep links, without path normalization or a
  shell fallback for reserved prefixes;
- the exact REST method/path list at the root and under one `/hermes` prefix;
- OAuth callback code/state and provider-error query permutations only;
- chat upgrades with one non-empty bounded `ticket` query;
- PTY upgrades with `ticket` plus `resume` and optional `attach`, in any key
  order, with duplicate, extra, empty, and `fresh` values denied;
- wrong Host (`421`), wrong WebSocket Origin (`403`), unknown paths or methods
  (`404`), traversal, encoded separators or dots, duplicate prefixes, malformed
  upgrades, and query mutations before upstream access; and
- invalid, expired, or reused ticket outcomes remaining Hermes-layer results
  after the edge accepted the request.

Inbound forwarding fields are not trusted. The static entry point disables
insecure forwarded-header trust, the policy receives the original request
metadata, and the Hermes middleware overrides the retained forwarding fields
with the synthetic public authority, HTTPS scheme, one optional `/hermes`
prefix, and the private Hermes service authority. The proof does not claim
that a cookie has `Secure`, `HttpOnly`, `SameSite`, or `Path`: no real
`Set-Cookie` response is captured, so `cookie_proof.status` remains
`not_proven`.

## Evidence bindings

`traefik-proof-evidence.json` is bound to:

- the reviewed Hermes source SHA;
- the same static build and shared route/deep-link fixture identities used by
  the disposable Caddy proof;
- the deterministic Traefik static/dynamic configuration digest; and
- the deterministic runtime-input digest.

The browser state is `blocked_provider` with only the fixed
`provider_unavailable` blocker. No `gateway.ready`, `session.resume`,
`prompt.submit`, `message.delta`, or `message.complete` event is retained or
claimed. A successful browser completion must be collected separately with
complete provenance before the status can change.

The evidence digest is stored in
`traefik-proof-evidence-sha256.txt`. The aggregate fixture registry is not
modified by this unit; registering a new fixture root is deferred until the
shared registry ownership and DEP-03 blocker are resolved.

## Verification

The focused checks are:

```text
python3 scripts/test_traefik_proof.py
python3 -O scripts/test_traefik_proof.py
python3 -m unittest discover -s scripts -p 'test_traefik_proof.py'
python3 -O -m unittest discover -s scripts -p 'test_traefik_proof.py'
python3 -m py_compile scripts/traefik_proof.py scripts/test_traefik_proof.py
```

These checks are offline and use only standard-library policy and renderer
models. They do not claim a live Traefik binary, a Hermes process, provider
availability, cookie attributes, firewall behavior, or issue #90 completion.
