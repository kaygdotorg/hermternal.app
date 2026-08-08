# Disposable Traefik proof evidence

**Operation:** issue #92 / DEP-05 Traefik HTTPS and prefix-routing proof
**Status:** synthetic-local edge/upstream policy evidence only; browser journey blocked by provider; live deployment not proven
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

The retained `proof_run` is deliberately `synthetic_observed` with
`scope=synthetic_local`, `live_run=false`, and `compatible=false`. Positive
route cases therefore describe only local renderer and mock-upstream behavior;
they do not complete the deployment proof. The completion gate is an exact
reviewed and merged build commit exercised against authorized real Hermes in
that private non-loopback/default-deny topology. A separate live run must
supply that evidence before any deployment-complete or compatibility claim.

Traefik's native `Query` and `QueryRegexp` matchers can require known query
keys but cannot reject every unknown key in a raw query. The dynamic config
therefore places a local `forwardAuth` policy gate before every service. The
policy gate applies the closed query grammar in `scripts/traefik_proof.py` and
returns the edge result before Hermes or the static server is contacted. It is
part of this disposable proof harness, not a production authentication
service. The retained evidence names this dependency instead of implying that
Traefik's native matchers alone prove exact query denial.

Traefik router rules use the normalized host name (`traefik-92.test`) because
that is the router matcher contract. The executable policy adapter requires the
standard ForwardAuth metadata: exactly one `X-Forwarded-Host` authority with
`:19444`, `X-Forwarded-For`, `X-Forwarded-Method`,
`X-Forwarded-Port: 19444`, `X-Forwarded-Proto: https`, and `X-Forwarded-Uri`.
Only copied `Origin` is permitted beside that generated set. The adapter's
ordinary `Host` is an ignored ForwardAuth-service transport header, not the
public authority. `Content-Length`, `User-Agent`, `Accept-Encoding`, and
`Connection: close` are explicit bounded transport exceptions; they are never
policy input or upstream forwarding. `Authorization`, `Cookie`, unknown
headers, and other connection tokens fail closed. The port value is checked
against the configured HTTPS entrypoint rather than trusted as arbitrary
forwarded input. `X-Forwarded-Uri` includes the query and is parsed for the
closed route grammar; it is not raw request-target evidence. No separate
raw-target, path, query, Upgrade, or Connection observation is claimed at the
adapter boundary.

WebSocket `Upgrade` and `Connection` enforcement is represented by the
Traefik router matcher (`HeaderRegexp`) only. Path-only exclusion routers send
malformed or non-GET WebSocket requests to an always-deny local endpoint so
they cannot fall through to the generic static router. The fixture records
Traefik `v3.7.6` as the requested minimum only; it does not claim that this
minimum or the `HeaderRegexp` syntax was accepted by a Traefik runtime.

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
- model-denied wrong Host (`421`), wrong WebSocket Origin (`403`), unknown paths
  or methods (`404`), traversal, encoded separators or dots, duplicate prefixes,
  malformed upgrades, and query mutations before modeled upstream access; and
- invalid, expired, or reused ticket outcomes remaining Hermes-layer results
  after the edge accepted the request.

Inbound forwarding fields are not trusted. The static entry point disables
insecure forwarded-header trust, and the executable adapter enforces a closed
case-insensitive header contract: the six generated ForwardAuth fields,
copied `Origin`, and only the explicit transport exceptions documented above.
`Authorization`, `Cookie`, unknown `X-Forwarded-*` metadata, direct hop-by-hop
spoofing, and non-`close` `Connection` values fail closed. C0, DEL, and C1
characters in forwarded request paths or targets are rejected before route
matching. The generated Hermes middleware emits a finite known-field override
map: private upstream `Host` and `Origin`, synthetic public
`Forwarded`/`X-Forwarded-*` metadata, one optional `/hermes` prefix, and only
the canonical WebSocket upgrade pair. Empty values express the intended finite
removal map, but this offline fixture does not prove Traefik's runtime removal
of RFC hop-by-hop headers or `Connection`-listed tokens. Traefik's
`customRequestHeaders` has no wildcard delete for arbitrary inbound
`X-Forwarded-*` names, so this fixture does not claim arbitrary forwarding
alias deletion either. Those runtime guarantees remain a future real Traefik
plus recording-upstream capture requirement or a dedicated sanitizer boundary,
outside this offline harness. Root and dashboard WebSocket routes use separate
header middleware so prefix stripping does not erase the `/hermes` contract.
The proof does not claim that a live Traefik/Hermes response has a cookie with
`Secure`, `HttpOnly`, `SameSite`, or `Path`: no real `Set-Cookie` response is
captured, so `cookie_proof.status` remains `not_proven`. It does retain a
synthetic `__Host-` canary model that requires `Secure`, `HttpOnly`,
`SameSite=Lax`, `Path=/`, and no `Domain`; the canary value is always
`redacted` and is not a live cookie observation.

The synthetic ticket ledger models the contract's 30-second, single-use Chat
and PTY ticket boundary. It records only fixed outcomes for first use, reuse,
expiry, and invalid tickets. Upgrade targets, queries, ticket values, and the
bounded ticket fragment are all represented by fixed `redacted` markers. Chat
and PTY upgrade retries are explicitly `disabled`; this does not claim that a
live Traefik runtime has exercised a retry path.

The synthetic PTY lifecycle models POSIX/WSL attach, input forwarding without
retaining bytes, detach, no cleanup before the 30-minute detached TTL, and
one eventual TTL reap. The model keeps a detached handle reconnectable at
exactly 30 minutes and reaps only after the boundary, at elapsed 30 minutes
plus one second. It deliberately does not claim immediate PTY kill or
replay-before-live ordering. These are lifecycle contract labels, not a live
Hermes process observation.

The annotated negative evidence includes an explicit no-upstream summary. All
edge-denied and direct-private-port vectors retain `upstream_request=false`.
The direct-port vector describes untrusted access denied at the required
private non-loopback Hermes TCP `9119` boundary; no socket is opened by this
fixture and no firewall is exercised.

## Offline harness and generated files

The regression suite starts `make_forward_auth_server()` on an ephemeral
loopback port and sends real standard-library `http.client` requests through
the adapter. The server bounds the request line, header count and bytes,
content length, the closed ForwardAuth header contract, and transport framing.
It rejects C0, DEL, and C1 request-target controls, symlinks, FIFOs, special
files, replacement races, and digest traversal or byte/time budget overruns.
Adapter allows are ForwardAuth `200` decisions; they are not WebSocket `101`
observations. This is an executable local policy harness only: it does not
start Traefik, Hermes, a provider, or any deployment listener.

`render_to_directory()` writes `traefik-static.json` and
`traefik-dynamic.json` under the requested output directory and binds the file
provider to that exact absolute dynamic filename. This lane does not invoke a
Traefik CLI or start a runtime. `traefik_runtime.required_minimum_version` is
`v3.7.6` as an unverified requested boundary, while
`traefik_runtime.runtime_validation` explicitly records that configuration and
`HeaderRegexp` compatibility are not claimed. A future live proof must exercise
an official Traefik build through its documented startup or configuration path
before making that runtime claim.

## Evidence bindings

`traefik-proof-evidence.json` is bound to:

- the reviewed Hermes source SHA;
- the same static build and shared route/deep-link fixture identities used by
  the disposable Caddy proof;
- the deterministic Traefik static/dynamic configuration digest;
- the deterministic runtime-input digest;
- the synthetic cookie, ticket, PTY, no-retry, and no-upstream model outputs; and
- the fixed synthetic proof-run boundary (`live_run=false`, `compatible=false`).

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

These checks are offline and use only standard-library policy, renderer, and
loopback adapter code. They do not invoke a Traefik CLI, and therefore do not
claim Traefik configuration parsing, `v3.7.6` minimum compatibility, or runtime
`HeaderRegexp` behavior. The suite does not claim a live Traefik deployment, a
Hermes process, provider availability, live cookie attributes, firewall behavior,
or issue #90 completion. Synthetic cookie and lifecycle models make the
reviewed invariants executable without upgrading them into live deployment
proof. The fixture keeps `proof_run.live_run=false` and
`proof_run.compatible=false`; only an authorized live exercise of the exact
reviewed and merged build against real Hermes in the required private topology
can clear that deployment gate.
