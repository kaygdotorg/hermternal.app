# Deployment proof matrix

Status: normative planning specification.

This matrix defines a disposable same-origin HTTPS proof for Hermternal beside Hermes Dashboard. Caddy and Traefik are equal reference deployments. The proof checks routing, authentication, cookies, WebSocket upgrades, public-origin policy, private binding, firewall behavior, PTY lifecycle, and log redaction. It is not a production reverse-proxy file, production credential set, or deployment approval.

## Topology and fixed boundary

The reference topology is:

- `https://<configured-origin>/` serves the static Hermternal web client.
- `https://<configured-origin>/hermes/` exposes the reviewed Hermes Dashboard surface under one public origin.
- Hermes listens on one recorded private, non-loopback address and port `9119`.
- The firewall permits `9119` only from the selected Caddy or Traefik proxy source address or addresses. It denies every other source and every public interface.

The Hermes bind address MUST be fixed and private. It MUST NOT be `127.0.0.1`, `::1`, `0.0.0.0`, `::`, or a dynamically selected address. The exact private address is deployment input to the disposable proof, not a value to copy into this document. The proxy MUST connect to that recorded address. A direct request from an untrusted host MUST fail at the network boundary and MUST NOT reach Hermes.

Terminal mode requires Hermes to run on a POSIX or WSL host. The proof MUST record the Hermes host class and MUST fail the Terminal case for an unsupported host. All Apple clients MUST NOT invoke `/api/pty`.

The fixed non-loopback rule is intentional. The reviewed Hermes authentication gate is not active on loopback. Older planning text that names loopback is superseded for this proof.

## Public origin and private bind

The public origin and the private Hermes bind authority are different authorities. The disposable proof MUST resolve that mismatch using the behavior accepted by the pinned Hermes source:

1. At the edge, validate the exact configured public `Host` and HTTPS scheme.
2. For browser WebSocket upgrades, validate the exact configured public `Origin`. Reject a wrong, missing-where-required, `null`, wildcard, or otherwise unapproved origin before an upstream request.
3. Only after those checks pass, map the upstream `Host` to the recorded Hermes bound authority and map the upstream `Origin` to the origin required by that authority and the pinned Hermes source. For the HTTP upstream, this is normally the bound private authority, such as `http://<hermes-bind-authority>`.
4. Record the public and mapped upstream values as separate redacted proof fields. Never accept the mapped values from request input.

This mapping is a disposable, source-compatible proof strategy. It lets Hermes apply its source-level host and origin checks while the edge remains the public policy boundary. The security tradeoff is that Hermes sees the mapped private authority, not the public browser origin. Hermes therefore does not independently validate the public origin. The edge allowlist, strict proxy configuration, private bind, and firewall become the primary public-origin controls. The proof MUST test those controls with both accepted and rejected public values and MUST fail closed if the source-compatible mapping is not proven.

## Route ownership and default denial

The exact route allowlist, methods, request forms, and response forms are owned by [`contracts/hermes-dashboard/manifest.md`](../../contracts/hermes-dashboard/manifest.md). This matrix names only the paths required to prove the known boundaries:

- `/api/ws` is the authenticated chat WebSocket path.
- `/api/pty` is the authenticated, web-only Terminal mode path.

The proxy MUST apply the Dashboard prefix exactly once. It MUST NOT infer, duplicate, strip, or broaden a route because a similar path exists. The proof MUST test both the public prefixed form and the upstream path mapping defined by the manifest. No route name not in the manifest is allowed by implication.

**Edge default deny has exact semantics:**

1. Normalize the request path without accepting traversal, an encoded separator, a duplicate prefix, or an ambiguous decoding.
2. Match the normalized path and method against the manifest allowlist.
3. If there is no exact match, terminate at the edge with HTTP `404`.
4. Do not redirect, rewrite to `/`, serve a static fallback, set a Dashboard cookie, or send the request upstream.
5. An unapproved method is also an edge default-deny case and returns HTTP `404` without an upstream request.
6. A request with an unapproved public `Host` is rejected at the edge with HTTP `421` and no upstream request.
7. A browser WebSocket request with a wrong, `null`, wildcard, or otherwise unapproved public `Origin` is rejected at the edge with HTTP `403` and no upstream request.
8. A protected route with no valid authentication MAY return the reviewed Dashboard or Hermes authentication response, but the proof MUST show that the request reached only the approved upstream route and did not bypass the auth gate.

The Caddy and Traefik proofs MUST use the same edge status and no-upstream rules for every edge default-deny case.

## Edge and Hermes status layers

Edge policy results and Hermes results are different evidence:

- Edge `404`, `421`, and `403` mean that the edge denied the path, method, public host, or public browser origin. These cases MUST show no upstream request.
- Hermes `400` and `4403` are upstream results after the edge has allowed the request to reach Hermes. The proof MUST record them as Hermes behavior, not relabel them as edge host or origin policy.
- A status alone is not enough. Every case MUST record the responding layer, whether Hermes was reached, the mapped upstream host and origin where applicable, and the redacted response or upgrade result.

The proof MUST NOT force Caddy, Traefik, and Hermes to share one status code when the layers have different source behavior.

## Positive route cases

| Case | Required behavior | Proof evidence |
| --- | --- | --- |
| Static client | `GET` and `HEAD` for the approved static paths serve the built web fixture from the public origin. | Edge response, content hash, and no Hermes upstream request. |
| Dashboard prefix | Each manifest-approved Dashboard path is forwarded under `/hermes/` with the prefix applied once. | Edge response, mapped upstream path, host and origin fields, and upstream trace show the exact path, method, and status. |
| `/api/ws` | A valid authenticated WebSocket upgrade uses the session's approved REST credential to obtain a fresh, short-lived, single-use `?ticket=` query and reaches the reviewed chat path. Browser and native password-provider sessions use a provider cookie; supported native OAuth or OIDC sessions use a source-issued bearer credential. | `101` upgrade, approved REST-auth evidence, ephemeral ticket use, strict public-origin result where applicable, mapped upstream host and origin, and close evidence. |
| `/api/pty` | A valid authenticated web Terminal upgrade on a POSIX or WSL Hermes host uses a fresh, short-lived, single-use `?ticket=` query and reaches the reviewed PTY path. | `101` upgrade, web-only client test, interactive input fixture, detach, and eventual TTL reap evidence. No PTY kill or replay-before-live guarantee is asserted. |
| Authentication | Login, callback, cookie, bearer, session, REST, and WebSocket ticket cases follow the manifest and provider-neutral authentication specification. | Redacted response headers, protected cookie attributes, protected native bearer handling, approved REST-auth calls, ephemeral ticket lifecycle, and safe logs. |

Web-only means a v0.0.1 web product feature. All Apple clients MUST NOT invoke `/api/pty`. The edge MUST NOT use a user-agent string as an authorization boundary. The route is protected by the reviewed Dashboard authentication, cookie, ticket, and origin rules; the platform and host restrictions are enforced by product clients and parity tests.

## Terminal host and lifecycle

Terminal mode is supported only when Hermes runs on a POSIX or WSL host. The proof MUST record that host requirement before it opens `/api/pty`.

At this source pin, WebSocket `Close` means detach. It does not promise an immediate PTY kill. Hermes reaps the detached PTY later by its TTL. The proof MUST show detach and eventual TTL cleanup. It MUST NOT promise replay-before-live ordering or another PTY replay guarantee.

## Required header and prefix checks

For every approved proxied request, the proof MUST verify the following:

- The public `Host` is the exact configured host after edge validation.
- The upstream `Host` is the recorded Hermes bound authority required by the pinned source-compatible proof.
- `X-Forwarded-Host` identifies the public host.
- `X-Forwarded-Proto` is `https` for the public request.
- `X-Forwarded-Prefix` is `/hermes` when the prefixed Dashboard route requires it.
- `X-Forwarded-For` or the reviewed client-address header contains the real client chain. Inbound spoofed forwarding headers are stripped before the proxy writes its own values.
- The public browser `Origin` is validated at the edge. The upstream `Origin` is mapped to the Hermes bound authority required by the pinned source. The proxy does not accept an unvalidated origin, replace it with a wildcard, or claim that Hermes saw the public origin unchanged.
- The path is prefixed once. A request that arrives already prefixed must not become double-prefixed, and an unprefixed request must not escape the approved public prefix.
- Only headers listed by the manifest or proxy policy are forwarded. Inbound `Authorization`, cookie, forwarding, and debug headers are not copied to logs or to unrelated routes.

The exact route-specific header names remain owned by the manifest. This matrix does not create an unsupported header contract.

## Cookie and ticket checks

For browser and native password-provider paths, the proof MUST capture `Set-Cookie` and compare the exact reviewed cookie name or prefix and attributes. Supported native OAuth or OIDC token and refresh paths return bearer material and MUST set no provider cookie; the proof MUST verify that absence separately. The cookie-path proof MUST fail if the proxy:

- removes `Secure` or `HttpOnly`;
- changes the reviewed `SameSite` value;
- widens `Domain` or `Path` beyond the reviewed public origin and prefix;
- rewrites a provider cookie into a different name or prefix;
- exposes a cookie on an unapproved path or host;
- logs `Cookie`, `Set-Cookie`, or server-managed refresh material.

A protected `HttpOnly` provider cookie MAY contain server-managed refresh material. That material is allowed inside the protected cookie, but it MUST NOT appear in logs, fixtures, browser history, or error text.

Browser and native password-provider REST calls MUST use the authenticated provider cookie. Supported native OAuth or OIDC REST calls MUST use the source-issued bearer credential. REST calls MUST NOT use a WebSocket ticket. Both `/api/ws` and `/api/pty` are gated WebSocket upgrades and require a fresh `?ticket=` query. Each ticket is short-lived and single-use, but not session-bound. The proof MUST reject missing, malformed, expired, and reused tickets. It MUST NOT claim that a ticket is rejected because it was presented with a different session.

A ticket MAY exist only in the ephemeral upgrade URL. For an unknown or reused ticket, the pinned source can emit the first eight ticket characters plus an ellipsis in its audit reason. The proxy, Hermes log configuration, upstream log filter, test harness, and client diagnostics MUST remove the full query value, full upgrade URL, and bounded audit fragment before logs are retained or collected. They MUST also keep those values out of browser history, crash reports, fixtures, and user-visible errors. A proof run that retains any ticket fragment fails.

## Caddy and Traefik cases

Run the same fixture set twice: once with Caddy and once with Traefik. Each run MUST cover:

1. HTTPS static load and asset failure behavior.
2. Every manifest-approved Dashboard route class.
3. Valid and invalid authentication.
4. Provider cookie prefix and attribute preservation, including allowed protected refresh material.
5. Browser and native password-provider REST calls with the provider cookie, supported native OAuth or OIDC REST calls with the source-issued bearer credential, and no WebSocket ticket.
6. `/api/ws` upgrade with a fresh ticket, wrong public origin at the edge, missing upgrade, invalid or expired ticket at the reviewed layer, reuse, mapped upstream host and origin, detach, and reconnect.
7. Web-only `/api/pty` upgrade with a fresh ticket on a POSIX or WSL Hermes host, interactive input, detach, eventual TTL reap, and an Apple-client negative case. No PTY kill or replay-before-live guarantee is tested.
8. Wrong host, cleartext request, unknown path, duplicate prefix, traversal, encoded separator, wrong method, and malformed upgrade.
9. Direct private-address access from the proxy host, an allowed source, and an untrusted source.
10. Header forwarding, public-to-private host/origin mapping, and removal of spoofed forwarding headers.
11. Edge, Hermes, access, error, and upstream logs with non-sensitive redaction canaries for password, cookie, Authorization, ticket, provider state, query, and transcript values.
12. Malformed JSON using only a non-sensitive marker, with upstream log controls that prevent the source parse-warning payload representation, capped at 240 characters, from exposing a secret or transcript.

A case passes only when the edge result, layer identity, upstream trace, mapped headers, lifecycle result, and redacted log result match the expected fixture. A route that returns the right status but reaches the wrong upstream is a failure.

## Negative and privacy checks

The proof MUST demonstrate all of these negative results:

- unknown paths return edge `404` and never reach Hermes;
- unknown methods return edge `404` and never reach Hermes;
- wrong public hosts return edge `421` and never reach Hermes;
- wrong public WebSocket origins return edge `403` and never reach Hermes;
- a Hermes `400` or `4403` result is recorded as an upstream result, not as an edge host or origin decision;
- HTTP or direct private-address requests cannot bypass HTTPS, the proxy, the firewall, or the Dashboard auth gate;
- duplicate prefixes, traversal, encoded separators, and ambiguous paths are denied;
- missing, malformed, expired, or reused tickets are denied;
- Apple clients make no `/api/pty` request;
- unsupported Hermes host classes fail the Terminal proof;
- no password-provider credential, protected-cookie refresh material, cookie, access token, provider state, ticket, ticket fragment, prompt, transcript, or raw secret header appears in retained logs or proof artifacts; the proof removes the pinned source's bounded invalid-ticket audit fragment;
- malformed JSON cases contain no secret or transcript-bearing payload, and upstream log controls are present and verified;
- no PTY kill, replay-before-live, or immediate-reap guarantee is claimed.

The proof harness MUST use fake credentials, redacted fixtures, and ephemeral data. It MUST destroy the test state after the run.

## Parity result

Caddy and Traefik are equivalent only when their normalized results match for every case:

- public status and upgrade outcome;
- responding layer and whether an upstream request occurred;
- normalized public and upstream paths;
- validated public host and origin;
- mapped Hermes host and origin;
- required prefix and forwarding headers;
- cookie name or prefix and security attributes;
- REST cookie or approved native bearer authentication and WebSocket ticket acceptance or rejection;
- redacted log output, including malformed-payload controls;
- POSIX/WSL host result, detach result, and eventual TTL reap;
- private bind and firewall outcome.

Any difference is a proof failure and blocks v0.0.1 deployment work. This file defines disposable evidence, not a production proxy configuration or production secret.
