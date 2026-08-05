# Hermes Dashboard compatibility specification

Status: normative planning specification.

Hermternal v0.0.1 targets the Hermes Dashboard protocol. It does not target the separate Hermes API-server contract. Dashboard names that are defined only by source are compatibility data, not assumed public API.

This document describes the compatibility gate. Exact route paths, methods, payloads, WebSocket messages, event names, error forms, and fixture names are owned by [`contracts/hermes-dashboard/manifest.md`](../../contracts/hermes-dashboard/manifest.md). This file intentionally does not invent route details.

The specification and its disposable proofs are not production credentials, production configuration, or a live Hermes connection.

## Release identity

Every release candidate MUST carry a compatibility record with these values:

- `hermes_source_sha`: one full, immutable 40-character Git commit SHA. A branch name, tag, moving ref, abbreviated SHA, or local working-tree state is not a pin.
- `deployment_attestation`: a trusted, out-of-band record that binds the deployment identity to `hermes_source_sha`, the route-manifest revision or digest, and the reviewed proxy proof. It is verified through the deployment or release channel, not read from a Hermes response.
- `route_manifest`: the exact path `contracts/hermes-dashboard/manifest.md` plus the manifest revision or digest used by the proof.
- `fixture_set`: the redacted request, response, WebSocket, event, error, and recovery fixtures for the pinned source revision.
- `behavioral_probe`: the redacted live-deployment probe and its expected results for the supported REST, authentication, WebSocket, edge, and Terminal behavior.
- `proof_run`: the date, tool versions, proxy variants, host class, and pass or fail result for the disposable proof.

At this source pin, Hermes has no server-observable source SHA field and no server-observable protocol-version field. The compatibility record MUST NOT require a version endpoint, response header, or guessed `dashboard_protocol_version`. The full SHA and deployment identity come from the out-of-band attestation. The behavioral probe is additional evidence; it does not replace the attestation.

The deployment or release gate MUST fail closed when the attestation is absent, malformed, unverifiable, or different from the pinned SHA, route-manifest revision, or reviewed proxy proof. It MUST also fail closed when the behavioral probe is missing or fails. A placeholder, missing value, or `unknown` source SHA means **not compatible** and MUST block the release.

A client or deployment gate MUST verify the attestation and behavioral probe before it treats an authenticated connection as usable. It MUST NOT silently downgrade, select the nearest known behavior, or continue with a guessed route shape.

## Supported surface

The v0.0.1 compatibility set covers the following behavior classes:

- provider-neutral authentication discovery, including the password-capable provider named `basic` and implemented by `BasicAuthProvider`, supported OAuth or OIDC callbacks, and rejection of unsupported callback transport;
- browser and native password-provider REST requests authenticated by the protected provider cookie, plus supported native OAuth or OIDC REST requests authenticated by source-issued bearer credentials;
- WebSocket ticket creation and ticket failure behavior;
- the chat WebSocket at `/api/ws`, including a fresh `?ticket=` upgrade, connection, reconnect, detach, and error behavior;
- web-only Terminal mode at `/api/pty`, including a fresh `?ticket=` upgrade, interactive input, detach, and eventual TTL reap on a POSIX or WSL Hermes host;
- session creation, restoration, and session state operations;
- prompt submission and streamed chat events;
- tool activity, approval, clarification, interruption, and failure events;
- active-model changes and the pending-change behavior during a stream;
- common error forms and redacted recovery fixtures.

Browser and native password-provider REST use the provider cookie. Supported native OAuth or OIDC REST uses the source-issued bearer credential. Both gated WebSocket paths, `/api/ws` and `/api/pty`, require a fresh, short-lived, single-use `?ticket=` query in the ephemeral upgrade URL. Tickets are not session-bound. The ticket query MUST NOT be persisted in application state, page URLs, browser history, fixtures, or errors. The pinned source can emit an eight-character ticket fragment in an invalid-ticket audit reason. The deployment compatibility proof MUST verify a log control that removes that fragment before logs are retained or collected. A deployment that retains the fragment is blocked. All Apple clients, including macOS, MUST NOT invoke `/api/pty`.

The chat WebSocket path is named `/api/ws` in the reviewed contract. The terminal path is named `/api/pty` and is web-only. These names do not grant permission to infer any other path, method, header, message, or payload. The exact route manifest remains the authority.

At this source pin, WebSocket `Close` means detach. Hermes reaps the detached PTY later by TTL. The compatibility set does not promise an immediate PTY kill, replay-before-live ordering, or another PTY replay guarantee.

## Compatibility check

The compatibility check MUST run before a client treats an authenticated connection as usable. It MUST record enough evidence to answer:

1. Which deployment attestation binds the tested deployment to the immutable Hermes source SHA?
2. Which route-manifest revision or digest was loaded?
3. Did the behavioral probe observe cookie-authenticated browser and password-provider REST, bearer-authenticated supported native OAuth or OIDC REST, and fresh-ticket WebSocket behavior for `/api/ws` and `/api/pty`?
4. Did the probe distinguish edge host/origin policy from Hermes `400` and `4403` upstream results?
5. Which redacted fixtures passed on web and Apple clients?
6. Did the Caddy and Traefik proofs produce the same approved, denied, mapped-header, log, and Terminal lifecycle results?

The check MUST fail closed if the deployment attestation is absent or mismatched, or if the behavioral probe fails. A behavioral match without an attestation is not sufficient proof of the source pin.

The client MUST show a safe, actionable incompatibility state when the check fails. The state MAY expose a deployment identifier, expected SHA, attestation status, or safe probe name, but MUST NOT expose cookies, passwords, refresh material, tickets, provider state, prompt text, transcript text, malformed payloads, or raw headers.

There is no server-observed protocol version to compare at this source pin. Missing server version metadata is expected and MUST NOT be converted into a guessed version. Missing or invalid attestation and failed behavioral evidence mean blocked. There is no best-effort mode in v0.0.1.

## Evidence rules

A compatibility record is valid only when all of the following evidence exists:

- source inspection or an equivalent reviewed record for the pinned SHA;
- a verifiable out-of-band deployment attestation for that SHA, route-manifest revision, and proxy proof;
- a behavioral probe for cookie-authenticated browser and password-provider REST, bearer-authenticated supported native OAuth or OIDC REST, fresh `?ticket=` upgrades on `/api/ws` and `/api/pty`, single-use and short-lived ticket rejection, and the fact that tickets are not session-bound;
- proof that ticket query values exist only in ephemeral upgrade URLs and that full values plus the pinned source's bounded invalid-ticket fragment are removed from retained access logs, error logs, debug output, browser history, fixtures, and user-visible errors;
- redacted fixtures for every supported behavior class;
- negative fixtures for missing or mismatched attestation, failed probes, invalid tickets, expired tickets, reused tickets, denied public origins, Hermes `400` and `4403` upstream results, malformed messages, unsupported methods, and unsupported host classes;
- a source-compatible deployment proof that strictly validates the public host and browser origin at the edge, maps upstream `Host` and `Origin` to the Hermes bound authority, and records the security tradeoff;
- explicit evidence that edge `404`, `421`, and `403` results are not confused with Hermes `400` or `4403` results;
- malformed JSON fixtures containing only a non-sensitive marker. On a JSON parse error, the pinned source emits a warning with the payload representation capped at 240 characters. The proof MUST verify upstream log controls. No malformed fixture may carry a password, cookie, ticket, provider state, prompt, transcript, or other secret;
- web and Apple parity tests against the same fixtures, with all Apple clients barred from `/api/pty`;
- a web-only `/api/pty` test on a POSIX or WSL Hermes host that proves interactive input, detach, and eventual TTL reap without claiming PTY kill or replay-before-live behavior;
- a WebSocket test for `/api/ws` with valid authentication, fresh ticket, invalid authentication, missing upgrade, wrong public origin where applicable, close, and reconnect;
- deployment proofs for both Caddy and Traefik;
- a review that confirms no fixture contains a production credential, live transcript, user data, protected-cookie refresh material, or secret header.

Fixtures MUST be tied to the pinned SHA and attested deployment. A fixture copied from an unpinned branch or a different Hermes release does not prove compatibility.

## Change policy

A change to a route, method, header, cookie, ticket, message, event, error, host/origin mapping, PTY lifecycle, or source revision requires a new compatibility review. The change MUST update the route manifest, redacted fixtures, behavioral probe, parity tests, deployment attestation, and compatibility record before client code relies on it.

If the Dashboard changes without a new approved attestation and behavioral probe, clients MUST remain blocked. A client MAY report that a newer revision is available, but it MUST NOT try to adapt at runtime.

This file is a specification and a disposable-proof gate. It does not pin a production checkout, add a live server, or create production credentials.
