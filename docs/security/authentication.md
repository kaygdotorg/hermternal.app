# Authentication specification

Status: normative planning specification.

Hermternal uses the authentication providers exposed by each Hermes Dashboard deployment. Hermternal does not define which provider is primary. The pinned `basic` plugin is implemented by the `BasicAuthProvider` class. It is a username/password provider, not HTTP Basic authentication. Provider discovery exposes source-defined `name`, `display_name`, and capability fields such as `supports_password`; it does not expose the Python class name. Authentik, Nous OAuth, OIDC, or another provider MAY be exposed by a deployment, but the client MUST discover the provider set and use only a provider covered by the compatibility record.

This document and its disposable proofs are not production credentials, production authentication configuration, or a live login flow.

## Authentication matrix

| Client | Discovery | Approved v0.0.1 path | Session material | Release status |
| --- | --- | --- | --- | --- |
| Web browser | Read provider-neutral Dashboard discovery over the configured HTTPS origin | Follow the provider's Dashboard browser flow. OAuth or OIDC is supported when the Dashboard exposes a reviewed browser callback. A provider with `supports_password: true`, including the pinned `basic` plugin implemented by `BasicAuthProvider`, MAY use its reviewed username/password form. This is not an HTTP Basic header flow. PKCE applies only to the reviewed OAuth or OIDC browser path; it is not required for the username/password path. | Browser-managed protected `HttpOnly` provider cookie. It MAY contain server-managed refresh material. The client does not read or copy the cookie. | In scope when discovery, callback, cookie, ticket, and route evidence pass. |
| iOS and iPadOS | Read the same provider-neutral discovery over HTTPS | The native password-provider cookie path is approved when discovery reports `supports_password: true`; the pinned `basic` plugin is implemented by `BasicAuthProvider`. Native OAuth or OIDC MAY be used only for a provider with a reviewed callback transport supported by the platform. | Password path: isolated protected provider cookie session; the cookie MAY contain server-managed refresh material. Supported native OAuth or OIDC path: source-issued bearer access and refresh material protected by Keychain Services and never copied into cookies, links, fixtures, or logs. | `BasicAuthProvider` is in scope. OAuth or OIDC is blocked for unsupported callback transport and when target-platform proof is absent or fails. |
| macOS | Same provider-neutral model as iOS and iPadOS | The native password-provider path, including the pinned `basic` plugin implemented by `BasicAuthProvider`, and supported native OAuth or OIDC callback paths are v0.0.1 targets after the shared Apple contract and authentication layer is stable. | Password path: isolated protected provider cookie session; the cookie MAY contain server-managed refresh material. Supported native OAuth or OIDC path: source-issued bearer access and refresh material protected by Keychain Services and never copied into cookies, links, fixtures, or logs. | In scope after the shared Apple contract and authentication layer is stable. macOS MUST NOT invoke `/api/pty`. |

The exact discovery, login, callback, session, and ticket routes are owned by [`contracts/hermes-dashboard/manifest.md`](../../contracts/hermes-dashboard/manifest.md). This document does not invent route names.

## Provider-neutral discovery

The client MUST:

- fetch discovery only from the configured Dashboard origin over HTTPS;
- treat the discovered provider identifiers, display labels, capabilities, and callback data as untrusted input until validated against the compatibility record;
- show the provider choices exposed by that deployment without imposing a Hermternal-owned provider order or policy;
- reject an unknown, malformed, or unsupported provider instead of coercing it to a password-capable provider or to a token flow;
- use the callback and scope data supplied by the reviewed Dashboard contract, not a hard-coded provider-specific URL;
- keep the chosen provider and pending authentication state isolated to the current server connection.

A provider discovery response MUST NOT cause the client to contact an arbitrary origin. An origin, callback, or issuer that is not covered by the configured deployment and compatibility record is blocked.

## Browser authentication

The web client MUST use the Dashboard browser flow on the same public HTTPS origin. It MUST use an approved OAuth or OIDC callback when that provider is discovered. If discovery reports a provider with `supports_password: true`, the browser MAY use its reviewed Dashboard form. The pinned provider named `basic` is implemented by `BasicAuthProvider`. The browser implementation MUST NOT create a Hermternal-specific password endpoint or send an HTTP Basic header in place of the provider flow.

PKCE is conditional on the reviewed provider mode, not on browser use in general. A `supports_password: true` provider follows its reviewed username/password form and does not enter the OAuth state or PKCE exchange. Only a reviewed OAuth or OIDC provider with callback evidence enters the state and PKCE requirements below.

The browser MUST:

- rely on the Dashboard to issue and refresh the provider cookie;
- keep the cookie in the browser's protected cookie mechanism;
- allow server-managed refresh material to remain inside the protected `HttpOnly` provider cookie, but never read, copy, export, or serialise it from JavaScript;
- avoid storing a password, reusable credential, access token, refresh token, ticket, or provider state in `localStorage`, `sessionStorage`, IndexedDB, a navigable URL, URL fragment, browser history, or source control;
- for a reviewed OAuth or OIDC provider, validate the callback state against the server-managed pending state; for the pinned Nous OAuth browser flow, require the provider exchange to validate the PKCE verifier. The username/password path for a `supports_password: true` provider does not create OAuth state or PKCE;
- apply a provider-specific OIDC `nonce` requirement only when the compatibility record covers it. The pinned Nous browser flow does not expose a separate `nonce`, so Hermternal MUST NOT invent a `nonce` requirement for that provider;
- return only to the validated same-origin application target;
- clear pending navigation state after success, cancellation, failure, or logout.

A WebSocket ticket is an exception only for the in-memory, ephemeral upgrade URL. It MAY appear as `?ticket=` on the `/api/ws` or `/api/pty` upgrade request. It MUST NOT become a page URL, bookmark, navigation entry, application state value, or user-visible error. The browser MUST NOT treat an access token or a ticket in a URL as a session. It MUST NOT accept an arbitrary `return_to`, redirect, or provider origin from a user-supplied link.

REST requests use the protected provider cookie. They MUST NOT use a WebSocket query ticket.

### Pinned browser OAuth source audit

The browser contract is frozen to [`NousResearch/hermes-agent@f5be9236e00ddf2f2a412697f267078fc4ee068e`](https://github.com/NousResearch/hermes-agent/tree/f5be9236e00ddf2f2a412697f267078fc4ee068e). The synthetic audit in [`contracts/fixtures/source-audit/oauth-browser/`](../../contracts/fixtures/source-audit/oauth-browser/) records the observable behavior without contacting a provider.

At this revision, for the pinned Nous browser OAuth flow:

- `hermes_cli/dashboard_auth/routes.py:auth_login` returns the reviewed password form before calling `start_login` when the provider reports `supports_password: true`. Only the OAuth branch receives `state` and a PKCE verifier from `start_login` and stores them in the short-lived `hermes_session_pkce` cookie. The route marks that cookie `HttpOnly`, `SameSite=Lax`, and secure when the request is HTTPS.
- `hermes_cli/dashboard_auth/routes.py:auth_callback` fails closed for a missing PKCE cookie, provider cancellation/error, a missing or mismatched callback state, or a provider `InvalidCodeError`. It passes the stored `code_verifier` to `complete_login`; a rejected code or verifier does not issue a session cookie.
- `plugins/dashboard_auth/nous/__init__.py:NousDashboardAuthProvider.start_login` builds the outbound authorization parameter map with `state`, `code_challenge`, and `code_challenge_method=S256`. Its cookie payload contains `state` and `verifier`; its `complete_login` sends `code_verifier` to the token endpoint.
- No separate OAuth/OIDC `nonce` is exposed or required by this pinned Nous flow. This does not override reviewed OIDC nonce semantics for another provider. Hermternal MUST NOT add nonce validation or claim nonce support for a provider that does not expose it.

A successful OAuth callback issues the provider-managed session cookie and clears the PKCE cookie. Cancellation and other callback failures do not create a session; a fresh login attempt is required. The provider's short-lived PKCE cookie remains server-managed and must never be copied into browser-readable storage.

## Native password-provider cookie path

The iOS, iPadOS, and macOS clients MUST support the native password-provider path when discovery reports `supports_password: true`. At the pinned source, the provider named `basic` is implemented by `BasicAuthProvider`. macOS follows the same contract after the shared Apple contract and authentication layer is stable:

1. Show the provider's username/password form in native UI. Do not log or persist the password.
2. Send the credentials only over the configured HTTPS connection to the reviewed Dashboard provider route. Do not send them in an HTTP Basic header, WebSocket URL, deep link, or query parameter.
3. Accept only the server-issued provider session cookie returned by the reviewed response. Do not manufacture a cookie or exchange the password for a Hermternal-owned token.
4. Keep the cookie in an app-isolated protected cookie store. A protected `HttpOnly` provider cookie MAY contain server-managed refresh material. Do not extract that material or persist it outside the protected cookie mechanism. Persist only separately approved session material in Keychain Services. Do not use a shared browser cookie store.
5. Use the authenticated cookie for all reviewed REST calls. REST requests do not use a ticket.
6. For each WebSocket upgrade, obtain a fresh, short-lived, single-use ticket through the approved Dashboard path. Put the ticket only in the ephemeral `?ticket=` upgrade URL for `/api/ws` or `/api/pty`. Apple clients MUST NOT invoke the web-only `/api/pty` route.
7. Treat tickets as not session-bound. Do not rely on a ticket matching a cookie session. The security proof relies on single use, short lifetime, HTTPS, edge policy, and log redaction.
8. Never send the password through a WebSocket, deep link, log field, crash report, notification, or user-visible error.
9. On logout, explicit account removal, or unrecoverable expiry, clear the provider cookie and the related approved Keychain item.

A native client MUST NOT persist a password-provider password. A protected short-lived provider cookie is session material, not a reusable Hermes credential. A ticket is a one-use, short-lived upgrade credential, not a session credential.

## Native OAuth and OIDC callback constraint

Native OAuth or OIDC is allowed only when the reviewed callback transport is accepted by the pinned Hermes native route and proven by the target Apple platform's system authentication-session contract. The pinned source includes an RFC 8252 loopback and PKCE native flow, but each Apple platform still requires a reviewed proof that its system authentication session and callback handling support that transport. A provider remains blocked when source acceptance is absent or when platform proof fails or is absent.

The clients MUST NOT work around an unsupported callback with an embedded login view, token interception, an unreviewed loopback relay, a copied browser cookie, or a provider-specific hidden route. A native OAuth or OIDC path requires a reviewed callback contract and parity evidence for that provider. A provider with unsupported callback transport remains blocked while other providers may remain in scope.

This constraint does not prevent browser OAuth or OIDC when the Dashboard exposes a reviewed browser callback. It does not prevent the approved native password-provider cookie path.

## Cookie, ticket, and origin controls

The authentication proof MUST check the exact cookie name or prefix and attributes returned by the pinned Dashboard contract. The proxy or client MUST NOT widen the cookie Domain or Path, remove `Secure` or `HttpOnly`, or change the reviewed `SameSite` behavior. If a `__Host-` cookie is used, the proof MUST require `Secure`, `Path=/`, and no `Domain`. If another provider-defined prefix is used, the proof MUST compare the exact reviewed name and attributes instead of guessing.

A protected `HttpOnly` provider cookie MAY carry server-managed refresh material. That material is allowed only inside the protected cookie mechanism. The client, proxy logs, fixtures, and error surfaces MUST NOT expose or copy it.

The edge MUST validate the exact configured public `Host` and browser `Origin` before a WebSocket request reaches Hermes. Browser WebSocket requests MUST carry the exact configured public `Origin`. A disposable source-compatible proof MAY map the validated public `Host` and `Origin` to the Hermes bound authority upstream; the mapping and its tradeoff are defined in [`docs/deployment/proof-matrix.md`](../deployment/proof-matrix.md). Native requests are not browser requests. A native password-provider session uses its isolated cookie; a supported native OAuth or OIDC session uses its source-issued bearer credential. Both use a fresh ticket for the gated WebSocket upgrade rather than a fabricated browser origin.

Browser and native password-provider REST requests use the authenticated provider cookie. Supported native OAuth or OIDC REST requests use the source-issued bearer credential. Both gated WebSocket paths, `/api/ws` and `/api/pty`, require a fresh `?ticket=` query ticket on the upgrade request. A ticket is short-lived and single-use, but it is not session-bound. A ticket MAY exist only in that ephemeral upgrade URL. The pinned source can place the first eight ticket characters plus an ellipsis in the audit reason for an unknown or reused ticket. The deployment proof MUST apply and verify an upstream log control that removes that fragment before logs are retained or collected. Proxy access logs, browser history, debug messages, crash reports, diagnostics, fixtures, and user-visible errors MUST contain neither a ticket nor a ticket fragment. If the source audit fragment cannot be removed from retained logs, the deployment fails the security gate. The client and proxy proofs MUST reject a missing, malformed, expired, or reused ticket. They MUST NOT claim that a ticket is rejected because it was presented with a different session.

## Required security proof cases

The web and Apple test suites MUST cover:

- provider discovery with the pinned provider name `basic`, `supports_password: true`, OAuth or OIDC providers, multiple providers, unknown providers, malformed providers, and no providers;
- same-origin and wrong-origin discovery and callbacks;
- browser OAuth or OIDC state and PKCE validation for each reviewed provider, cancellation, callback failure, safe return behavior, pinned Nous rejection of an unsupported separate nonce requirement, and reviewed-provider OIDC nonce semantics when declared by the compatibility record;
- native password-provider success, wrong password, expired cookie, logout, session renewal, isolated cookie storage, protected-cookie refresh material, and Keychain clearing, using the pinned `basic` provider fixture where applicable;
- native OAuth or OIDC success for a source-accepted, platform-proven callback transport, plus rejection for unsupported transport and for absent or failed target-platform proof;
- cookie prefix, `Secure`, `HttpOnly`, `SameSite`, Domain, and Path checks;
- browser and native password-provider REST requests authenticated by the provider cookie, plus supported native OAuth or OIDC REST requests authenticated by the source-issued bearer credential, all without a WebSocket ticket;
- fresh `?ticket=` upgrades for `/api/ws` and `/api/pty`, plus missing, malformed, expired, and reused ticket cases;
- no password, cookie, server-managed refresh material, access token, provider state, ticket, ticket fragment, or full callback URL in retained logs, fixtures, links, browser history, or source control, including removal of the pinned source's bounded invalid-ticket audit fragment;
- malformed JSON fixtures that contain no secret or transcript text, with upstream log controls that cover the source warning whose payload representation is capped at 240 characters;
- no direct filesystem, SSH, Hermes API-server, or arbitrary-origin fallback.

A proof failure blocks the affected flow. It does not permit a fallback to an unreviewed provider or route.
