# Authentication state model

**Status:** normative planning contract
**Applies to:** web, iOS, iPadOS, and macOS
**Dashboard contract:** `dashboard-v0.0.1`

## Purpose

This model defines what an authentication client shows and when it may open a Dashboard session.

The client discovers the providers exposed by Hermes. It does not choose a provider policy for the deployment. One configured Hermes profile is used for one server connection.

## Observable states

| State | Observable meaning | Allowed actions |
| --- | --- | --- |
| `signed_out` | No verified Dashboard identity is available. | Discover providers, start login, or show the signed-out screen. |
| `discovering` | `/api/auth/providers` is in progress. | Cancel the view or wait. Do not start a prompt. |
| `provider_unavailable` | Provider discovery failed or returned no usable provider. | Retry provider discovery after user action. Show the deployment error. |
| `redirecting` | Browser or system authentication has started. | Wait for the callback. Do not open a chat WebSocket. |
| `password_submitting` | The configured password provider is processing a login. | Disable duplicate submit. Allow cancel. |
| `native_exchanging` | A native authorization result is being exchanged. | Wait for the exchange or cancel the system session. |
| `authenticated` | `/api/auth/me` verifies a Dashboard identity. | Mint a WebSocket ticket when needed and restore the selected session. |
| `refreshing` | Native or server session renewal is in progress. | Keep the current view only if the session is still valid. |
| `expired` | The server rejected the session or renewal failed. | Clear usable session material and return to `signed_out`. |
| `logging_out` | Logout is in progress. | Disable duplicate logout. |
| `failed` | The last authentication action failed. | Preserve the safe error and allow an explicit retry. |

## Required transitions

1. App start enters `discovering` and calls `GET /api/auth/providers`.
2. A successful provider list enters `signed_out` unless a stored native session can be checked safely.
3. A browser provider starts `redirecting`. The callback enters `authenticated` only after `GET /api/auth/me` verifies the server session.
4. A password provider enters `password_submitting`. A successful response still requires the identity probe before chat starts.
5. A native provider enters `native_exchanging`. The client stores only approved credential material in Keychain Services. It then verifies the Dashboard identity.
6. A missing, expired, or rejected credential enters `expired`. The client must not keep using an old WebSocket ticket.
7. Logout enters `logging_out`, clears client session references, and returns to `signed_out` after the server response or a confirmed server rejection.
8. A network failure enters `failed` with a retry action. It must not erase a draft or claim that a prompt was rejected when the request result is unknown.

## Invariants

- No prompt, session mutation, or chat WebSocket starts before `authenticated`.
- A gated browser WebSocket uses a fresh single-use ticket from `/api/auth/ws-ticket`. The client never retries a ticket value.
- The browser does not store a password, refresh token, or reusable Hermes credential in local storage, session storage, IndexedDB, or a URL.
- Native credential material uses system authentication and Keychain Services. Do not copy it into a transcript, fixture, log, or deep link.
- A provider list is data, not permission to call every provider route. The client uses only the selected auth route family in the Dashboard manifest.
- One connection has one active Hermes profile. Profile switching and profile aggregation are not authentication states.
- An authentication error cannot be converted into a chat error by silently creating a new session.

## Native callback boundary

At the pinned Hermes revision, native OAuth or OIDC is supported only when the provider's reviewed callback transport is accepted by the native authorization route and proven on the target Apple platform. An unsupported or unproven callback is a release-blocking result for that provider, not a reason to add an upstream route in Hermternal.

The configured password path is supported when provider discovery advertises it. A deployment may also expose a supported native provider. The client must report the provider capability that it observed.

## Native bearer REST boundary

The web contract claims native bearer authentication only for the exact method/path pairs proven by the pinned source audit. The frozen set is `GET /api/auth/me`, `POST /api/auth/ws-ticket`, `GET /api/sessions`, `GET /api/sessions/search`, `GET /api/sessions/{session_id}`, `GET /api/sessions/{session_id}/messages`, `PATCH /api/sessions/{session_id}`, and `POST /api/chat/image-upload`. Parameterized session IDs match one non-empty path segment; a method change or path suffix is not covered.

A valid `Authorization: Bearer` session continues to the reviewed handler. An invalid or expired bearer enters the structured `401` recovery path and must not fall through to cookie authentication. A provider outage is a `503` failure that preserves the distinction between transient unavailability and bad credentials. Public discovery and native authorize/token/refresh routes are bootstrap or credential issuance/rotation paths, not authenticated REST routes. `POST /api/gateway/drain` belongs to a separate exact-path service-token seam and is not native bearer coverage.

Anything outside the reviewed method/path set is `blocked_unverified`: Hermternal must not claim support for it until a new source audit proves the route. This is a contract boundary for the web mock/proof and does not add a live Hermes integration. The deterministic evidence lives in [`native-bearer/README.md`](../fixtures/source-audit/native-bearer/README.md), [`source_audit.json`](../fixtures/source-audit/native-bearer/source_audit.json), and [`cases.json`](../fixtures/source-audit/native-bearer/cases.json); run [`test_native_bearer.py`](../fixtures/source-audit/native-bearer/test_native_bearer.py) to check the frozen inventory and negative cases.

## Recovery rules

- After a `401`, invalidate the current ticket and enter `expired`.
- After a transient network error, remain in the safe authenticated view only when the server session is not known to be invalid. The connection model owns reconnection.
- Never retry a password or native exchange without a user-visible attempt boundary.
- Never log credential values, callback query values, ticket values, or identity tokens.
- Authentication recovery restores the server session before a chat prompt can be retried. See [`connection.md`](connection.md) and [`chat.md`](chat.md).
