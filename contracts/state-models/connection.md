# Connection and restoration state model

**Status:** normative planning contract
**Applies to:** web, iOS, iPadOS, and macOS
**Dashboard contract:** `dashboard-v0.0.1`

## Purpose

This model separates transport health from Hermes session state. A WebSocket can fail while a server session remains recoverable. A new WebSocket is not a new conversation.

## Observable states

| State | Observable meaning | Allowed actions |
| --- | --- | --- |
| `offline` | No transport is open. | Start auth, connect, or wait for network. |
| `auth_required` | The server requires a verified identity or a fresh ticket. | Run the authentication model. |
| `connecting` | The client is opening the Dashboard transport. | Cancel or wait. Do not send application methods before readiness. |
| `handshaking` | The WebSocket is open and the client waits for `gateway.ready`. | Wait for the ready event. |
| `ready` | The transport is usable for the selected profile. | Restore or create a session. Send allowed methods. |
| `restoring` | The client is resolving the selected server session. | Wait for `session.resume` and the server history/status result. |
| `reconnecting` | The old transport ended and the client is trying to recover it. | Back off, cancel, or authenticate again. |
| `delivery_uncertain` | A prompt may have reached the server, but the result is unknown. | Restore first. Do not resend automatically. |
| `incompatible` | The deployment attestation is missing or mismatched, the behavioral probe failed, or a required route, method, event, or transport rule is absent or changed. | Stop chat and show the safe pinned-contract mismatch. |
| `failed` | The connection or restoration attempt failed with a known result. | Offer an explicit retry or sign-out. |
| `closing` | The user or lifecycle is closing the transport. | Finish cleanup. Do not start a retry. |

## Required sequence

### Initial connection

1. Authentication reaches `authenticated`.
2. In gated mode, the authenticated client mints a fresh ticket and opens `WS /api/ws?ticket=...`. A browser or native password-provider session authenticates ticket creation with its protected Dashboard cookie. A supported native OAuth or OIDC session uses its source-issued bearer credential. The ticket, not the cookie or bearer credential, authenticates the WebSocket upgrade. Non-gated local mode may use the source-defined token query.
3. The client enters `handshaking`.
4. The client waits for `gateway.ready`.
5. The client verifies the trusted out-of-band deployment attestation against the pinned Hermes SHA, route-manifest revision, and proxy proof.
6. The client runs the non-destructive behavioral probe.
7. The client enters `ready` only when both the attestation and probe pass and the selected surface is present.
8. The client enters `restoring` for the last server session or remains `ready` with an empty-session action.

### Reconnect

1. A transport loss enters `reconnecting`.
2. The client cancels in-flight response handling but keeps the selected server session identifier and the local draft.
3. The client obtains a new WebSocket ticket when required. It never reuses an expired or consumed ticket.
4. The client repeats the handshake and receives a new `gateway.ready`.
5. The client enters `restoring` and calls the source-defined resume/history/status path.
6. Only after restore completes may the client retry a method that is safe to retry. A prompt is not safe to retry when delivery is uncertain.

## Restore-before-retry rule

Restoration is a barrier. No prompt retry crosses the barrier.

- If the last prompt has a confirmed server rejection, the draft may be sent again after `ready`.
- If the last prompt has a confirmed server acceptance or visible server event, do not send it again.
- If the WebSocket ended after send and before a result, enter `delivery_uncertain`, restore the session, inspect server-owned history/status, and ask the user whether to resend only when the server does not show the prompt.
- A timeout is not proof of rejection. A reconnect is not proof that the server lost the prompt.
- Do not create a second session to avoid the decision.

## Transport observations

- `/api/ws` uses text JSON-RPC records. Send one JSON object per WebSocket message.
- `gateway.ready` is required before a request is sent.
- JSON parse errors use code `-32700`; dispatch failures use code `-32603`. Surface both as transport errors, not successful method results.
- A WebSocket close with authentication, host, peer, or disabled-chat codes enters `auth_required`, `failed`, or `incompatible` according to the close reason. Do not loop on a permanent rejection.
- A clean user close enters `closing` and never schedules reconnect.

## Invariants

- Transport state and session state are separate. `reconnecting` does not mean that the server session is closed.
- A new connection does not select a new profile or create a new session without a user action.
- Restoration uses server-owned history and status. The client has no durable transcript mirror.
- One active profile is allowed for one connection.
- Retry policy is idempotent only for discovery, history, status, and model options. Prompt delivery needs the uncertainty rule above.
- Unknown events and unknown close codes are observable compatibility failures. They must not trigger a destructive fallback.
- Every transition is interruptible by sign-out or explicit cancel. A backoff timer must not block user input.

## Failure outcomes

| Failure | State | Required result |
| --- | --- | --- |
| No network before connect | `offline` | Show offline state and allow retry. |
| Auth rejected during upgrade | `auth_required` | Invalidate the ticket and run auth recovery. |
| `gateway.ready` missing | `failed` | Close the transport and report handshake failure. |
| Required route or event missing | `incompatible` | Stop chat. Do not call an unreviewed fallback. |
| Prompt result unknown | `delivery_uncertain` | Restore first. Never auto-resend. |
| User closes the workspace | `closing` | Release the transport and do not reconnect. |
