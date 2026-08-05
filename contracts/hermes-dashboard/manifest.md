# Hermes Dashboard v0.0.1 manifest

**Status:** normative planning contract
**Contract:** `dashboard-v0.0.1`
**Source:** `NousResearch/hermes-agent` at `f5be9236e00ddf2f2a412697f267078fc4ee068e`

## Purpose

This manifest defines the Hermes Dashboard surface that Hermternal v0.0.1 may use.

Hermternal is a client of the Dashboard surface. It is not a client of the separate Hermes API server. The manifest freezes route families, transport rules, method names, and observable behavior. It does not copy a server schema that the reviewed source does not define as stable.

The source revision is evidence for this contract. It is not a dependency in this repository. A later Hermes revision needs a new compatibility review.

## Deployment base

A deployment may serve Hermternal at `/` and proxy Hermes Dashboard at `/hermes/`. The route names below are relative to the Dashboard base. The proxy must preserve HTTPS, cookies, WebSocket upgrades, host checks, and the forwarded path prefix.

One Hermternal connection uses one configured Hermes profile. Profile discovery, profile switching, profile aggregation, and profile administration are not part of v0.0.1.

## Schema policy

- Route names, HTTP methods, WebSocket paths, JSON-RPC method names, event names, and state rules in this file are normative.
- Request and response bodies remain source-defined unless this manifest names an observable rule explicitly.
- Do not infer fields from a screen, a log line, a Python type, or an unknown JSON object.
- Clients must ignore unknown additive fields and must fail closed when a required route, method, event, or state rule is missing.
- Synthetic fixtures must identify `dashboard-v0.0.1` and must not contain live credentials, transcripts, hostnames, or user data.

## Selected route families

### Authentication

The client may use these routes:

| Method | Path | Use |
| --- | --- | --- |
| `GET` | `/login` | Server-rendered login entry point. |
| `GET` | `/api/auth/providers` | Discover the providers exposed by this Dashboard. |
| `GET` | `/auth/login` | Start the configured browser provider flow. |
| `GET` | `/auth/callback` | Complete the browser provider flow. |
| `POST` | `/auth/password-login` | Use the configured password provider when it is advertised. |
| `POST` | `/auth/logout` | End the Dashboard session. |
| `GET` | `/api/auth/me` | Verify the authenticated identity. |
| `POST` | `/api/auth/ws-ticket` | Mint a short-lived WebSocket ticket from an authenticated gated session for a browser or native client. |
| `GET` | `/auth/native/authorize` | Start the native authorization flow when the deployment supports it. |
| `POST` | `/auth/native/token` | Exchange a native authorization result when supported. |
| `POST` | `/auth/native/refresh` | Refresh native authentication material when supported. |

The client discovers providers. It does not impose a `BasicAuthProvider`, Authentik, Nous, or other provider policy. `BasicAuthProvider` is the pinned source's username/password provider, not HTTP Basic authentication. Browser authentication uses a server-issued secure session cookie. The browser must not store a password, refresh token, or reusable Hermes credential. Native clients use the system authentication session and Keychain Services for approved material.

The WebSocket ticket is single-use and has a 30-second time-to-live at the pinned revision. Mint one ticket for each gated WebSocket upgrade. Do not reuse a ticket after a failed or completed upgrade.

Native OAuth or OIDC is supported only when the provider's reviewed callback transport is accepted by the pinned native route and proven on the target Apple platform. An unsupported or unproven transport is release-blocked for that provider. Do not add an upstream callback extension in a client issue. The configured password path is valid when `/api/auth/providers` advertises it.

### Sessions and search

The client may use the active profile's session family:

| Method | Path | Use |
| --- | --- | --- |
| `GET` | `/api/sessions` | List server-owned sessions. |
| `GET` | `/api/sessions/search` | Search server-owned sessions. |
| `GET` | `/api/sessions/{session_id}` | Read one server-owned session. |
| `GET` | `/api/sessions/{session_id}/messages` | Restore the server transcript projection. |
| `PATCH` | `/api/sessions/{session_id}` | Update supported session metadata only when a reviewed fixture covers the operation. |

The client does not mirror the transcript in local storage. A memory cache may render the current view. The server remains the source of truth after refresh, reconnect, resume, or process restart.

Session creation, resume, interruption, close, and chat turns use the JSON-RPC channel below. A newly created empty session is not durable until the first prompt causes Hermes to persist it. Bulk delete, import, prune, profile session views, and profile management are blocked.

### Images

The only selected upload route is `POST /api/chat/image-upload`. It is for validated images attached to a prompt. Arbitrary files, file-system reads, audio, and data URLs from untrusted paths are outside the client contract.

### Structured chat WebSocket

- Path: `WS /api/ws`.
- Authentication: in gated mode, mint a fresh `/api/auth/ws-ticket` ticket and put it in the ephemeral WebSocket upgrade query as `?ticket=...`. Browser and native password-provider sessions use their protected Dashboard cookie to authenticate ticket creation. A supported native OAuth or OIDC session uses its source-issued bearer credential. Neither the cookie nor bearer credential directly authenticates the gated upgrade. Non-gated local mode may use the source-defined `?token=` path.
- Framing: use text JSON-RPC records. Send one JSON object per WebSocket message. Do not depend on the server splitting a message that contains several newline records.
- The first server event is `gateway.ready`. The source exposes `skin` and `change_events` in its payload, but their full shapes are not part of this contract.
- Replies and server events share the same channel. Correlate a reply only by the request identifier that the source returns. Do not treat an event as a request result.
- A parse failure is JSON-RPC error code `-32700` with message `parse error`. A dispatch failure is code `-32603` with message `internal error`. The client must surface the failure and must not retry a prompt automatically.
- A disconnected session may be detached for server-side recovery. A new connection and `session.resume` are the restore paths.

`/api/pub` and `/api/events` are Dashboard sidecar channels for the embedded TUI. They are not direct Hermternal client routes in v0.0.1.

### PTY WebSocket

- Path: `WS /api/pty`.
- Scope: web only on an attested POSIX or WSL Hermes host. It renders the full Hermes TUI. An unsupported or unverified host class blocks Terminal. Apple clients do not use this route in v0.0.1.
- Authentication: use a fresh gated WebSocket ticket when required.
- `attach` identifies the keep-alive PTY process. `resume` selects the Hermes conversation identity. `fresh=1` prevents implicit reuse of the active session and starts a fresh identity. These are opaque source-defined query values; the client must not construct their internal keys.
- The keep-alive registry retains a detached PTY for 30 minutes and reattaches it with the same opaque `attach` value.
- PTY output is binary and byte-preserving. Text input is encoded as UTF-8 bytes. Binary input is forwarded as bytes.
- The source-defined resize control is the complete byte sequence `ESC [RESIZE:<cols>;<rows>]`. The Dashboard consumes it as a resize command and does not write it to the PTY. Clamp dimensions to 1–2000 columns and 1–1000 rows before sending the control.
- The keep-alive replay buffer retains the newest 1 MiB of output. On reattach, retained and live bytes may race because the pinned source does not expose a replay boundary or guarantee replay-before-live delivery. A replay can also be incomplete when more than 1 MiB arrived while detached.
- The pinned source has no client-facing PTY kill operation. Navigation, transport loss, and the Hermternal **Close** action detach the socket. A running source reaper closes a PTY after process exit or after the detached retention window exceeds 30 minutes; its periodic interval means cleanup is eventual, not immediate.

The client must treat these close codes as observable outcomes: `4401` authentication rejected, `4403` host or origin rejected, `4404` embedded chat disabled, `4408` peer rejected, `4409` attachment superseded, `4410` PTY process exited, and `1011` backend failure. Other codes are unsupported and must not trigger an unsafe retry.

## Selected JSON-RPC methods

The client may send the following method names on `/api/ws`:

| Group | Methods | Rule |
| --- | --- | --- |
| Session | `session.create`, `session.resume`, `session.list`, `session.active_list`, `session.most_recent`, `session.history`, `session.status`, `session.close` | Use server session identity. Restore before a prompt retry. |
| Prompt | `prompt.submit` | Send text plus image references only. Delivery uncertainty is a state, not a reason to resend. |
| Control | `session.interrupt` | Stop the active turn. Do not fabricate a successful stop when the transport is lost. |
| Human input | `approval.respond`, `clarify.respond` | These are the only interactive approval and clarification replies in v0.0.1. |
| Model | `model.options` | Read picker options. Do not assume provider or pricing fields. |
| Model | `config.set` with the source-defined `model` key only | Change the active session model under the rules below. Other configuration keys are blocked. |

The selected source emits `session.info`, `message.delta`, `reasoning.delta`, `thinking.delta`, `message.complete`, `tool.start`, `tool.complete`, `approval.request`, `clarify.request`, and `error` events. The client may ignore unknown additive non-interactive events. It must not require `tool.progress`, and it must not treat `sudo.request`, `secret.request`, or another sensitive interactive event as an approval or clarification.

This manifest does not freeze a JSON schema for any method or event. The contract test suite must use redacted fixtures captured from the pinned revision and must fail when a required semantic observation changes.

## Active model switch

Model selection changes the active session, not every session on the server.

1. `model.options` provides the source-defined picker data. The client must not guess provider names or model identifiers.
2. An idle session applies a valid selection immediately. The selection is pinned to that session and is reported through normal session information.
3. A running or streaming session does not mutate the live agent mid-turn. The server records a pending selection and applies it at the next turn start. The current turn continues.
4. At the pinned revision, the server pops a deferred selection before applying it. If expensive-model confirmation is then required, that deferred selection is dropped. The client must not claim that it remains pending. Prefer submitting the confirmed selection after the current turn, or show that the user must confirm and select again.
5. A failed switch is a no-op. The old model remains active, and the error is recoverable. Do not persist a failed selection.
6. A resumed or rebuilt session reapplies its persisted per-session model override before the next prompt.
7. v0.0.1 does not call a global configuration switch. It does not mutate process-global environment state. A `scope` value that means global is outside the client contract.

## Version compatibility policy

- `dashboard-v0.0.1` is tested against exactly `f5be9236e00ddf2f2a412697f267078fc4ee068e`.
- A patch-level Hermes change may use this contract only when all selected route names, auth behavior, WebSocket framing, method names, events, model-switch rules, PTY rules, and state fixtures remain unchanged.
- A route rename, auth change, WebSocket framing change, method removal, required-field change, model-switch change, approval or clarification change, PTY close/replay change, or profile-scope change requires a new contract review and contract version.
- The selected v0.0.1 Dashboard surface does not expose its source SHA or a stable protocol-version field. The separate `/api/ssh/ownership` route returns `protocolVersion: 1`, but that SSH ownership protocol is explicitly blocked and outside this contract. A deployment must provide reviewed out-of-band attestation for the installed Hermes SHA, and the client or proof harness must also run a non-destructive behavioral probe before enabling chat. Missing or mismatched attestation blocks the connection.
- Compatibility is not negotiated by an invented Hermes header or query parameter. The deployment attestation, manifest, behavioral probe, and fixture revision form the compatibility record until Hermes publishes a stable wire version.

## Explicitly blocked surface

The client must not call, proxy, or expose these families in v0.0.1:

- Dashboard administration: `/api/config*`, `/api/env*`, `/api/system/*`, `/api/gateway/*`, `/api/hermes/update*`, `/api/ops/*`, `/api/logs`, `/api/ssh/*`.
- Profile and provider administration: `/api/profiles*`, `/api/providers/*`, `/api/credentials/*`, `/api/messaging/*`, `/api/pairing*`, `/api/webhooks*`, `/api/memory/*`.
- Filesystem and broad file access: `/api/files*`, `/api/fs/*`, `/api/media`, and `/api/console`. The image upload route above is the only exception.
- Plugin and integration management: `/api/plugins/*`, `/api/dashboard/plugins*`, `/api/skills*`, `/api/tools*`, `/api/mcp/*`, and `/api/cron/*`.
- Sensitive JSON-RPC methods: `cli.exec`, `shell.exec`, `slash.exec`, `browser.manage`, `process.list`, `plugins.manage`, `skills.manage`, `reload.mcp`, every `projects.*` method, every `complete.*` method, every `setup.*` method, every `billing.*` method, every `subscription.*` method, `usage.bars`, `llm.oneshot`, `sudo.respond`, and `secret.respond`.
- Configuration changes other than the active session model switch.
- Direct SSH, direct `~/.hermes` access, terminal backend selection, local transcript mirroring, profile switching or aggregation, Apple Terminal, Android, Windows, production telemetry, and live sharing links.

An unsupported method or route is not a hidden feature. It is a compatibility or scope error that needs explicit product approval.

## Review evidence

The source-only planning reconciliation is recorded in [`planning_review.json`](../fixtures/source-audit/planning-reconciliation/planning_review.json). Run [`validate.py`](../fixtures/source-audit/planning-reconciliation/validate.py) against a local checkout of the exact source SHA to verify file digests and anchors. This is a source review only; it does not replace deployment attestation, behavioral probes, or later focused fixture audits.

Review the pinned source paths before changing this manifest:

- `hermes_cli/dashboard_auth/routes.py`
- `hermes_cli/dashboard_auth/ws_tickets.py`
- `hermes_cli/web_routers/sessions.py`
- `hermes_cli/web_server.py`
- `hermes_cli/pty_session.py`
- `hermes_cli/pty_bridge.py`
- `tui_gateway/methods_prompt.py`
- `tui_gateway/methods_session.py`
- `tui_gateway/methods_complete.py`
- `tui_gateway/server.py`
- `tui_gateway/ws.py`
