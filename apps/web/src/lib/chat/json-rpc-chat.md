# Bounded Dashboard JSON-RPC chat transport

`json-rpc-chat.ts` is the W-07 browser transport seam for the reviewed Dashboard
surface. It is a typed, deterministic prototype boundary. It does not contact
Hermes, mint a ticket, own a browser credential, load a session over REST, or
persist a transcript.

## Pinned contract

- Dashboard contract: `dashboard-v0.0.1`
- Reviewed Hermes source: `f5be9236e00ddf2f2a412697f267078fc4ee068e`
- WebSocket route: `WS /api/ws`
- Upgrade mode: same-origin, one fresh ticket in an ephemeral `ticket` query
- Source event envelope: one text JSON-RPC object per WebSocket message
- Synthetic evidence only: no live deployment, proxy, provider, or Hermes call

The caller injects two boundaries:

- `ticketProvider(signal)` returns one fresh short-lived ticket;
- `createWebSocket(upgrade, signal)` consumes the explicit `{ path: "/api/ws",
  origin: "same-origin", query: { ticket } }` seam for one upgrade.

The transport does not build a URL, read cookies, add an Authorization header,
retain a ticket, or reuse a ticket after the factory call. Every explicit
`connect()` and `reconnect()` obtains a fresh ticket. Reconnect is never
automatic.

The W-05 ticket client remains the owner of the authenticated
`POST /api/auth/ws-ticket` boundary. This file only consumes its injected fresh
ticket provider. No production authentication or network integration is part of
this planning-only prototype.

## Server-first readiness and compatibility gates

The server sends the first application event. The client never sends a custom
handshake and never negotiates an invented protocol version.

```json
{
  "jsonrpc": "2.0",
  "method": "event",
  "params": {
    "type": "gateway.ready",
    "payload": {
      "skin": "source-defined",
      "change_events": true
    }
  }
}
```

The connection state remains `handshaking` until `gateway.ready` arrives. A
bounded gateway-ready deadline closes the socket and reports
`gateway-ready-timeout` when the event is missing.

After `gateway.ready`, the transport invokes two injected, non-network gates in
order:

1. deployment attestation against `dashboard-v0.0.1`, the pinned Hermes SHA,
   the reviewed route-manifest revision, and proxy proof;
2. the non-destructive behavioral probe.

`ready` is exposed only after both gates pass. Missing callbacks fail closed as
`incompatible`; a matching attestation never replaces the independent probe.
The gate evidence is static contract metadata plus the transient bounded
`gateway.ready` payload. It contains no ticket, prompt, credential, transcript,
host, or user data.

If a selected server session is configured, readiness enters `restoring` and
sends the source method `session.resume` with the selected opaque
`session_id`. The connection promise resolves only after the resume result is
received. The server owns the durable history; the transport does not mirror it.

## Reviewed wire methods and events

The client sends only these methods in this transport:

- `session.resume` for restoration;
- `prompt.submit` for a prompt;
- `session.interrupt` for an explicit stop;
- `approval.respond` for an active approval owner;
- `clarify.respond` for an active clarification owner.

The source-defined selected event names are:

- `gateway.ready`;
- `session.info`;
- `message.delta`;
- `reasoning.delta`;
- `thinking.delta`;
- `message.complete`;
- `tool.start`;
- `tool.complete`;
- `approval.request`;
- `clarify.request`;
- `error`.

Event bodies remain source-defined. The transport validates only the bounded
JSON-RPC envelope, the required event name, optional bounded session/request
correlation, and optional fixture sequence numbers. It passes the bounded
payload through as opaque transient data. Unknown additive fields are ignored.

Unknown additive non-interactive event names are ignored without creating UI
state. Unknown interactive names, including `sudo.request`, `secret.request`,
and other `*.request` events, fail closed as `incompatible`; they are never
promoted to approval or clarification.

Server replies and events share the channel. A reply is correlated only by the
JSON-RPC request `id`. The event `request_id` field is optional source data; it
is checked when present and otherwise correlated to the one active selected
session operation. An event is never interpreted as a request result.

The pinned source uses JSON-RPC parse error `-32700` and dispatch error `-32603`.
Both are surfaced as transport failures, not successful results. Raw server
messages, raw frames, close reasons, and adapter errors are not copied into
errors or hooks.

## Prompt, restore, control, and owner rules

`sendPrompt()` sends the source-shaped boundary below and retains no prompt
text after the call:

```json
{
  "jsonrpc": "2.0",
  "id": "rpc-id",
  "method": "prompt.submit",
  "params": {
    "session_id": "selected-session",
    "text": "..."
  }
}
```

A prompt acknowledgement may contain any bounded source-defined result. A
result is not required to contain an invented `{ "accepted": true }` field.
The acknowledgement and completion deadlines are explicit, bounded options.
An acknowledgement timeout is uncertain delivery and closes the context before
any retry decision.

`approval.request` and `clarify.request` each create exactly one local pending
owner for the active operation. The owner is extracted from a source payload
when present or assigned a bounded local owner marker when the source payload
omits an ID. The local marker is never echoed to Hermes.

- `approval.respond` validates the matching request and approval owner, then
  sends only source-shaped session routing, `choice` (`once` for an affirmative
  boolean and `deny` for a negative boolean), and `all` fields;
- `clarify.respond` validates the matching request and clarification owner,
  then sends only source-shaped `request_id` and `answer` fields;
- duplicate, late, mismatched, cancelled, or post-terminal responses are
  rejected locally;
- a control abort records the request ID in a bounded ignored-response set, so
  a late acknowledgement cannot fail the connection.

`session.interrupt` is the explicit stop operation. Its acknowledgement does
not fabricate a successful completion; the active request remains
`interrupting` until the server emits completion or the connection is restored.

An attached prompt abort is local cancellation and closes the current socket
instead of sending a replayable cancel frame. The next user-led recovery must
obtain a fresh ticket and restore the server session. Abort reasons are never
forwarded or retained.

## State and uncertain delivery

The observable connection states are:

`offline`, `auth_required`, `connecting`, `handshaking`, `ready`, `restoring`,
`reconnecting`, `delivery_uncertain`, `incompatible`, `failed`, and `closing`.

A transport loss, send failure, or acknowledgement timeout after prompt send
sets the prompt to `uncertain-delivery`. The completion rejects with that
semantic error. Reconnect preserves only the selected session identifier and
local UI-owned state; it never resends the prompt.

Restoration is a barrier:

1. obtain a fresh ticket;
2. receive `gateway.ready`;
3. pass attestation and behavioral probe;
4. call `session.resume` for the same server session;
5. inspect server-owned history/status outside this transport before any
   user-led resend choice.

A timeout is not proof of rejection. The transport provides no automatic prompt
retry and no automatic new-session fallback.

## Close-code mapping

The source-defined close observations are classified as follows:

| Code | Classification | Connection state |
| --- | --- | --- |
| `4401` | authentication rejected | `auth_required` |
| `4403` | host or origin rejected | `incompatible` |
| `4404` | embedded chat disabled | `incompatible` |
| `4408` | peer rejected | `failed` |
| `4409` | attachment superseded | `failed` |
| `4410` | PTY process exited | `failed` |
| `1011` | backend failure | `failed` |
| other or missing | unsupported | `incompatible` |

Unknown close codes never schedule unsafe automatic retry. A user close enters
`closing` and does not reconnect.

## Bounded parser and safety boundary

The parser bounds frame bytes, JSON depth, JSON nodes, object keys, array length,
string length, prompt length, IDs, sequence values, active requests, and pending
controls. It rejects duplicate object keys, invalid UTF-8, non-finite or unsafe
numbers, trailing JSON, and empty-container nesting beyond the exact configured
depth. Additive object fields remain valid after required-field validation.

The transport stores only bounded IDs, sequence counters, statuses, selected
session identity, pending-owner markers, and promise settlers for active work.
It does not store prompt text, ticket values, credentials, provider messages,
transcript history, event payload history, URLs, search terms, or deep-link
state. Consumer hooks receive transient typed values and cannot alter transport
state when they throw.

## Synthetic evidence and verification status

The implementation is bounded by these offline synthetic contract roots:

- `contracts/fixtures/behavioral-probe` — ready; probe fixture
  `c-04a-behavioral-compatibility`; live run remains false;
- `contracts/fixtures/compatibility-attestation` — ready; attestation fixture
  `hermternal.revision-attestation.v1`; live trust remains unrecorded;
- `contracts/fixtures/connection-restoration` — internally validated but
  registry coverage remains pending;
- `contracts/fixtures/session-persistence` — ready fixture root, while shared
  `chat-stream-and-completion` coverage remains pending;
- `contracts/fixtures/route-allowlist` — reviewed JSON-RPC route and event
  allowlist;
- `contracts/fixtures/deployment-security-browser-auth` and
  `contracts/fixtures/deployment-security-ws-ticket` — synthetic browser
  cookie and fresh-ticket boundary evidence;
- `contracts/fixtures/source-audit-compatibility-gate` — pinned source review
  and compatibility evidence.

These validators do not import Hermes, open a WebSocket, contact a provider,
read a live transcript, or claim deployment compatibility. They must retain
`live_claim: false`.

Benchmark evidence is **N/A — this is a planning-only protocol seam with no
production or release executable and no live gateway to measure**. The shared
benchmark contract and synthetic validator evidence remain the applicable
preservation record; no 30-sample product latency or bundle-size claim is made.

The unit suite uses a deterministic fake WebSocket and covers:

- server-first readiness, attestation/probe gates, and `session.resume`;
- exact prompt/control method names and source-shaped parameters;
- additive fields and unknown noninteractive/interactive event policy;
- ordered fixture sequences and malformed/oversized frames;
- disconnect before and after acknowledgement;
- fresh-ticket reconnect, stale-generation suppression, and no prompt replay;
- abort-triggered socket closure, send-failure cleanup, and late control-ack
  suppression;
- approval/clarification owner validation and acknowledgement deadlines;
- all pinned close-code classifications and the exact JSON depth bound;
- a browser-like no-network module import that does not touch `fetch` or
  `WebSocket` globals.

This is prototype evidence only. It does not prove a live gateway, ticket
endpoint, cookie policy, Hermes deployment, proxy behavior, production
WebSocket, or runtime motion/accessibility behavior.
