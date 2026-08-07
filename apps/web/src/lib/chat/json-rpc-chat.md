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
- Evidence scopes: deterministic `fixture_only` tests and the pinned `official_image` browser lane

The caller injects two boundaries:

- `ticketProvider(signal)` returns one fresh short-lived ticket;
- `createWebSocket(upgrade, signal)` consumes the explicit `{ path: "/api/ws",
origin: "same-origin", query: { ticket } }` seam for one upgrade.

The transport does not build a URL, read cookies, add an Authorization header,
retain a ticket, or reuse a ticket after the factory call. Every explicit
`connect()` and `reconnect()` obtains a fresh ticket. Reconnect is never
automatic.

A genuine unauthenticated ticket response (`HTTP 401`) is represented as
`authentication-required` and publishes `auth_required`; it is not downgraded to
the generic retryable `failed` state. Other ticket failures, including `HTTP 403`,
remain distinct from that unauthenticated state.

The W-05 ticket client remains the owner of the authenticated
`POST /api/auth/ws-ticket` boundary. `browser-chat.ts` composes that client with
this transport for the pinned official Hermes image. It gives the real upgrade
URL directly to the browser `WebSocket` constructor, then gives JSON-RPC only a
fixed consumed marker. The ticket is not copied into controller state, browser
history, callbacks, diagnostics, or retained evidence. W-05 issue
[#119](https://github.com/kaygdotorg/hermternal/issues/119) and PR
[#271](https://github.com/kaygdotorg/hermternal/pull/271) are integrated in
`dev` at merge commit `965da31ba433c95c99ce85ef85f0485fa44e42e6`.

While the browser adapter is between ticket acquisition and JSON-RPC socket
consumption, it owns the prepared socket. Abort or provider failure clears and
closes that socket exactly once. Successful `createWebSocket` consumption
removes the browser abort listener before transferring ownership to JSON-RPC;
this prevents a cancellation race from double-closing the underlying socket or
poisoning the next explicit retry. If the signal aborts after a factory result
arrives but before JSON-RPC adopts it, the acquired socket is closed exactly once
and is never attached to a stale generation.

The `official_image` evidence scope binds the immutable upstream image reference
to the reviewed route manifest, source review, and proxy proof. The behavioral
gate accepts only the bounded server-first `gateway.ready` event already parsed
by this transport. This composition enables the browser lane; it does not claim
end-to-end compatibility until the full Playwright journey passes against that
exact official image.

## Deterministic W-07 fixture IDs

The focused fake-WebSocket evidence uses these stable, synthetic IDs, all bound
to `dashboard-v0.0.1` and Hermes SHA
`f5be9236e00ddf2f2a412697f267078fc4ee068e2`:

- `w07-gateway-ready-session-resume-v1` — server-first readiness and restore barrier;
- `w07-prompt-event-ack-ordering-v1` — event-before-ack and late-ack ordering;
- `w07-approval-state-invariant-v1` — requested/null and resolved/boolean approval states;
- `w07-disconnect-reconnect-no-replay-v1` — uncertain delivery and fresh-ticket recovery;
- `w07-close-code-classification-v1` — close mapping and stale-generation cleanup; and
- `w07-compatibility-gates-v1` — typed evidence, attestation, and behavioral-probe gates.

The shared C-19 registry still has pending C-05 and C-08 coverage. Child issue
[#281](https://github.com/kaygdotorg/hermternal/issues/281) owns the coordinated
registry update; PR #275 does not edit the shared `contracts/fixtures/index.json`
artifact or claim that pending rows are ready.

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
   the scoped deployment identity, the reviewed route-manifest revision and
   digest, the source-review artifact, and the reviewed proxy proof;
2. the non-destructive behavioral probe.

The typed evidence record binds the complete proof boundary:
`deployment.identity`, `deployment.trustChannel`, `deployment.scope`,
`routeManifest.path`, `routeManifest.revision`, `routeManifest.sha256`,
`sourceReview.path`, `sourceReview.sha256`, `proxyProof.path`, and
`proxyProof.sha256`, in addition to the fixed contract, Hermes SHA, WebSocket
path, and transient bounded `gateway.ready` payload. Artifact sizes are bounded
as metadata only. Missing or malformed evidence fails closed as `incompatible`.

`ready` is exposed only after both gates pass. Missing callbacks and gates that
do not settle before the bounded compatibility-gate deadline fail closed;
a matching attestation never replaces the independent probe. The evidence
contains no ticket, prompt, credential, transcript, host, or user data.

If a selected server session is configured, readiness enters `restoring` and
sends the source method `session.resume` with the selected opaque
`session_id`. The connection promise resolves only after the resume result is
received. `sendPrompt()` requires `ready` after this response; `restoring` is a
strict barrier that permits waiting or cancellation only. The server owns the
durable history; the transport does not mirror it.

An authenticated empty workspace can explicitly call `session.create` after
readiness. Hermes returns a short-lived live session ID and a distinct stored
session ID. The first prompt uses only the live ID; REST reconciliation uses the
stored ID after that prompt makes the row durable. The client validates both
identifiers, does not retry creation, and does not invent a durable session from
an empty REST list.

## Reviewed wire methods and events

The client sends only these methods in this transport:

- `session.create` for one explicit empty draft;
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
state. Official session-less global broadcasts, such as `sessions.changed`, use
an empty `session_id`; the transport normalizes that source sentinel to absent
before ignoring the event. Unknown interactive names, including `sudo.request`,
`secret.request`, and other `*.request` events, fail closed as `incompatible`;
they are never promoted to approval or clarification.

Server replies and events share the channel. A reply is correlated only by the
JSON-RPC request `id`. The event `request_id` field is optional source data; it
is checked when present and otherwise correlated to the one active selected
session operation. An event is never interpreted as a request result.

Acknowledgement receipt is tracked separately from operation lifecycle. If a
stream, approval, clarification, or completion event arrives before the reply,
the later acknowledgement cannot regress that event-derived state. If
completion removes an operation before its valid acknowledgement arrives, a
bounded late-ack tombstone consumes that response without reopening the
operation or failing the connection.

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
omits an ID. The local marker is never echoed to Hermes. Approval state is also
validated at the boundary: `state: "requested"` requires `approved: null`, and
`state: "resolved"` requires a boolean `approved`; contradictory combinations
fail closed as protocol violations.

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

The browser ticket adapter maps only a genuine `401` ticket response to
`authentication-required` and `auth_required`. Close observations remain attached
to the connection state, so the workspace can retain the terminal reason and
classification separately from its broad `permanent-error` state: `4401` carries
sign-in guidance, while `4403` carries incompatible-origin guidance. The
workspace treats authentication and compatibility failures as permanent until
the user takes the matching recovery action; a `403` or generic transport
failure remains a separate failure classification.

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

| Code             | Classification          | Connection state |
| ---------------- | ----------------------- | ---------------- |
| `4401`           | authentication rejected | `auth_required`  |
| `4403`           | host or origin rejected | `incompatible`   |
| `4404`           | embedded chat disabled  | `incompatible`   |
| `4408`           | peer rejected           | `failed`         |
| `4409`           | attachment superseded   | `failed`         |
| `4410`           | PTY process exited      | `failed`         |
| `1011`           | backend failure         | `failed`         |
| other or missing | unsupported             | `incompatible`   |

Unknown close codes never schedule unsafe automatic retry. A user close enters
`closing` during cleanup, then settles at `offline`. `reconnect()` is rejected
until a new explicit `connect()` call reopens the user-closed transport; no
callback or stale attempt can start a replacement socket during close.

## Bounded parser and safety boundary

The parser bounds frame bytes, JSON depth, JSON nodes, object keys, array length,
string length, prompt length, IDs, sequence values, active requests, and pending
controls. Session IDs use the route-manifest grammar: one ASCII letter or digit,
or 2–128 ASCII characters with an ASCII letter or digit at both ends and only
`.`, `_`, `-`, or `~` internally. It rejects duplicate object keys, invalid UTF-8, non-finite or unsafe
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

Benchmark evidence is **N/A for this W-07 prototype seam**. The deterministic
fixture is `w07-gateway-ready-session-resume-v1` plus the focused transport IDs
listed above. There is no production or release executable, no live gateway, and
no approved product performance budget in this planning-only PR, so latency,
render, memory, and bundle-size measurements would not describe a releasable
artifact. Environment, build mode, repetitions, distribution, raw trace, and
baseline are therefore **not applicable**, not omitted; the shared benchmark
validator evidence remains the applicable format-preservation record. The
registry child issue [#281](https://github.com/kaygdotorg/hermternal/issues/281)
will attach any future coordinated trace or approved N/A record after its C-05,
C-08, and W-05 dependencies are resolved. No 30-sample product claim is made.

The unit suite uses a deterministic fake WebSocket and covers:

- server-first readiness, attestation/probe gates, and `session.resume`;
- exact prompt/control method names and source-shaped parameters;
- additive fields and unknown noninteractive/interactive event policy;
- ordered fixture sequences and malformed/oversized frames;
- the strict restore barrier, event-before-ack state preservation, and
  completion-before-ack tombstones;
- disconnect before and after acknowledgement;
- fresh-ticket reconnect, stale-generation suppression, explicit close/offline
  cleanup, reconnect suppression, and no prompt replay;
- abort-triggered socket closure, send-failure cleanup, late control-ack
  suppression, pre-adoption socket cleanup, reconnect ticket replacement, and
  genuine-401 `auth_required` publication;
- complete compatibility evidence, missing-evidence failure, bounded gate
  timeout, route-manifest session-ID validation, approval/clarification owner
  validation, and acknowledgement deadlines;
- all pinned close-code classifications, including terminal state propagation for
  active prompts, and the exact JSON depth bound;
- a browser-like no-network module import that does not touch `fetch` or
  `WebSocket` globals.

This is prototype evidence only. It does not prove a live gateway, ticket
endpoint, cookie policy, Hermes deployment, proxy behavior, production
WebSocket, or runtime motion/accessibility behavior.
