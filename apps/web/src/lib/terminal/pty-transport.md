# Current-session PTY transport

This module is the renderer-neutral browser boundary for the web-only
`WS /api/pty` route. It follows `dashboard-v0.0.1` and the pinned Hermes source
revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`.

The implementation and tests use injected, synthetic ticket and WebSocket
adapters. They do not contact Hermes, open a real PTY, read cookies, or own the
W-Term renderer, session coordinator, workspace shell, or Chat UI.

## Interface

`createFreshPtyTicketProvider` adapts the reviewed authenticated request seam to
one same-origin `POST /api/auth/ws-ticket` request per call. It requires the
closed `{ ticket }` response shape and keeps no reusable credential state.

`createPtyTransport` exposes state and byte/event subscriptions plus these
operations:

- `connect(input)` opens the active Hermes session. Missing or empty `attach`
  omits the query value and selects legacy mode. A non-empty `attach` requires
  the injected fail-closed attachment validator before ticket mint or upgrade.
- `reconnect()` is explicit and attach-only. Attachment identity is exactly the
  session ID, attach handle, and process identity; `detachedAtMs` remains local
  expiry evidence and cannot change a `4409` retry decision. Authorized reconnect
  validates the 30-minute detached window and mints a fresh single-use ticket.
  A `4409` superseded socket is blocked from reattaching because its replacement
  is already the active attachment. Permanent close classifications and
  expired/invalid attachment evidence expose `reconnectSupported: false`; `4401`
  remains recoverable through the auth path, while `4403`, `4409`, `4410`, and
  other deterministic failures stay fail-closed.
- `sendInput()` sends UTF-8 text or copied raw bytes only while attached.
- `resize()` sends one binary `ESC [RESIZE:<cols>;<rows>]` frame after clamping
  exact integers to `1..2000` columns and `1..1000` rows.
- `detach()` and `close()` remove every socket callback before closing. Attach
  mode enters `detached`; legacy mode enters `exited` because its bridge owns
  the child process lifetime. Explicit `close()` latches the reconnect denial;
  later cleanup such as `detach()` cannot weaken it. Only a new `connect()` call
  makes replacement user intent current again.
- An established attach socket that reports `onerror` without `onclose` enters
  `detached` and remains eligible for explicit reconnect. Before its callbacks
  are removed, that error records one write-once local retention anchor for the
  exact session, attach, and process identity. Repeated or stale errors cannot
  move that anchor; explicit reattach is permitted through the reviewed
  30-minute window and rejected after it. An error or close before `onopen`
  remains `failed` and cannot seed or extend a detach-retention window. Changing
  current-session identity discards the old expiry evidence.
  Cleanup and state observers are generation-guarded so a synchronous retry or
  replacement cannot be overwritten by the old failure or Close path. A new
  attempt claims its generation and active slot before aborting the old adapter,
  and reattach notices/readiness are rechecked after observer callbacks. State
  events are captured before observers, but `onStateChange` runs only if that
  transition still owns the generation after `onEvent`. Ticket-pending
  cancellation is rechecked before ticket minting, and `connecting` cancellation
  is rechecked again before constructing the opaque upgrade or invoking the
  socket factory. Therefore a reentrant observer cannot allocate a stale socket
  or consume a replacement generation's factory work. A detach timestamp is
  recorded only if adapter-controlled socket close returns without
  a replacement claiming the generation, so an old A cleanup cannot write
  evidence after reentrant B connects. Late socket-factory values are closed
  exactly once even when cancellation wins before the abort listener is
  installed. Coalesced callers share one ticket and socket, but each caller's
  abort signal only rejects that caller's wait; the shared attempt continues
  while another caller still owns a wait. If cancellation reaches an adapter
  that ignores its signal, the transport keeps that same-identity owner
  quarantined until its validator, ticket provider, or socket factory settles.
  A duplicate reconnect receives the deterministic aborted result instead of
  minting parallel low-level work; its late ticket or validator cannot publish
  state, and its late factory socket is closed without handlers. Explicit
  same-identity `connect()` after Close is different replacement intent: it may
  safely claim a new generation before the quarantined raw work settles, while
  `reconnect()` remains denied by the Close latch. A different identity may
  replace the current generation, but stale settlement can never reclaim it. If
  an established reattach is cancelled after `onopen`, its exact
  identity's detach-retention evidence is restored. `outputMayBeTruncated` is
  true only for the current successful reattach and resets on detach, Close,
  cancellation, failure, replacement, and unrelated generations.

The transport never queues input or resize frames. It has no prompt or tool
action method, so reconnect cannot replay those actions. The transport owns one
fresh ticket only while constructing its structured, same-origin
`PtyWebSocketUpgradeRequest.query` handoff; it does not copy the ticket into
state, storage, navigation, logs, or errors. The injected WebSocket factory owns
its received upgrade request and must not retain, log, or expose ticket material.
Errors are a closed semantic set and never include ticket values, ticket
fragments, attach handles, terminal bytes, socket reasons, or adapter errors.

## Retained output and races

Server frames remain raw bytes. `ArrayBuffer`, typed-array, and `Blob` frames are
copied without UTF-8 decoding. Async Blob conversion is serialized per socket,
and generation plus socket-identity checks discard stale work after replacement,
detach, Close, or a `4409` supersession.

The browser does not create a second replay buffer or transcript. On explicit
reattach it emits `output-may-be-truncated` with the normative 1 MiB server
capacity and marks every received byte event as potentially retained or live.
It preserves receive order and inserts no replay separator because the pinned
source exposes no replay boundary.

## Current-session browser adapter

`current-session-terminal.ts` composes this transport for the normal Svelte
workspace. `createBrowserPtyTransport()` requests a fresh same-origin ticket for
each transport attempt and constructs the same-origin `/api/pty` upgrade without
exposing the ticket, URL, socket, attach handle, or process identity to
presentation state. `CurrentSessionTerminalBridge` owns one transport and one
same-session binding at a time. It rejects stale PTY generations before byte
forwarding, invalidates a binding after unsolicited detach/failure/exit, and
maps `4401` to `authentication-required` while leaving `4403` as
`incompatible-origin`. `reconnectBinding()` creates a fresh opaque binding for
coordinator-owned attach-mode recovery; callers must not use the direct
transport reconnect method as a workspace lease. The coordinator may supply a
binding-adoption callback; the bridge invokes it before starting reconnect so a
synchronous transport `attached` event cannot outrun the new lease. Explicit
detach/close also rejects renderer-gated waiters synchronously.

The pinned source has no client-visible attach-token issuance route. The normal
browser bridge therefore connects in legacy mode and reports reconnect as
unsupported; it never fakes an attach identity or silently creates a replacement
PTY. Callers with a separately reviewed opaque attach/process-identity provider
may pass it to the bridge, in which case `reconnectBinding()` delegates to the
transport's exact attach-mode retention and supersession rules while returning a
new coordinator lease. Deterministic transport blocks hide retry rather than
presenting a reconnect action that cannot succeed.

The bridge can wait for the lazy TerminalSurface renderer-ready signal before
its first `connect()` and before an attach-mode `reconnect()`. This prevents
replay bytes from arriving before a renderer sink exists without adding a second
application-level replay buffer. The renderer owns bounded output queues; the
bridge and workspace snapshot do not retain terminal bytes.

## Verification scope

`pty-transport.test.ts` uses deterministic fake sockets. It covers fresh ticket
use, missing and empty legacy attach semantics, attachment preflight, raw byte
preservation, malformed non-binary frames, resize boundaries and malformed
types, active-session replacement, process-identity continuity, reconnect,
retention equality and expiry, truncation notice, receive-order races, no action
replay, `4409` stale cleanup, close-code classification, cancellation, Close,
and callback cleanup. Lifecycle regressions cover already-aborted attempts,
pre-open retry races, pre-open failure classification, established error-only
`onerror` detachment with a write-once retention anchor, stale-error expiry,
identity-scoped expiry evidence, reentrant Close replacement,
observer cancellation during `ticket_pending`, `connecting`, and reattach,
stale `onStateChange` suppression after `onEvent` Close, A-close/B replacement
retention evidence, abort-listener replacement races, post-ticket stale
continuations, and reentrant `connecting` cancellation, Detach, Close, caller
abort, and replacement that produce no stale factory call or socket. It also
covers late socket ownership, duplicate-caller cancellation,
adapter-close reentrancy, reattach-retention restoration, and prior-true
truncation resets across failure and replacement transitions. New deterministic
deferred-adapter regressions prove that ignored validator, ticket, and factory
cancellation fences the current identity until settlement: no duplicate ticket
or factory work starts, and a late factory socket is closed without state,
bytes, notice, or retry publication. Companion Close regressions prove that
explicit same-identity `connect()` safely supersedes each quarantined stage,
while reconnect stays closed-latched. Tests also verify that terminal bytes and
ticket material are not logged or retained in public state.

Accessibility is N/A for this transport-only change. It adds no UI nodes and
does not alter the renderer contract. Keyboard, focus, semantic naming, browser
zoom, contrast, reduced motion/transparency, and touch-target verification
remain owned by the Terminal renderer and workspace integration issues.

`pty-retry-authorization.bench.ts` measures only the synchronous same-identity
retry decision after a prepared `4409`; ticket minting, socket creation,
rendering, and network work remain outside the timed region. The checked-in
1,000-evaluation artifact reports p50 `0.000708 ms`, p95 `0.002461 ms`, and p99
`0.004835 ms`, with one setup ticket/socket and no blocked-attempt ticket/socket.
`threshold` is `null` because no reviewed latency budget exists. Reproduce it
with `bun src/lib/terminal/pty-retry-authorization.bench.ts` from `apps/web`.

`pty-error-retention.bench.ts` measures 1,000 opened attach adapter-error cleanup
and retention-anchor captures. It excludes setup ticket minting, socket creation,
rendering, and network work. The checked-in artifact reports p50 `0.000583 ms`,
p95 `0.002252 ms`, and p99 `0.004003 ms`; `threshold` is `null` until reviewed
latency evidence defines a budget. Reproduce it with
`bun src/lib/terminal/pty-error-retention.bench.ts` from `apps/web`.

`pty-reconnect-supersession.bench.ts` captures 30 deterministic cancellation
bursts per ignored adapter stage (validator, ticket, and factory), after five
warmups. Its checked-in sanitized test-mode artifact records min, median, and
p95 settle time plus ticket, validator, factory, opened-socket, cleanup, and
duplicate-owner totals. `provenance.sourceRevision` is the immutable source
commit at which the benchmark ran; the artifact is committed afterward, so it
does not claim an impossible self-hash. Reproduce it with
`GIT_SOURCE_REVISION=$(git rev-parse HEAD) bun src/lib/terminal/pty-reconnect-supersession.bench.ts`
from `apps/web`, then commit the resulting evidence separately. The current
artifact reports zero duplicate-owner violations; a latency threshold remains
`null` because this issue establishes a baseline rather than inventing a budget.

`pty-connecting-ownership.bench.ts` measures only the post-`connecting`
ownership-decision path: from a reentrant observer's cancellation or replacement
to the old operation's aborted settlement. It deliberately excludes ticket
minting before `connecting`, network, credentials, PTY bytes, rendering, and the
replacement's successful open. Thirty deterministic runs plus five warmups cover
caller abort, Close, Detach, and replacement. Its sanitized
`pty-connecting-ownership-benchmark.json` artifact records factory,
stale-factory, allocation, open, stale-state, and cleanup totals so a stale
generation must have zero factory calls and zero allocated sockets. At source
revision `7b02c3b25c95bee7928ef528ad6db97a95375fd8`, all 30 abort, Close, and
Detach runs had zero factory/allocation/open/stale-state/cleanup totals; all 30
replacement runs had one valid replacement socket and zero stale totals.
`provenance.sourceRevision` names the committed source revision measured before
its artifact is committed, avoiding a circular self-hash. Reproduce with
`GIT_SOURCE_REVISION=$(git rev-parse HEAD) bun src/lib/terminal/pty-connecting-ownership.bench.ts`
from `apps/web`; no latency threshold is claimed.
