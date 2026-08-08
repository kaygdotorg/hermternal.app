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
closed `{ ticket }` response shape and keeps no reusable credential state. Ticket
HTTP 401 and 403 both become the workspace-neutral `authentication-required`
error; response bodies, credentials, and ticket fragments never enter the error.

`createPtyTransport` exposes state and byte/event subscriptions plus these
operations:

- `connect(input)` opens the active Hermes session. Missing or empty `attach`
  omits the query value and selects legacy mode. A non-empty `attach` requires
  the injected fail-closed attachment validator before ticket mint or upgrade.
- `reconnect()` is explicit and attach-only. Attachment identity is exactly the
  session ID, attach handle, and process identity; `detachedAtMs` remains local
  expiry evidence and cannot change a `4409` retry decision. Authorized reconnect
  validates the 30-minute detached window and mints a fresh single-use ticket.
- `sendInput()` sends UTF-8 text or copied raw bytes only while attached.
- `resize()` sends one binary `ESC [RESIZE:<cols>;<rows>]` frame after clamping
  exact integers to `1..2000` columns and `1..1000` rows.
- `detach()` and `close()` remove every socket callback before closing. Attach
  mode enters `detached`; legacy mode enters `exited` because its bridge owns
  the child process lifetime. Ordinary detach preserves an unresolved validator,
  ticket, or socket-factory quarantine, so same-identity `connect()` and
  `reconnect()` return the deterministic aborted result until that raw adapter
  settles. Explicit `close()` authorizes a same-identity replacement after an
  ordinary user Close, but it does not erase a server 4403 or 4409 fence; only a
  different identity or the documented 4401 recovery transition clears those
  fences. Close is therefore an explicit replacement path, not a retry bypass.
- An established attach socket that reports `onerror` without `onclose` enters
  `detached` and remains eligible for explicit reconnect. Before its callbacks
  are removed, that error records one write-once local retention anchor for the
  exact session, attach, and process identity. Repeated or stale errors cannot
  move that anchor; explicit reattach is permitted through the reviewed
  30-minute window and rejected after it. Every pre-open error or close remains
  `failed` and removes no existing anchor, but it cannot seed or extend one.
  Established 4401 also remains `failed`, retains the exact anchor, and blocks
  `reconnect()` with `authentication-required`; after authentication, an
  explicit same-identity `connect()` is the only recovery action and performs
  one bounded reattach. Established 4403 remains a host/origin fence, and 4409
  remains a supersession fence, across detach and Close cleanup. Changing
  current-session identity discards old expiry evidence and clears those fences.
  Cleanup and state observers are generation-guarded so a synchronous retry or
  replacement cannot be overwritten by the old failure or Close path. A new
  attempt claims its generation and active slot before aborting the old adapter,
  and reattach notices/readiness are rechecked after observer callbacks. State
  events are captured before observers, but `onStateChange` runs only if that
  transition still owns the generation after `onEvent`. The external caller's
  `AbortSignal` is registered with the attempt before the validator is invoked;
  synchronous validator, `onStateChange`, `onEvent`, and `subscribe(listener)`
  cancellation or replacement therefore prevents ticket and socket work. The
  owner is rechecked before every validator, ticket, upgrade, and socket-factory
  stage. `ticket_pending` cancellation is rechecked before ticket minting, and
  `connecting` cancellation is rechecked again before constructing the opaque
  upgrade or invoking the socket factory. Therefore a reentrant observer cannot
  allocate a stale socket or consume a replacement generation's factory work. A
  detach timestamp is recorded only if adapter-controlled socket close returns
  without
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
runs for each ignored adapter stage (validator, ticket, and factory), after five
warmups. Stages execute sequentially, never with `Promise.all`. Each run retains
its rounded raw settle sample, validator, ticket, factory, per-socket open and
close counters, active-owner identity, and exact proof assertions. The harness
identifies sockets by connection identity, exercises real replacement `onopen`,
late `onmessage`/`onerror`/server-close emitters, bounds every wait, and proves
that Close nulls callbacks and late values cannot publish stale state, bytes, or
notices. The checked-in artifact is evidence of behavior and cleanup, not a
latency claim; `threshold` remains `null` because no reviewed budget exists.

`pty-connecting-ownership.bench.ts` measures only the ownership decision after
the `connecting` state observer runs. Its timer starts immediately before the
observer's Abort, Close, Detach, or replacement action and ends when the
cancelled operation rejects; ticket/connect setup before that observer is not in
the metric. It excludes network, Hermes, credentials, PTY bytes, rendering, and
unsupported latency budgets. Its v2 artifact retains raw samples, exact
identity-owned replacement `onopen`, callback-null and late-event proof,
expected ticket/factory counts, duplicate-owner checks, and per-socket cleanup.
The validator recomputes every distribution and total, binds assertions to the
expected stage ledger, and rejects failed or renamed proofs, concurrent-stage
metadata, missing provenance, or arbitrary source revisions.

Both v2 artifacts record the actual full source commit, source tree, git blob
and SHA-256 hashes for the declared benchmark source, transport, package
manifest, and lockfile. Provenance also records detached/clean checkout state,
Bun and embedded Node versions, host Node checked against `package.json` engine
requirements, package runtime declarations, OS release, architecture, CPU
model, and CPU count. Generate evidence from a clean detached source checkout,
writing outside the repository so the output file cannot make the checkout
dirty:

```sh
git switch --detach <sourceRevision>
bun src/lib/terminal/pty-reconnect-supersession.bench.ts > /tmp/pty-reconnect.json
bun src/lib/terminal/pty-connecting-ownership.bench.ts > /tmp/pty-connecting.json
```

Run those commands from `apps/web`, then copy the two JSON files into
`src/lib/terminal/` and commit them in a later evidence-only change. The
provenance helper derives `sourceRevision` from the actual `HEAD`; it rejects an
arbitrary `GIT_SOURCE_REVISION` override. Validate both artifacts from `apps/web`
with `bun run test:benchmark:pty`, which runs normal and `--optimized` validator
modes. The benchmark command is synthetic-only and never contacts Hermes,
opens a live endpoint, logs a ticket, or uses credentials.
