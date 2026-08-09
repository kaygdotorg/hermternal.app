# Current-session PTY transport

This module is the renderer-neutral browser boundary for the web-only
`WS /api/pty` route. It follows `dashboard-v0.0.1` and the pinned Hermes source
revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`.

The implementation and tests use injected, synthetic ticket and WebSocket
adapters. They do not contact Hermes, open a real PTY, read cookies, or own the
W-Term renderer, session coordinator, workspace shell, or Chat UI.

## Interface

`createFreshPtyTicketProvider` adapts the reviewed authenticated request seam to
one same-origin `POST /api/auth/ws-ticket` request per call. The shared HTTP
boundary validates the exact `{ "ticket": "<URL-safe value>", "ttl_seconds": 30 }`
response, rejects duplicate or extra fields, and returns only normalized
`{ ticket }` to this PTY adapter. The adapter keeps no reusable credential state
and does not duplicate raw-response validation.

`createPtyTransport` exposes state and byte/event subscriptions plus these
operations:

- `connect(input)` opens the active Hermes session. Missing or empty `attach`
  omits the query value and selects legacy mode. A non-empty `attach` requires
  the injected fail-closed attachment validator before ticket mint or upgrade.
- `reconnect()` is explicit and attach-only. It reuses the exact session,
  attach, and process identity input, validates the 30-minute detached window,
  and mints a fresh single-use ticket. A `4409` superseded socket is blocked
  from reattaching because its replacement is already the active attachment.
  Permanent close classifications and expired/invalid attachment evidence expose
  `reconnectSupported: false`; `4401` remains recoverable through the auth path,
  while `4403`, `4409`, `4410`, and other deterministic failures stay fail-closed.
- `sendInput()` sends UTF-8 text or copied raw bytes only while attached.
- `resize()` sends one binary `ESC [RESIZE:<cols>;<rows>]` frame after clamping
  exact integers to `1..2000` columns and `1..1000` rows.
- `detach()` and `close()` remove every socket callback before closing. Attach
  mode enters `detached`; legacy mode enters `exited` because its bridge owns
  the child process lifetime. Explicit `close()` also blocks `reconnect()` until
  a new `connect()` call makes the user's intent current again.
- An established attach socket that reports `onerror` without `onclose` enters
  `detached` and remains eligible for explicit reconnect. An error or close
  before `onopen` remains `failed` and cannot seed a detach-retention window.
  Detached timestamps are scoped to the exact session, attach, and process
  identity; changing current-session identity discards the old expiry evidence.
  Cleanup and state observers are generation-guarded so a synchronous retry or
  replacement cannot be overwritten by the old failure or Close path. A new
  attempt claims its generation and active slot before aborting the old adapter,
  and reattach notices/readiness are rechecked after observer callbacks. State
  events are captured before observers, but `onStateChange` runs only if that
  transition still owns the generation after `onEvent`. Ticket-pending
  cancellation is rechecked before ticket minting or socket creation. The
  browser adapter converts the current HTTP origin to `ws:` or `wss:` and passes
  the transport-owned abort signal to the injected socket factory, so a PTY
  attempt can close its socket even when its caller has no signal. A detach
  timestamp is recorded only if adapter-controlled socket close returns without
  a replacement claiming the generation, so an old A cleanup cannot write
  evidence after reentrant B connects. Late socket-factory values are closed
  exactly once even when cancellation wins before the abort listener is
  installed. Coalesced callers share one ticket and socket, but each caller's
  abort signal only rejects that caller's wait; the shared attempt continues
  while another caller still owns a wait. If an established reattach is
  cancelled after `onopen`, its exact identity's detach-retention evidence is
  restored. `outputMayBeTruncated` is true only for the current successful
  reattach and resets on detach, Close, cancellation, failure, replacement, and
  unrelated generations.

The transport never queues input or resize frames. It has no prompt or tool
action method, so reconnect cannot replay those actions. The structured
`PtyWebSocketUpgradeRequest.query` is the one ephemeral, same-origin
upgrade-URL handoff for the fresh ticket; the transport does not copy it into
state, storage, navigation, logs, or errors. Errors are a closed semantic set
and never include ticket values, ticket fragments, attach handles, terminal
bytes, socket reasons, or adapter errors.

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
pre-open retry races, pre-open failure classification, established `onerror`
detach semantics, identity-scoped expiry evidence, reentrant Close replacement,
observer cancellation during `ticket_pending` and reattach, stale
`onStateChange` suppression after `onEvent` Close, A-close/B replacement
retention evidence, abort-listener replacement races, post-ticket stale
continuations, late socket ownership, duplicate-caller cancellation,
adapter-close reentrancy, reattach-retention restoration, and prior-true
truncation resets across failure and replacement transitions. Tests
also verify that terminal bytes and ticket material are not logged or retained
in public state.

Accessibility is N/A for this transport-only change. It adds no UI nodes and
does not alter the renderer contract. Keyboard, focus, semantic naming, browser
zoom, contrast, reduced motion/transparency, and touch-target verification
remain owned by the Terminal renderer and workspace integration issues.

Performance evidence is limited to the bounded implementation rules: no local
replay accumulation, one serialized conversion chain per active socket, and
immediate stale-context release. No reviewed runtime latency or memory budget
exists, so this issue does not claim a threshold.

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

The retry-authorization and error-retention artifacts are legacy v1 PTY
benchmarks. They are intentionally outside the current v2 default validator:
the v2 validator accepts only the two reviewed reconnect and connecting
ownership schemas, so those legacy files need separate reviewed coverage before
any release validation includes them.

`pty-reconnect-supersession.bench.ts` captures 30 deterministic cancellation
runs for each ignored adapter stage (`validator`, `ticket`, and `factory`), after
five warmups. Stages execute sequentially, never with `Promise.all`. Its measured
`sampleMs` starts immediately before ordinary `detach()` begins quarantine
settlement, after the relevant validator, ticket, or factory work has been staged,
and ends when the ignored adapter settles after `detach()` and the blocked
reconnect. A pre-connect `negativeControlSampleMs` includes staged work only as a
control; it is not part of `sampleMs`. Recovery, close, all-sink publication
checks, and delayed-Blob completion remain outside the measured interval. The
transport's PTY owner is the full structured tuple `{ sessionId, attach,
processIdentity }`; `detachedAtMs` is local expiry evidence and is not part of
that identity. The v2 JSON proof intentionally records that complete
deterministic synthetic tuple in `expectedOwnerIdentity`,
`activeOwnerIdentities`, `staleSocketIdentity`, and `replacementSocketIdentity`
because the validator must prove identity continuity; these values are fixture
labels, not live credentials or runtime handles. Each socket allocation remains
a separate ordered `socketClosures` row containing its synthetic `socketId`,
owner tuple, `opened` state, and exact `closeCalls` count. These are unique
per-socket records, not a promise that the serialized owner label is globally
unique: same-owner stale and replacement sockets can share a label, but cannot
be collapsed into one cleanup count. Live attach handles, live process
identities, credentials, PTY bytes, socket reasons, and real user data must
never enter retained evidence. The validator requires the expected owner set,
no duplicate active owner, exact per-socket cleanup, and exactly-once close
proofs.

Each run retains its rounded raw settle sample, exact validator counts
(`validatorCalls` is `2` and `validatorCallsBeforeRecovery` is `1`),
stage-dependent ticket and socket-factory counts before and after recovery,
opened-socket count, stale/replacement identities and close counts, callback
nulling, all four late-callback dispatch counts, post-close state/bytes/notice
counts, and exact proof assertions. The harness exercises the real replacement
`onopen`, late `onmessage`/`onerror`/server-close emitters, and bounded waits.
Recovery is outside the measured quarantine-settlement interval. The checked-in
artifact is evidence of behavior and cleanup, not a latency claim;
`threshold` remains `null` because no reviewed budget exists.

`pty-connecting-ownership.bench.ts` measures only the ownership decision at the
`connecting` lifecycle boundary. Its measured `sampleMs` starts at
`performance.now()` immediately before the observer's Abort, Close, Detach, or
replacement action and ends when the cancelled operation rejects. A separate
pre-connect `negativeControlSampleMs` starts before `connect()` and intentionally
includes validation and ticket setup; it is a control that proves those stages are
outside `sampleMs`, not a second latency metric. Recovery, socket opening, late
callback dispatch, delayed-Blob completion, sink assertions, and final cleanup
remain outside the measured ownership interval. It excludes network, Hermes,
credentials, PTY bytes, rendering, and unsupported latency budgets. Its synthetic
validator returns immediately and is not a timed or serialized validator-call
metric. For Abort, Close, and Detach, the connecting guard prevents the stale attempt
from becoming an active owner. The approved transport may still invoke the
socket factory after the observer cancels; the returned value is retained as one
unopened stale socket and closed exactly once. The artifact therefore records one
ticket request, one stale factory value, one exact unopened cleanup row, no active
owner, no bound socket callbacks, and zero late-event dispatches. In those runs,
`connectingGuard` proves stale ownership was fenced; callback-null and
late-callback assertions are conditional over the callback-free stale adapter,
not fabricated callback coverage. Replacement invokes the stale factory once,
then allocates one identity-owned replacement socket, proves its real `onopen`,
and then proves callback nulling, late-event suppression, and exactly-once close.
The connecting producer's stale owner is the exact synthetic tuple
`{ sessionId: "benchmark-session-a", attach: "benchmark-attach-a",
processIdentity: "benchmark-process-a" }`. The validator uses that tuple for
`staleSocketIdentity`, `staleSocketIdentities`, every stale `socketClosures` row,
and connecting cleanup proofs, including the replacement stage. The unsuffixed
`benchmark-session` / `benchmark-attach` / `benchmark-process` tuple belongs only
to the separate reconnect schema; it must not satisfy connecting evidence.
The v2 artifact retains raw samples, expected ticket/factory counts,
duplicate-owner checks, the ordered per-socket cleanup ledger, and the
conditional callback proof.

The current-v2 all-sink/delayed-Blob proof contract for both artifacts is
implemented in this source correction. It retains every issued stale callback
and requires suppression at every transport
publication sink. Each v2 run records
`callbackBoundSocketCount`, `callbackBoundSinkCount`, and
`callbackProofApplicable`, plus the pre-cleanup `replacementStateStatus`
(`attached` for an applicable recovery/replacement and `null` for an
inapplicable connecting cancellation), and a `stalePublications` ledger for
`onEvent`, `subscribe`, and `onStateChange`; `callbackProofApplicable` must agree
with those counts: replacement runs require one bound socket and three bound
sinks, while pre-factory cancellation runs prove callback inapplicability rather
than vacuous coverage. Each sink row has exact
`eventCount`, `stateCount`, `bytesCount`, and `noticeCount` fields, all four of
which must be zero after close. The browser bridge's transport subscriber remains
covered by the subscriber path. The delayed-Blob proof records `scheduledCount`,
`completionCount`,
`dispatchedBeforeClose`, `conversionStartedBeforeClose`, `resolvedAfterClose`,
and `postCloseBytesRejected`. On applicable runs, the counts must be exactly
`1`/`1` and every delayed-Blob boolean must be true: a synthetic
`Blob.arrayBuffer()` is dispatched and conversion starts before cleanup, its
completion resolves only after cleanup, and it publishes no bytes, state, or
notice. All sink ledgers and delayed-Blob assertions are required proof fields
and remain outside the timed interval.

The validator recomputes every distribution from rounded raw samples and every
total from the raw run counters. It enforces exact schema-specific run,
counter, assertion, owner, and close-ledger expectations; sequential stage
metadata; and all proven-true cleanup and late-event assertions. Standard
validation (`bun run validate:benchmark:pty`) is schema-strict but ignores JSON
object-key order, including nested metadata and `sourceBlobs` order. Optimized
validation (`--optimized`) reruns the same checks and additionally requires the
exact canonical key order for the root, nested metadata, ledgers, and source
blobs; it is a stricter evidence mode, not a different benchmark. Both modes
reject failed or renamed proofs, wrong validator/ticket/factory counts,
concurrent-stage metadata, missing provenance, or arbitrary source revisions.

Both v2 artifacts record the exact reviewed source S commit and generation
commit, source tree, and Git blob plus SHA-256 hashes for both benchmark sources,
transport, package manifest, lockfile, and provenance helper. The helper is
execution-critical because changing it changes the evidence contract. Four-blob
provenance is reserved for the explicitly named legacy v1 retry and error
artifacts; every current v2 artifact requires all five inputs, including its
helper. Provenance also records a clean detached checkout. Runtime provenance distinguishes Bun's embedded Node
version from the host Node executable, records Bun/package-manager and declared
engine versions, and requires the host Node to match `package.json`; it also
records OS release, architecture, CPU model, and CPU count. Detached checkout
provenance describes evidence generation and is separate from PTY
`detachedAtMs`. The reviewed correction uses a two-step trust record. Source S is the exact
reviewed commit `7f25cd496f60732e5f6fdf5ba4781ee55e911ecb`; trust pin P is a
separate later commit containing the immutable S manifest and the reviewed
validator and CLI blobs. The validator must run from P, not from an evidence
checkout, and the evidence checkout must descend from P before adding only the
two retained JSON paths. A source M that changes benchmark inputs, transport,
package or lock files, validator, or CLI cannot self-authorize: P rejects its
source manifest or its non-evidence descendant paths. Changed paths are read as
exact NUL-delimited Git bytes; leading/trailing whitespace, controls,
newlines, duplicate names, and invalid UTF-8 are rejected without trimming.
The helper derives `sourceRevision` from the actual `HEAD` and rejects an
arbitrary `GIT_SOURCE_REVISION` override. Evidence generation remains blocked
until independent review approves the all-sink/delayed-Blob proof
contract and the corrected metric boundaries. Legacy v1 remains outside current
v2 scope, and current v2 evidence requires exactly five source blobs, including
its helper. Do not regenerate or copy either retained v2 JSON; the retained
reconnect and connecting files remain historical
proof inputs and must stay byte-for-byte untouched. Once that review gate is
cleared, generate new evidence from a clean detached source checkout, writing
outside the repository so the output file cannot make the checkout dirty:

```sh
git switch --detach <sourceRevision>
bun src/lib/terminal/pty-reconnect-supersession.bench.ts > /tmp/pty-reconnect.json
bun src/lib/terminal/pty-connecting-ownership.bench.ts > /tmp/pty-connecting.json
```

After independent review clears the gate, run those commands from `apps/web`,
then create a detached evidence checkout from trust pin P. Only newly generated,
independently reviewed outputs may be added in a later evidence-only change; do
not copy either retained v2 JSON into that checkout. Invoke the validator and CLI
from the P checkout while pointing at that evidence checkout; do not run
validator code loaded from E. The two retained JSON files in this source tree are
historical, not-current evidence under the S-to-P trust pin. They remain
byte-for-byte untouched by this correction; the focused harness writes temporary
E artifacts for current standard and optimized validation. Validate both
artifacts from `apps/web` with `bun run test:benchmark:pty`, which runs standard
and `--optimized` validator modes. The benchmark command is synthetic-only and
never contacts Hermes, opens a live endpoint, logs a ticket, or uses credentials.
