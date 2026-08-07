# Shared Chat and Terminal session coordinator

`coordinator.ts` owns the browser runtime's one selected Hermes session identity.
It is a narrow prototype seam between the reviewed W-07 Chat transport and a
future W-Term adapter. It does not render either workspace, open a PTY, create a
Hermes session, or mirror transcript content.

## Invariants

- `activeSessionId` is one bounded opaque server identity in memory.
- `activate('chat')` and `activate('terminal')` reuse that identity. There is no
  create-session operation in the coordinator.
- A mode switch never calls the other workspace's renderer or transport. A
  Terminal attach is coalesced while pending, and a completed binding is reused
  until the selected session changes. Repeated Terminal activations transfer
  focus ownership to the latest Terminal request without starting another attach.
- `setSession()` increments the session generation, invalidates and releases the
  old Terminal binding before awaiting Chat restoration, and ignores late
  completions from the previous generation.
- A Terminal attach failure is reported as `terminal-attach-failed`; the Chat
  transport remains open and usable. Switching back to Chat focuses the composer
  without retrying or replaying a prompt.
- `reconnect()` coalesces concurrent calls to the existing Chat transport. It
  does not reattach an already valid Terminal binding.
- `restore(sessionId)` uses the server-backed Chat restore boundary after a
  browser refresh. No messages, prompt text, or local transcript mirror are
  retained by this module.
- Deployment evidence must be explicitly compatible with the pinned
  `dashboard-v0.0.1` contract and Hermes revision
  `f5be9236e00ddf2f2a412697f267078fc4ee068e2`. Omitted, unknown, mismatched, or
  incompatible evidence blocks both modes before an adapter is called.

The input `reducedMotion` option is intentionally presentation-only. Focus
semantics, session generations, and failure behavior are identical for normal
and reduced-motion rendering.

## Focus contract

A still-current Chat activation emits a deterministic focus intent targeting the
`composer` as soon as Chat is ready, even when a Terminal attach remains pending.
A still-current Terminal activation emits one targeting the `w-term-input` surface
**after** the session binding resolves. Repeated Terminal activations coalesce
one attach and transfer focus ownership to the latest Terminal request, so a
stale Terminal completion never emits focus. Each intent includes the opaque
session identity, session generation, and a monotonic sequence. For example,
a pending Terminal → Chat → Terminal sequence emits `composer` then exactly one
`w-term-input` intent; it never emits a Terminal intent for the stale first
request.

The renderer owns the actual DOM focus and any motion. It should treat the
intent as immediate and interruptible, and should provide a reduced-motion
alternative without changing the coordinator state machine.

## Adapter boundary

```ts
const coordinator = createSessionCoordinator({
  chat: jsonRpcChatTransport,
  terminal: wTermAdapter,
  deployment: {
    status: 'compatible',
    contract: PINNED_DASHBOARD_CONTRACT,
    hermesSourceSha: PINNED_HERMES_SOURCE_SHA
  },
  initialSessionId: selectedServerSessionId
});
```

`chat` is the existing `JsonRpcChatTransport` shape from issue #118. The
`terminal` adapter returns an opaque `{ sessionId, invalidate() }` binding. It
must not return PTY bytes or transcript data. The coordinator owns each returned
binding until one cleanup path calls `invalidate()` and then optional `release()`
exactly once. This ordering applies on session replacement, logout, disposal,
and a stale asynchronous completion; a late binding is never installed into the
new session.

This is offline prototype evidence. The injected adapters are the only places
where a later runtime may connect to a server or renderer; this change itself
makes no network request and does not claim live Hermes compatibility.

## Verification

From `apps/web`:

```sh
bun x vitest run src/lib/session/coordinator.test.ts
bun x --package @typescript/native tsc --noEmit --pretty false -p tsconfig.json
bun src/lib/session/coordinator.bench.ts
bun run build
```

The benchmark measures 30 repetitions of 1,000 in-memory mode transitions with
fake adapters. It prints raw samples and min/p50/p95/p99/max/mean milliseconds.
The observed run is recorded in
`coordinator-benchmark-evidence.json`. Network calls, renderer operations,
transcript mirror entries, and the threshold are recorded as zero or `null`; no
unreviewed performance budget is invented.
