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
  A late Terminal completion may leave its binding attached after switching to
  Chat, but it never restores W-Term focus while Chat is the active mode.
- `setSession()` increments the session generation, invalidates and releases the
  current Terminal binding lease before awaiting Chat restoration, and ignores
  late completions from the previous generation. Cleanup is rechecked before the
  replacement identity is installed because adapter invalidation or release may
  synchronously log out or dispose the coordinator. Each attach gets a fresh
  lease, so an adapter may reuse one raw binding object after an earlier lease
  settles without suppressing later cleanup. If overlapping attaches return the
  same raw object, a stale completion never cleans the raw binding owned by the
  active lease; a distinct stale binding still receives exactly-once cleanup.
- `logout()` and `dispose()` claim lifecycle state before adapter cleanup. They
  close Chat and clean the active Terminal lease at most once, increment the
  session generation once, and treat `disposed` as higher precedence than
  `logged-out` when cleanup reenters the coordinator.
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
**after** the session binding resolves. For deferred Terminal focus, currentness
includes the active mode, the opaque session identity and generation, and the
mode's latest activation sequence. Repeated Terminal activations coalesce one
attach and transfer focus ownership to the latest Terminal request, so a stale
Terminal completion never emits focus.
Each intent includes the opaque session identity, session generation, and a
monotonic sequence. For example, a pending Terminal → Chat sequence emits only
`composer`; the late Terminal binding may remain attached, but it never emits a
late `w-term-input` intent. A pending Terminal → Chat → Terminal sequence emits
`composer` then exactly one `w-term-input` intent for the latest Terminal request.

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
binding through an attachment lease. One lease calls `invalidate()` and then
optional `release()` exactly once; a later lease may wrap the same raw object
after the earlier lease settles. During overlapping attaches, a stale result
that matches the raw binding currently owned by the active lease is not wrapped
in a second lease or cleaned; a distinct stale result receives its own lease and
is cleaned exactly once. This ordering applies on session replacement, logout,
disposal, and a stale asynchronous completion; a late binding is never installed
into the new session.

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
The v2 evidence records the exact `HEAD` used for the run, SHA-256 digests of the
coordinator source and benchmark harness, a stable workload identity, the
command, working directory, and environment. Regenerate it only after the
coordinator and harness are stable, then keep those fields consistent with the
checked-in `coordinator-benchmark-evidence.json`. Network calls, renderer
operations, transcript mirror entries, and the threshold are recorded as zero or
`null`; no unreviewed performance budget is invented.
