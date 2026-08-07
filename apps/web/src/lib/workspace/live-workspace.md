# Live workspace boundary

`LiveWorkspaceSession` coordinates the reviewed browser transports for one authenticated Hermes session.

## Ownership

- REST remains the source of truth for the session list and completed message history.
- The controller replaces presentation arrays after each server read. It does not keep a secondary transcript store.
- One JSON-RPC transport belongs to one selected session. A session change closes that transport before creating another one.
- Generation numbers and abort signals prevent stale session reads from publishing after a newer selection.
- A new workspace generation revokes the coordinator's PTY/session lease synchronously before the replacement snapshot is published. Coordinator callbacks are accepted only when the workspace generation, coordinator session generation, selected identity, and visible snapshot agree.
- Chat fallback state is tagged to its workspace generation; an old transport callback cannot poison a replacement Terminal activation while Chat is being rebuilt.
- Approval and clarification replies capture their generation, transport identity, and pending-map owner. A late completion or failure cannot mutate a replacement chat, disposed workspace, or newer interactive item.
- `invalidate()` detaches the chat identity before close, aborts reads, and removes session and timeline references before subscribers receive the signed-out view. `dispose()` marks the workspace closed and clears subscribers before close callbacks can re-enter.

## Chat and Terminal mode continuity

The normal route keeps one `LiveWorkspaceSession` mounted while the user switches
between Chat and Terminal. The session's coordinator receives a façade over the
existing Chat transport and a single current-session PTY bridge. Mode actions
reuse the selected opaque session; they do not call `createSession()`, create a
second Chat transport, or dispose Chat. A session replacement clears the old
terminal presentation state after synchronous PTY invalidation, so a late old
terminal publication cannot appear on the replacement session.

`TerminalSurface` remains mounted while Chat is selected and hides only its
presentation layer. It owns the host, lazy W-Term/Ghostty import, renderer mount
and disposal, resize forwarding, focus intents, lifecycle notices, native
selection/copy, and accessible recovery actions. The bridge forwards raw
`Uint8Array` output directly to that renderer and stores only redacted
lifecycle state. The renderer-ready gate delays the first PTY connection until
the lazy sink is mounted; reconnect keeps that mounted sink in place so a PTY
generation change cannot open a zero-byte-loss window. An explicit Terminal
close is a user-selected detach; an unexpected PTY exit is the failure path,
and both revoke the coordinator lease before another Terminal action.

The pinned server source does not expose a client-visible attach-token issuance
route. The normal browser composition therefore uses a legacy PTY and labels
reattach as unavailable instead of presenting a reconnect action that would
silently create a second process. A reviewed attach provider can opt into the
transport's exact session/attach/process-identity reconnect contract later.

`4401` remains an authentication-required recovery path for Chat and PTY. The
root composition expires the authenticated BrowserAuthSession from a PTY `4401`
even while Chat hides TerminalSurface. `4403` remains an incompatible-origin
failure and never invokes sign-in recovery. These are prototype boundaries
backed by synthetic tests; same-session proof against hermternal-dev is still
required after review and merge.

## Prompt delivery

A prompt is submitted only after REST restoration and the explicit JSON-RPC connection and `session.resume` sequence complete. Streaming text is transient presentation data. Official Hermes may omit `request_id` from delta and completion events; the JSON-RPC transport exposes its fail-closed sole-operation correlation as the public request ID before this controller applies prompt ownership. A successful completion triggers a new REST message read so server-owned history replaces it. The prompt allocates its refresh epoch only after the synchronous transport call returns; completion and failure continuations consume that exact owner instead of minting a new one from a promise reaction. That read receives the prompt operation's abort signal, so invalidation, session replacement, logout, and disposal cancel it and stale authenticated data cannot repopulate the timeline.

The live Hermes gateway does not provide one total order for REST, JSON-RPC replies, events, and socket lifecycle callbacks. The earlier synthetic fixture assumed a request acknowledgement preceded prompt events; official Hermes can start prompt work and emit completion-related events before returning that acknowledgement. A generic failed or uncertain callback can also arrive after a successful completion and its REST read. During restore, the bounded REST projection is provisional and may be visible before chat factory, ticket, connection, or `session.resume` succeeds. The workspace commits a general history barrier after every successful REST replacement. For an exact prompt that observed a successful `message.complete`, it defers a matching generic `failed` callback while that prompt's REST reconciliation is pending and suppresses the callback after the reconciliation commits. A refresh failure, cancellation, or ownership loss revokes the pending completion and leaves the correct recovery or replacement state. Initial restore and reconnect history do not establish completion ownership, so their generic failures remain `retryable-error`; a real `delivery_uncertain` callback still publishes `retryable-error`, and classified authentication/origin closes remain permanent. If history loading fails before `openSession()` can publish the selected identity, the workspace keeps only that opaque persisted session ID as private retry ownership; Retry reopens that same server session and never falls through to `createSession()`. Once bounded history is mapped and published, the normal active-session retry path takes over. If the factory fails before a chat exists, Retry starts a fresh active-session lookup, factory, ticket, connection, and resume operation with generation ownership; a new-session factory failure without a stored ID retries the guarded create path instead. Stale or reentrant retries cannot adopt a replacement. Authentication-required and incompatible-origin classifications always bypass this generic barrier.

Hermternal never reconnects or replays a prompt automatically. An uncertain delivery shows a fixed warning. The user must reconnect and inspect Hermes history before deciding whether to send again.

## Bounded presentation

The controller reads only documented text keys from known JSON-RPC events. Unknown payload values stay opaque. Compact tool rows show a name and fixed status copy, never tool arguments or raw output. REST mapping excludes system context and session preview transcript text.

`WorkspacePreview` defaults to deterministic fixture copy. Live callers must pass `dataMode="live"`, explicit timeline data, and disable the fixture-only artifact inspector. The live empty and recovery copy does not claim that controls are mocked or that an unretained draft is safe.

Authentication, provider discovery, REST, WebSocket tickets, and JSON-RPC remain separate reviewed boundaries. This module composes them; it does not weaken their same-origin, cancellation, size, or diagnostic rules. A genuine REST `LiveRestError('unauthenticated', 401)`, ticket HTTP `401`, `JsonRpcChatError('authentication-required')`, or active close `4401` remains `permanent-error` and may expire the authenticated root; REST `403`, ticket `403`, and close `4403` remain outside that sign-in boundary. Generic connection failures remain `retryable-error`. The workspace retains the terminal reason and close classification separately from that broad state: an active prompt after `4401` shows sign-in guidance, while `4403` shows incompatible-origin guidance. The rendered authentication-required actions call the root-provided auth recovery bridge, which invokes `BrowserAuthSession.expire()` and invalidates local workspace state; incompatible-origin actions stay on the fail-closed boundary. Reconnect recovery exposes working `Check connection` and `Cancel` actions: the former starts the guarded retry owner and the latter aborts it without replaying a prompt. Uncertain-delivery callbacks and prompt-failure cleanup cannot downgrade either permanent result.

The pre-identity retry regression deliberately fails the first history read, defers the second, and drives the real browser transport through ticket acquisition, `gateway.ready`, and `session.resume`. It keeps the session ID opaque in the ownership trace while asserting that detail lookup, both history reads, selected-session transport setup, and resume all address the same server session; the socket sends no `session.create`. The test-local trace records only generation, controller identity, abort, disposal, and gate results. This boundary is why the two fail-closed ownership gates remain unchanged until a live reproduction supplies a false predicate or an abort transition; production code does not log IDs, tickets, transcript data, or response bodies.
