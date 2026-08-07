# Live workspace boundary

`LiveWorkspaceSession` coordinates the reviewed browser transports for one authenticated Hermes session.

## Ownership

- REST remains the source of truth for the session list and completed message history.
- The controller replaces presentation arrays after each server read. It does not keep a secondary transcript store.
- One JSON-RPC transport belongs to one selected session. A session change closes that transport before creating another one.
- Generation numbers and abort signals prevent stale session reads from publishing after a newer selection.
- Approval and clarification replies capture their generation, transport identity, and pending-map owner. A late completion or failure cannot mutate a replacement chat, disposed workspace, or newer interactive item.
- `invalidate()` detaches the chat identity before close, aborts reads, and removes session and timeline references before subscribers receive the signed-out view. `dispose()` marks the workspace closed and clears subscribers before close callbacks can re-enter.

## Prompt delivery

A prompt is submitted only after REST restoration and the explicit JSON-RPC connection and `session.resume` sequence complete. Streaming text is transient presentation data. A successful completion triggers a new REST message read so server-owned history replaces it. The prompt allocates its refresh epoch only after the synchronous transport call returns; completion and failure continuations consume that exact owner instead of minting a new one from a promise reaction. That read receives the prompt operation's abort signal, so invalidation, session replacement, logout, and disposal cancel it and stale authenticated data cannot repopulate the timeline.

Hermternal never reconnects or replays a prompt automatically. An uncertain delivery shows a fixed warning. The user must reconnect and inspect Hermes history before deciding whether to send again.

## Bounded presentation

The controller reads only documented text keys from known JSON-RPC events. Unknown payload values stay opaque. Compact tool rows show a name and fixed status copy, never tool arguments or raw output. REST mapping excludes system context and session preview transcript text.

`WorkspacePreview` defaults to deterministic fixture copy. Live callers must pass `dataMode="live"`, explicit timeline data, and disable the fixture-only artifact inspector. The live empty and recovery copy does not claim that controls are mocked or that an unretained draft is safe.

Authentication, provider discovery, REST, WebSocket tickets, and JSON-RPC remain separate reviewed boundaries. This module composes them; it does not weaken their same-origin, cancellation, size, or diagnostic rules. A genuine REST `LiveRestError('unauthenticated', 401)`, ticket HTTP `401`, `JsonRpcChatError('authentication-required')`, or active close `4401` remains `permanent-error` and may expire the authenticated root; REST `403`, ticket `403`, and close `4403` remain outside that sign-in boundary. Generic connection failures remain `retryable-error`. The workspace retains the terminal reason and close classification separately from that broad state: an active prompt after `4401` shows sign-in guidance, while `4403` shows incompatible-origin guidance. The rendered authentication-required actions call the root-provided auth recovery bridge, which invokes `BrowserAuthSession.expire()` and invalidates local workspace state; incompatible-origin actions stay on the fail-closed boundary. Reconnect recovery exposes working `Check connection` and `Cancel` actions: the former starts the guarded retry owner and the latter aborts it without replaying a prompt. Uncertain-delivery callbacks and prompt-failure cleanup cannot downgrade either permanent result.
