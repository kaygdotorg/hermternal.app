# Live workspace boundary

`LiveWorkspaceSession` coordinates the reviewed browser transports for one authenticated Hermes session.

## Ownership

- REST remains the source of truth for the session list and completed message history.
- The controller replaces presentation arrays after each server read. It does not keep a secondary transcript store.
- One JSON-RPC transport belongs to one selected session. A session change closes that transport before creating another one.
- Generation numbers and abort signals prevent stale session reads from publishing after a newer selection.
- `invalidate()` aborts reads, closes chat, and removes session and timeline references before subscribers receive the signed-out view.

## Prompt delivery

A prompt is submitted only after REST restoration and the explicit JSON-RPC connection and `session.resume` sequence complete. Streaming text is transient presentation data. A successful completion triggers a new REST message read so server-owned history replaces it.

Hermternal never reconnects or replays a prompt automatically. An uncertain delivery shows a fixed warning. The user must reconnect and inspect Hermes history before deciding whether to send again.

## Bounded presentation

The controller reads only documented text keys from known JSON-RPC events. Unknown payload values stay opaque. Compact tool rows show a name and fixed status copy, never tool arguments or raw output. REST mapping excludes system context and session preview transcript text.

`WorkspacePreview` defaults to deterministic fixture copy. Live callers must pass `dataMode="live"`, explicit timeline data, and disable the fixture-only artifact inspector. The live empty and recovery copy does not claim that controls are mocked or that an unretained draft is safe.

Authentication, provider discovery, REST, WebSocket tickets, and JSON-RPC remain separate reviewed boundaries. This module composes them; it does not weaken their same-origin, cancellation, size, or diagnostic rules.
