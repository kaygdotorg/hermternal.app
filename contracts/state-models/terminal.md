# Terminal state model

**Status:** normative planning contract
**Applies to:** web only in v0.0.1
**Dashboard contract:** `dashboard-v0.0.1`

## Purpose

Terminal mode renders the full Hermes TUI over `WS /api/pty` only when the attested Hermes host is POSIX or WSL. An unsupported or unverified host class blocks Terminal. Terminal is not a shell, SSH client, terminal backend selector, or Apple feature.

The client treats PTY data as bytes. It does not parse command meaning or write terminal transcripts to local storage.

## Observable states

| State | Observable meaning | Allowed actions |
| --- | --- | --- |
| `closed` | No PTY exists for this view. | Open a new terminal or leave the workspace. |
| `ticket_pending` | A gated WebSocket ticket is being minted. | Wait or cancel. Do not reuse an old ticket. |
| `connecting` | The WebSocket upgrade is in progress. | Wait or cancel. |
| `starting` | The Dashboard is spawning or attaching the PTY. | Show startup state and accept no user input until attached. |
| `attached` | The socket receives PTY bytes. | Render output, send input, resize, or detach. |
| `reattaching` | A new socket is attaching and may receive retained and live bytes. | Render bytes as received. Do not claim a replay boundary that the server does not provide. |
| `detached` | The socket is gone but the keep-alive PTY may still run. | Reattach with the same opaque token or stop client retries. |
| `closing` | The user closed the Terminal view. | Detach, stop retries, and explain that server cleanup is deferred. |
| `exited` | The PTY process ended, including after a legacy non-attach disconnect. | Show the exit state and offer a new terminal. |
| `failed` | Auth, host, backend, or spawn failure occurred. | Show the failure and allow only a safe, explicit retry. |

## Identity and attach rules

- The browser `/api/pty` upgrade query is exactly `ticket` plus `resume`, with an optional non-empty `attach` value. Key order is not significant; duplicate keys, empty values, unknown parameters, and `fresh` are invalid and must fail closed before upgrade.
- `ticket` and `attach` are safe opaque values bounded to 512 characters; `resume` is a safe opaque value bounded to 128 characters. The browser client must not send a `fresh` query parameter.
- `attach` is an opaque keep-alive identity for the PTY process. The client stores it only as a session handle and never derives its internal key.
- `resume` identifies the Hermes conversation that the TUI should restore. It is separate from `attach`.
- In attach mode, a disconnect or navigation enters `detached`; the PTY remains eligible for reattach for 30 minutes. A legacy non-attach disconnect instead closes the bridge and enters `exited`.
- An explicit Hermternal **Close** is mode-specific: in legacy mode it follows the disconnect path, closes the bridge, terminates the child, and enters `exited`; in attach mode it detaches the socket, retains the PTY for the keep-alive window, and stops client retries. The pinned source exposes no client-facing PTY kill operation for attach mode.
- A second socket attaching to the same PTY supersedes the first socket. The source closes the old socket with `4409` before assigning the replacement WebSocket; the replacement then becomes active, and stale cleanup cannot detach it.

## Legacy versus attach mode

The pinned source selects the PTY lifetime from the **presence** of the `attach` query value. This is an opt-in split, not a reconnect promise for every Terminal socket.

| `attach` query | Pinned source path | Disconnect result | Reattach rule |
| --- | --- | --- | --- |
| Missing or empty | Legacy `_legacy_pump` path | The socket handler closes the PTY bridge in `finally`; the child is terminated and the client enters `exited`. | Prohibited. Open a new terminal instead. |
| Non-empty, previously accepted opaque handle | `PtySessionRegistry` keep-alive path | The handler detaches only the socket. The drain task keeps reading and buffering while the PTY remains eligible for reattach. | Reuse the same handle during the retention window. Never replace it with a fresh handle or silently fall back to legacy mode. |

The source does not define a client-visible attach-token grammar or an issuance route. Hermternal therefore treats only an exact opaque handle obtained from the reviewed attach flow as usable. A malformed or expired handle fails closed during preflight, before opening `/api/pty` or performing socket accept/upgrade, route dispatch, registry lookup/attach/spawn, session attach, or PTY spawn: do not create a replacement PTY, fall back to the legacy path, or retry the rejected value. This guard is required because the pinned registry accepts any non-empty key and can create a new PTY after an old detached entry has been reaped; that source behavior must not turn an invalid handle into an accidental fresh session.

A superseded socket is a separate failure from a malformed or expired handle. It is already open when a replacement attach arrives. The pinned `PtySession.attach` closes the old socket with `4409` before assigning the replacement WebSocket. The replacement is then marked active, and the old handler's later cleanup fails to retry or call detach against the replacement. The pinned `detach` identity check preserves the replacement attachment.

The source audit and deterministic regression fixtures for this distinction live in [`fixtures/source-audit/pty-attach`](../fixtures/source-audit/pty-attach/README.md).

## Byte and resize rules

- PTY output is sent as binary WebSocket frames. The client forwards bytes to the terminal renderer without UTF-8 decoding.
- Text input is encoded as UTF-8 bytes. Binary input is sent unchanged.
- The complete resize control sequence is `ESC [RESIZE:<cols>;<rows>]`. Send it as bytes in one control message. The Dashboard consumes it and does not write it to the PTY.
- Clamp dimensions to at least 1 and at most 2000 columns and 1000 rows. A bad dimension must not crash the resize path.
- Do not send JSON, newline-delimited terminal commands, or a second resize framing format on this route.

## Reattach and retained-output rules

- The server keeps the newest 1 MiB of PTY output in a bounded byte buffer.
- On reattach, the pinned source may deliver retained and live bytes without a client-visible boundary. It does not guarantee that all retained bytes arrive before live bytes.
- Render byte frames in receive order. Do not insert a separator or decode and re-encode them.
- Output older than the retained 1 MiB may be missing. The client must not claim that reattached output is a complete transcript or a strictly ordered replay snapshot.
- User input bytes and resize controls are not retained as replayable actions. Never replay input, resize controls, prompt submissions, or tool actions after detach or reattach; a retry requires a new, explicit user action. Prompt and tool output bytes are PTY output and may appear in retained output without implying that the underlying action was replayed.
- The client may show a non-blocking "reconnected" or "output may be truncated" notice. It must not save retained output as a durable transcript.
- `outputMayBeTruncated` is true only for the current attachment established by a successful explicit reattach. Detach, Close, cancellation, failure, replacement, and stale-generation cleanup reset it; cancellation after reattach `onopen` restores the exact identity's detached-retention evidence before cleanup.

## Close and failure rules

| Close or failure | State | Client action |
| --- | --- | --- |
| `4401` | `failed` or `ticket_pending` | In gated mode, refresh auth if needed and mint a new ticket. In non-gated local token mode, report token rejection. Never reuse a consumed ticket. |
| `4403` | `failed` | Report host or origin rejection. Do not loop. |
| `4404` | `failed` | Report that embedded chat is disabled. |
| `4408` | `failed` | Report that the peer is not allowed. |
| `4409` | `detached` | Stop reading the superseded socket; the source sends this before assigning the replacement, which then becomes the current attachment. |
| `4410` | `exited` | Stop reconnecting to the dead PTY. |
| `1011` | `failed` | Report backend failure and offer an explicit retry. |
| Legacy socket disconnect without `attach` | `exited` | The source closes the bridge. Do not offer reattach for that PTY. |
| Malformed or expired attach handle | `failed` | Reject during preflight before opening `/api/pty`; do not spawn a replacement PTY, fall back to legacy mode, or replay input. |
| Already-open superseded socket | `detached` | The stale socket receives `4409` before the replacement is assigned; then the replacement attaches, and stale cleanup cannot detach or retry it. |
| Legacy Hermternal **Close** | `exited` | Follow the legacy disconnect path, close the bridge, terminate the PTY, and offer a new terminal; reattach is prohibited. |
| Attach Hermternal **Close** | `detached` | Detach the socket, retain the PTY for the keep-alive window, and stop client retries; do not claim that attach-mode Close killed the process. |
| Network loss | `detached` | Reattach with the same token while the 30-minute window remains. |

Unknown close codes are compatibility failures. Do not treat them as permission to issue shell commands or to create a fresh session automatically.

## Invariants

- Terminal mode is available only on web in v0.0.1 and only when the verified Hermes host class is POSIX or WSL.
- The client never uses direct SSH, a separate terminal backend, or a Dashboard console route.
- A WebSocket ticket is short-lived and single-use. Mint one per gated upgrade.
- Resize controls never appear as terminal input.
- A detached PTY is not a new conversation. Reattach preserves the server-owned identity.
- Missing or empty `attach` is legacy mode and terminates the PTY on socket disconnect or explicit Close; it never implies keep-alive.
- A malformed or expired attach handle fails closed before opening a replacement PTY, and a superseded socket cannot detach or retry the active replacement.
- Attach-mode view disposal and **Close** do not request PTY process termination; legacy non-attach disconnect or **Close** follows the bridge termination path.
- PTY bytes, including retained prompt and tool output, are not stored as a local transcript mirror; retained bytes remain ephemeral output, not replayable actions or a durable transcript.
- Input, resize, attach, reattach, and close transitions remain interruptible. Retained output must not block the close control.
