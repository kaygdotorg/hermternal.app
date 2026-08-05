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
| `exited` | The PTY process ended. | Show the exit state and offer a new terminal. |
| `failed` | Auth, host, backend, or spawn failure occurred. | Show the failure and allow only a safe, explicit retry. |

## Identity and attach rules

- `attach` is an opaque keep-alive identity for the PTY process. The client stores it only as a session handle and never derives its internal key.
- `resume` identifies the Hermes conversation that the TUI should restore. It is separate from `attach`.
- `fresh=1` disables the active-session fallback and asks for a fresh Hermes identity. It does not mean that a prior PTY process can be reattached under a different token.
- A disconnect or navigation enters `detached`. The PTY remains eligible for reattach for 30 minutes.
- An explicit Hermternal **Close** enters `closing`, detaches the socket, and stops client retries. The pinned source exposes no client-facing PTY kill operation; server cleanup occurs through process exit or the keep-alive retention policy.
- A second socket attaching to the same PTY supersedes the first socket. The old socket receives close code `4409`.

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
- The client may show a non-blocking "reconnected" or "output may be truncated" notice. It must not save retained output as a durable transcript.

## Close and failure rules

| Close or failure | State | Client action |
| --- | --- | --- |
| `4401` | `failed` or `ticket_pending` | In gated mode, refresh auth if needed and mint a new ticket. In non-gated local token mode, report token rejection. Never reuse a consumed ticket. |
| `4403` | `failed` | Report host or origin rejection. Do not loop. |
| `4404` | `failed` | Report that embedded chat is disabled. |
| `4408` | `failed` | Report that the peer is not allowed. |
| `4409` | `detached` | Stop reading the superseded socket and keep the current attachment. |
| `4410` | `exited` | Stop reconnecting to the dead PTY. |
| `1011` | `failed` | Report backend failure and offer an explicit retry. |
| Hermternal **Close** | `closed` | Detach the socket and do not reconnect automatically. Do not claim that the PTY process was killed. |
| Network loss | `detached` | Reattach with the same token while the 30-minute window remains. |

Unknown close codes are compatibility failures. Do not treat them as permission to issue shell commands or to create a fresh session automatically.

## Invariants

- Terminal mode is available only on web in v0.0.1 and only when the verified Hermes host class is POSIX or WSL.
- The client never uses direct SSH, a separate terminal backend, or a Dashboard console route.
- A WebSocket ticket is short-lived and single-use. Mint one per gated upgrade.
- Resize controls never appear as terminal input.
- A detached PTY is not a new conversation. Reattach preserves the server-owned identity.
- No v0.0.1 client action requests PTY process termination at the pinned revision. View disposal and **Close** detach.
- PTY bytes, retained output, prompts, and tool output are not stored as a local transcript mirror.
- Input, resize, attach, reattach, and close transitions remain interruptible. Retained output must not block the close control.
