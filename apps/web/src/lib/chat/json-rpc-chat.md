# Bounded JSON-RPC chat transport

`json-rpc-chat.ts` is the W-07 browser transport seam. It is a typed, deterministic
prototype boundary. It does not contact Hermes, mint a ticket, own a browser
credential, load a session, create a route, or persist a transcript.

## Connection contract

The caller injects two boundaries:

- `ticketProvider(signal)` returns one fresh, short-lived, URL-safe ticket;
- `createWebSocket(ticket, signal)` consumes that value for one upgrade and
  returns the minimal WebSocket adapter.

The transport keeps neither value after the call returns. Every explicit
`connect()` or `reconnect()` calls the ticket provider again. Reconnect is never
automatic. A stale generation's socket callbacks and frames are ignored before
frame parsing, so a rapid reconnect cannot mutate the replacement connection.

After the socket opens, the client sends one JSON-RPC 2.0 request:

```json
{
  "jsonrpc": "2.0",
  "id": "rpc-id",
  "method": "chat.handshake",
  "params": {
    "protocol": "hermternal.chat.v1",
    "events": ["stream", "tool", "approval", "clarification", "completion"]
  }
}
```

The server must acknowledge with the exact bounded result `{ "accepted": true }`.
A response with an error, an unexpected key, a mismatched ID, or an event before
this acknowledgement fails the connection.

## Prompt and control messages

`sendPrompt()` is only available after the handshake. It allocates a bounded
request ID and sends:

```json
{
  "jsonrpc": "2.0",
  "id": "rpc-id",
  "method": "chat.prompt",
  "params": { "prompt": "..." }
}
```

The server must acknowledge the prompt before emitting events for that request.
Approval and clarification answers use request IDs and carry only their own
bounded response fields:

- `chat.approval.respond` with `request_id`, `approval_id`, and `approved`;
- `chat.clarification.respond` with `request_id`, `clarification_id`, and
  `answer`.

Cancellation is a JSON-RPC notification containing only `request_id`. It does
not wait for an acknowledgement and never retries a prompt.

## Ordered events

The server emits JSON-RPC notifications. Every notification has a `request_id`
and a one-based `sequence` number. The next sequence must equal the previous
sequence plus one, across all event types:

- `chat.stream`: bounded `delta` text;
- `chat.tool`: bounded `tool_call_id`, `name`, and `phase` (`started`,
  `completed`, or `failed`);
- `chat.approval`: bounded `approval_id`, `title`, `state`, and nullable
  `approved` (`requested` requires `null`, `resolved` requires a boolean);
- `chat.clarification`: bounded `clarification_id` and `question`;
- `chat.complete`: `outcome` (`success`, `cancelled`, or `failed`).

Malformed, oversized, unknown, duplicate, or out-of-order frames fail closed
with a fixed semantic error. Raw frames and server error messages are never
copied into errors or hooks.

## Delivery state and interruption

A request moves through `pending`, `accepted`, `streaming`, and one terminal
state. If the socket closes before or after prompt acknowledgement, the request
becomes `uncertain-delivery`; its completion rejects with that semantic error.
The transport does not replay the prompt on `reconnect()`. The caller must
choose a separate, user-visible recovery action after re-reading server state.

`abort()` and an attached `AbortSignal` move a request to `cancelled`. The
transport sends a cancellation notification without forwarding the abort reason
and without retaining the prompt. `close()` and explicit reconnect also settle
active requests as uncertain rather than claiming success.

The transport stores only bounded IDs, sequence counters, statuses, and promise
settlers for active work. It does not retain prompt text, ticket values,
credentials, provider messages, event history, URLs, search terms, or deep-link
state. Consumer hooks receive transient typed events; hook failures are isolated
from transport state.

## Bounds and verification

The implementation bounds frame bytes, JSON depth, JSON nodes, object keys,
array lengths, string lengths, prompt length, IDs, sequence numbers, active
requests, and pending controls. Its parser rejects duplicate object keys and
trailing JSON data before schema validation.

`json-rpc-chat.test.ts` uses a deterministic fake WebSocket and covers:

- handshake and all ordered event classes;
- approval and clarification responses;
- malformed and oversized frames;
- out-of-order sequences;
- disconnect before and after acknowledgement;
- explicit fresh-ticket reconnect without prompt replay;
- stale generation suppression during rapid reconnect;
- cancellation, abort-reason isolation, and redaction.

This is prototype evidence only. It does not prove a live gateway, ticket
endpoint, cookie policy, Hermes compatibility, deployment behavior, or a
production WebSocket.
