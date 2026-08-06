# Chat state model

**Status:** normative planning contract
**Applies to:** web, iOS, iPadOS, and macOS
**Dashboard contract:** `dashboard-v0.0.1`

## Purpose

This model defines prompt, stream, tool, approval, clarification, interruption, model selection, and image attachment behavior.

Hermes owns the transcript. Hermternal renders a server projection. A local memory cache may support the current view, but it is not a transcript mirror and must not become one.

## Observable states

| State | Observable meaning | Allowed actions |
| --- | --- | --- |
| `empty` | No server session is selected or the selected session has no messages. | Create a session or write a draft. |
| `restoring` | The client is loading server-owned history and status. | Wait or cancel. Do not retry a prompt. |
| `ready` | The session can accept a prompt. | Edit draft, attach images, send, interrupt nothing, or change the session model. |
| `submitting` | A prompt send is in progress. | Disable duplicate send. Allow cancel only when the source method supports it. |
| `streaming` | Server output, reasoning, or tool events are arriving. | Stop the turn, answer an active approval or clarification, or keep reading. |
| `awaiting_approval` | The server emitted `approval.request`. | Approve or deny the one pending request. Do not auto-approve. |
| `awaiting_clarification` | The server emitted `clarify.request`. | Submit the answer or cancel the clarification. |
| `interrupting` | `session.interrupt` was sent and the final state is not known. | Wait for a status/result or reconnect and restore. |
| `delivery_uncertain` | The prompt may have been accepted, but the client lacks a result. | Restore first. Do not resend automatically. |
| `completed` | The turn ended with a server completion or an explicit interruption. | Read, copy, start a new draft, or continue. |
| `failed` | The server returned a known error or the turn failed. | Preserve the draft when possible and allow an explicit retry. |

## Prompt transitions

1. `empty` or `ready` enters `submitting` when the user sends a non-empty prompt.
2. A confirmed successful result or the first correlated server event enters `streaming` or `completed` according to the observed event.
3. `message.delta`, `reasoning.delta`, and `thinking.delta` update the current turn projection. They do not create a second local transcript.
4. `tool.start` and `tool.complete` update tool status. The client may tolerate an additive progress event, but `tool.progress` is not required by the pinned source. Tool output is not an approval and does not grant command authority to the client.
5. `message.complete` enters `completed` after the server has finalized the turn.
6. `session.interrupt` enters `interrupting`. Enter `completed` only after a confirmed stop or restored server status. Do not claim success from a lost request.
7. A known request error enters `failed`. Keep the unsent draft unless the user removes it.
8. A transport loss after send and before a result enters `delivery_uncertain`, not `failed`.

## Uncertain prompt delivery

The client must not blindly retry a prompt.

- A timeout, WebSocket close, app suspension, or process crash after send is an unknown outcome.
- Reconnect and restore the server session before any resend decision. Observe
  `gateway.ready` and matching compatibility evidence before `session.history`,
  `session.status`, or another prompt operation.
- Inspect fresh server-owned history and status for every uncertainty cycle. A
  transient history or status read failure invalidates that read's current
  evidence until a successful retry of the same idempotent read completes;
  stale `absent`/`idle` evidence cannot authorize a later resend.
- If the prompt is present, render the server result and do not duplicate it.
- If the prompt is absent and the server confirms that no turn is running, ask the user whether to resend.
- Keep the original draft and a user-visible uncertainty notice until the decision is complete.
- Do not create a new session as an automatic workaround.
- A send requires a selected session, a non-empty draft, ready transport,
  gateway readiness, and compatible evidence. A `ready` label alone is not a
  transport or compatibility proof.
- Sign-out clears selected session, active request/turn references, restore
  evidence, and armed retry decisions. It latches offline and rejects stale
  transport, event, or user-decision input until a new authenticated session
  starts.

## C-06 uncertain-delivery contract

`delivery_uncertain` is a recoverable protocol state, not a server rejection. It applies when a prompt or interrupt may have reached Hermes but the client lost the result. The client keeps the draft and the selected session while it obtains authoritative evidence.

### Transition matrix

| Evidence or action | Required transition | Retry or rendering rule |
| --- | --- | --- |
| Explicit send from a selected `ready` session (or after the user creates one from `empty`) | `submitting` | Count one outward `prompt.submit`; block another local send while the turn is active. |
| Confirmed prompt acceptance or correlated output | `streaming`, then `completed` when the server completes | Never submit the same prompt again. Render the server-owned turn, not a local transcript copy. |
| Timeout, WebSocket close, app suspension, or process loss after send | `delivery_uncertain` | Do not classify the prompt as rejected and do not retry it automatically. |
| Restore begins | `restoring` | Reconnect first and wait for `gateway.ready` before application RPC. Keep the uncertainty notice and draft visible. |
| History shows the prompt and status is `running`/`streaming` | `streaming` | The server turn wins; resume rendering and do not resend. |
| History shows the prompt and status is `completed` | `completed` | Render completion and do not resend. |
| History shows the prompt absent and status is `idle` | `ready` | Preserve the draft and require an explicit user choice before one resend. |
| History or status remains unknown/pending | `delivery_uncertain` or `restoring` | Wait for more evidence. Unknown is never converted to rejection, success, or permission to resend. |
| Confirmed `prompt.submit` rejection | `failed` | Preserve the draft and permit only a later explicit retry. |

### Retry and idempotency rules

- Only idempotent reads may retry automatically: `session.resume`, `session.history`, `session.status`, and `model.options`.
- `prompt.submit`, `session.create`, and `session.interrupt` are never automatically retried. A restore barrier must complete before any resend decision.
- A resend is valid only when restored history says the prompt is absent, restored status says the turn is idle, and the user confirms. Use a new local request marker and perform one explicit resend. If that resend becomes uncertain, return to restore; never issue an automatic third submission.
- A duplicate send while `submitting` or `streaming` is blocked locally and does not reach Hermes. A known rejection does not authorize an automatic retry.
- `session.interrupt` enters `interrupting`. Mark it `completed` only after a confirmed interrupt result or restored server state that proves the turn stopped. If restore shows the turn still running, return to `streaming`; do not fabricate a stop result.
- Sign-out clears the selected session, suppresses reconnect, and moves the view to `empty`/`offline` while preserving the draft. An explicit later sign-in may start a new restore.
- An incompatible restore result or unknown interactive event fails closed. It must not become an approval, clarification, retry permission, or new session workaround.

The deterministic C-06 fixture in `contracts/fixtures/uncertain-delivery/` freezes this matrix with synthetic markers only. It also covers the pending-evidence and keep-draft paths. The fixture is protocol evidence, not a live Hermes integration test.

## Approval and clarification boundary

Only these interactive flows are supported:

- `approval.request` followed by `approval.respond`.
- `clarify.request` followed by `clarify.respond`.

The client must not present `sudo.request`, `secret.request`, or another sensitive interactive event as an approval or clarification. It must not collect, persist, or echo secrets. An unsupported interactive event is a contract error and stops the affected turn.

An approval or clarification has one pending owner. A second response after completion, denial, cancellation, or expiry is rejected locally. The client must show the pending question or approval, the available user action, and the final result.

## Images-only attachment boundary

- `POST /api/chat/image-upload` is the only selected upload route.
- A prompt may contain text and validated image references from that route.
- The client does not support arbitrary files, shell paths, audio, video, generic data URLs, or direct `~/.hermes` reads.
- Failed image validation leaves the text draft intact and enters `failed` for the attachment only.
- Image bytes are not written into the transcript model. The server remains the source of any stored attachment metadata.

## Active model selection

`model.options` reads available choices. `config.set` with the source-defined `model` key changes the active session model.

- An idle session applies a valid choice immediately.
- A streaming session keeps the current model for the current turn. A normal deferred choice may apply at the next turn start.
- At the pinned revision, a deferred choice is popped before expensive-model confirmation is checked. If confirmation is required, the server drops that deferred choice. The client must submit a confirmed choice after the current turn or tell the user to confirm and select again. It must not claim that the choice remains pending.
- A failed switch leaves the old model active. It does not rewrite global configuration.
- A session-scoped model choice survives restore and rebuild. A global model change is outside v0.0.1.

The UI may show the pending model during a stream, but it must not claim that the live turn already uses it.

## Transcript and restore invariants

- The server session is the only durable transcript source.
- On restore, replace the render projection with server history. Do not merge an unverified local copy into the server history.
- Drafts, attachment progress, selected session identity, and lightweight UI preferences may persist locally. Message bodies and tool output may not be persisted as a transcript mirror.
- Every turn has one visible lifecycle. A reconnect must not create duplicate user or assistant messages.
- Unknown event names do not create an interactive control.
- Recognized server events must carry correlated request, turn, and session
  identity and are accepted only for an active turn on a ready compatible
  transport. Events received in `empty`, `failed`, `completed`, or another
  inactive state fail closed.
- The send, stop, approval, clarification, attachment, and model controls must remain usable while the connection reports progress. Reduced-motion mode changes presentation only, not state rules.
