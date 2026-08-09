# Hermes live chat proof

This directory contains one legacy redacted screenshot and its SHA-256 sidecar
for issue #327. It remains bounded protocol evidence, but it predates the
reproducible issue #353 capture contract and is not visual-fidelity proof. The
proof was reviewed at repository commit
`e26f71bf8a19c6b83605f3d2f2dcb4d54bf1e5c1` (`origin/dev` at capture time).
The reviewed official Hermes image digest was
`sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e`.

## Observed live-chat boundary

Four consecutive fresh-chat passes completed the same bounded flow:

1. mint a fresh, single-use WebSocket ticket for the connection;
2. connect with the ticket-only WebSocket query and wait for `gateway.ready`;
3. submit exactly one prompt, with no replay or retry submission;
4. receive the Luna completion and reconcile the final state through REST; and
5. reach a stable `empty` or `ready` workspace state with no duplicate assistant completion.

Ticket-only means no bearer, cookie, or reusable session credential was placed
in the WebSocket query. `gateway.ready` was required before chat requests. The
post-completion REST `/messages` read count increased, and no second prompt was submitted.

## Artifact boundary

`hermternal-chat-proof-e26f71b.png` is a synthetic-only, redacted UI screenshot
of the stable Chat state. It is not a packet capture, raw JSON-RPC transcript,
credential record, host proof, or production-readiness claim. The screenshot
and this README contain no secrets, hosts, users, session/request IDs, raw
payloads, cookies, bearer values, tickets, or provider credentials.

The checked-in `capture-manifest.json` records the current issue #353 state as
blocked with no images. Issue #338 confirmed that the authorized disposable
lane reaches authentication, `gateway.ready`, session creation/resume, and one
`prompt.submit`, but issue #327's missing authenticated inference capability
produces the source `error` event before `message.complete`. The explicit
capture code is therefore implemented and tested without inventing a successful
live completion; replacement images can be published only after that capability
exists and the scrub plus independent visual-review hooks approve both sizes.

The remaining workspace blockers are intentionally separate:

- [#311](https://github.com/kaygdotorg/hermternal/issues/311) — persisted
  restore/reload timeline ownership.
- [#313](https://github.com/kaygdotorg/hermternal/issues/313) — the missing
  logout action and its review-gated Paper/frontend work.

Those blockers are not folded into this chat completion proof.
