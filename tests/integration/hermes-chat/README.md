# Historical Hermes chat fixture

This directory contains the reviewed issue-327 screenshot fixture and its SHA-256
sidecar. The fixture was reviewed at repository commit
`e26f71bf8a19c6b83605f3d2f2dcb4d54bf1e5c1` (`origin/dev` at capture time). The
reviewed official Hermes image digest was
`sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e`.

## Historical boundary

The four-pass flow described by the original issue material is retained as
historical context only. It describes the intended bounded sequence:

1. mint a fresh, single-use WebSocket ticket;
2. connect with the ticket-only query and wait for `gateway.ready`;
3. submit exactly one prompt without replay or retry submission;
4. receive completion and reconcile final state through REST; and
5. reach a stable `empty` or `ready` workspace state without duplicate completion.

Those claims are not a live Hermes result from the issue-353 correction. No live
Hermes run, credential handoff, browser capture, or retainable screenshot was
performed during this work. The current live lane is synthetic or explicitly
prerequisite-gated and records only bounded typed proof projections.

## Artifact boundary

`hermternal-chat-proof-e26f71b.png` is a synthetic-only, redacted UI fixture of
the stable Chat state. It is not a packet capture, raw JSON-RPC transcript,
credential record, host proof, or production-readiness claim. The screenshot and
this README contain no secrets, hosts, users, session/request IDs, raw payloads,
cookies, bearer values, tickets, or provider credentials.

The remaining workspace blockers are intentionally separate:

- [#311](https://github.com/kaygdotorg/hermternal/issues/311) — persisted
  restore/reload timeline ownership.
- [#313](https://github.com/kaygdotorg/hermternal/issues/313) — the missing
  logout action and its review-gated Paper/frontend work.

Those blockers are not folded into this historical fixture or the issue-353
privacy correction.
