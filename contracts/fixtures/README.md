# Protocol fixtures

This directory will contain synthetic, redacted request, response, WebSocket, Terminal, and recovery fixtures for both clients.

## Required coverage

Fixtures must represent:

- browser HttpOnly-cookie auth;
- native username/password provider auth, isolated `URLSession` cookies, and WebSocket tickets;
- one profile and provider-neutral discovery;
- session restore, long sessions, streaming, interruption, reconnect, loading, empty, success, and failure;
- approvals and clarification as separate pending actions;
- idle model switching, normal deferred switching, and deferred expensive-choice confirmation loss;
- images-only attachments;
- private deep links under `/v1/c/...`;
- the full web-only `/api/pty` Terminal on a POSIX or WSL host, plus an unsupported-host negative case;
- missing and mismatched deployment attestation;
- failed behavioral probes;
- missing, malformed, expired, and reused WebSocket tickets; and
- malformed JSON with a non-sensitive marker and verified upstream log controls.

Fixtures must identify the pinned Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`, contract version, expected state transitions, and whether the fixture is web-only or shared. A native OAuth/OIDC provider that requires an unsupported callback transport is a negative fixture, not a fallback path.

Use synthetic data only. Do not commit credentials, cookies, WebSocket tickets, ticket fragments, live transcripts, hostnames, tokens, secrets, provider data, or user data. Invalid-ticket fixtures use non-secret markers and verify that the pinned source's bounded audit fragment is removed from retained logs. Fixtures describe behavior; they do not create a transcript mirror.

## P0-01 source review

The source-derived planning claims are reconciled by the local [P0-01 review record](source-audit/planning-reconciliation/planning_review.json). Reproduce it with the [validator](source-audit/planning-reconciliation/validate.py) against a local checkout of the pinned Hermes SHA. This evidence is source-only: it does not contact a live Dashboard or replace deployment attestation, behavioral probes, parity tests, or the focused source-audit units owned by issue `#200` and PRs `#216`, `#218`, `#219`, and `#220`.
