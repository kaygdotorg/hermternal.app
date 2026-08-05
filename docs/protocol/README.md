# Protocol planning

## Status

This directory records the planned client contract. It does not define a live connection or authorize production API calls.

## Supported surface

Hermternal targets the Hermes Dashboard protocol, not the separate Hermes API server contract. The contract covers the reviewed authentication routes, session operations, prompt operations, chat events, WebSocket ticket creation, error forms, compatibility metadata, and the web-only full `/api/pty` Terminal.

The supported Hermes revision is pinned to `f5be9236e00ddf2f2a412697f267078fc4ee068e`. The pinned Dashboard does not expose its source SHA. Missing or mismatched deployment attestation, or a failed behavioral probe, blocks live operation. Protocol names found only in source are not stable by default.

## Client transport rules

- Browser auth uses the Dashboard flow and server-issued HttpOnly cookies.
- Native auth may use the discovered username/password provider with an isolated `URLSession` cookie store and WebSocket tickets.
- Native OAuth/OIDC is supported only when the provider's reviewed callback transport is accepted by the pinned route and proven on the target Apple platform. An unsupported or unproven transport is blocked. There is no approved upstream change or hidden workaround.
- Provider discovery stays provider-neutral. The contract must not encode an unreviewed provider-specific assumption.

## Product behavior in the contract

The contract must cover one profile, session restoration, streaming, interruption, approvals, clarification, images only for attachments, private deep links under `/v1/c/...`, and the active model rule: idle changes apply now; normal streaming changes may defer to the next turn; a deferred expensive choice may require confirmation and resubmission after the turn.

The full `/api/pty` Terminal is web-only. The client contract has no separate terminal-read, sudo, or secret operations. It does not define a transcript mirror. Sharing is a `v0.0.2` concern.

Each contract change needs redacted fixtures and matching web and Apple compatibility evidence. See the [Dashboard contract](../../contracts/hermes-dashboard/README.md), [fixtures](../../contracts/fixtures/README.md), and [state models](../../contracts/state-models/README.md).
