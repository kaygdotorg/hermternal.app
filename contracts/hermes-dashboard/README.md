# Hermes Dashboard contract

## Status

This directory freezes the Hermes Dashboard surface for the future `v0.0.1` milestone. It contains no client implementation and no live server connection.

## Revision rule

The contract is tied to the reviewed Hermes source revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`. The pinned Dashboard does not report its source revision. A deployment must provide reviewed out-of-band revision attestation, and the client or proof harness must run the approved behavioral probe. Missing or mismatched evidence blocks live operation.

## Supported surface

The contract covers the selected Dashboard REST routes, browser authentication, native username/password provider authentication, isolated native `URLSession` cookies, WebSocket ticket creation, chat WebSocket messages, session operations, prompt operations, chat events, error forms, deployment attestation, and behavioral compatibility evidence.

Browser sessions use HttpOnly cookies. Native sessions may use the discovered username/password provider with an isolated cookie store and WebSocket tickets. Native OAuth/OIDC is supported only when the provider's reviewed callback transport is accepted by the pinned route and proven on the target Apple platform. An unsupported or unproven transport is blocked. There is no approved upstream change or hidden workaround.

Provider discovery must stay provider-neutral. The contract must not require a provider-specific name or response shape unless the pinned evidence proves it.

## Product behavior

The contract must represent one profile, streaming, interruption, approvals, clarification, images only for attachments, private deep links under `/v1/c/...`, and the active model rule: apply a change now while idle; allow a normal streaming choice to defer; require confirmation and resubmission after the turn when the pinned server drops a deferred expensive choice.

The web client alone may use the full `/api/pty` Terminal. The contract adds no terminal-read, sudo, or secret operation. It does not define a transcript mirror. Sharing is deferred to `v0.0.2`.

Each change needs redacted fixtures and matching web and Apple compatibility tests. See the [fixture rules](../fixtures/README.md) and [state models](../state-models/README.md).
