# Product scope

## Status

Hermternal is in the planning, mock, and proof phase. This README records the approved product boundary for the future `v0.0.1` milestone. It does not authorize a live integration.

## Milestone and release tags

`v0.0.1` is a product milestone, not a git release tag. A release tag uses `vYYYY.MM.DD.<patch-num>` and is created only when a verified `dev` commit is promoted to `main`.

## v0.0.1 goal

Deliver a focused chat client for the web and native Apple platforms:

- static Svelte 5/SvelteKit 2/Bun web;
- native SwiftUI iOS, iPadOS, and macOS chat;
- one profile;
- provider-neutral discovery;
- session creation and restoration;
- prompt submission, streaming, interruption, approvals, clarification, and clear recovery states;
- images only for attachments; and
- private deep links under `/v1/c/...`.

The web client also owns the full `/api/pty` Terminal. Terminal is not part of the Apple clients. The client does not add terminal-read, sudo, or secret operations. A transcript mirror is out of scope. Sharing starts in `v0.0.2`.

## Interaction rules

The active model selector has two explicit outcomes:

- idle: apply the new model now;
- streaming: keep the current stream unchanged; a normal choice may defer, while an expensive choice may require confirmation and resubmission after the turn.

Approval and clarification are separate user actions. The client must show which action is waiting and must not treat either action as an implicit approval.

## Compatibility boundary

The supported Hermes revision is `f5be9236e00ddf2f2a412697f267078fc4ee068e`. Missing or mismatched deployment attestation, or a failed behavioral probe, blocks live operation. Browser auth uses protected HttpOnly cookies. Native auth may use the discovered username/password provider with isolated `URLSession` cookies and WebSocket tickets. Native OAuth/OIDC is allowed only when the callback transport is accepted by the pinned Hermes native route and target-platform proof passes. It is blocked when either condition is absent or fails. No upstream change is approved.

## Proof gates

Paper states are the first proof. Protocol, security, deployment, accessibility, and performance proofs follow. Only after those gates pass may application scaffolding and live integration begin. The [protocol plan](../protocol/README.md), [architecture plan](../architecture/README.md), and [security plan](../security/README.md) hold the focused boundaries.
