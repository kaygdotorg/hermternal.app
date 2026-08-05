# Shared contracts

This directory holds language-neutral artifacts that keep the web and Apple clients behaviorally aligned during the planning, mock, and proof phase.

## Contract set

- [Hermes Dashboard](hermes-dashboard/README.md) freezes the supported routes, messages, revision, and compatibility evidence.
- [Fixtures](fixtures/README.md) define synthetic request, response, stream, recovery, and proof data.
- [State models](state-models/README.md) define observable transitions without sharing runtime state code.
- [Design tokens](design-tokens/README.md) define semantic design intent for Paper, web, and SwiftUI.

The supported Hermes revision is pinned to `f5be9236e00ddf2f2a412697f267078fc4ee068e`. The pinned Dashboard does not report its revision. Missing or mismatched out-of-band deployment attestation, or a failed behavioral probe, blocks live operation. Contract changes must include redacted fixtures and matching web and Apple evidence.

Shared behavior includes one profile, provider-neutral discovery, streaming, approvals, clarification, interruption, images only for attachments, the source-correct active-session model switch, including deferred expensive-choice confirmation loss, and private deep links under `/v1/c/...`. The full `/api/pty` Terminal is web-only. Sharing starts in `v0.0.2`. There is no transcript mirror and no terminal-read, sudo, or secret operation.

Authentication stays platform-specific: browser HttpOnly cookies; native username/password provider authentication with isolated `URLSession` cookie storage and WebSocket tickets. Native OAuth/OIDC is supported only when the configured provider's reviewed callback transport is accepted by the pinned Hermes route and proven on the target Apple platform. An unsupported or unproven transport is blocked. No upstream change is approved.

Contract artifacts must never contain credentials, live transcripts, provider data, hostnames, tokens, or other user data.
