# Architecture

## Status

This is a planning, mock, and proof architecture. It is not an application build plan that may connect to Hermes before the proof gates pass.

## Client boundary

Hermternal has two first-class client implementations and one shared specification layer:

- the web client is a static Svelte 5/SvelteKit 2/Bun application;
- the Apple clients are native SwiftUI applications for iOS, iPadOS, and macOS; and
- the contract layer defines compatible behavior, fixtures, state transitions, and design-token names.

Share contracts, fixtures, state specifications, test scenarios, and semantic token names. Keep UI, networking, authentication, persistence, navigation, lifecycle, gestures, motion, and accessibility code platform-native. Do not add WASM, Swift FFI, cross-language async bridges, or shared UI to solve this boundary.

## Product boundary

The web client owns chat and the full `/api/pty` Terminal. Apple clients own chat only. Both clients support one profile, provider-neutral discovery, images only, approvals and clarification, private deep links under `/v1/c/...`, and the source-correct active-session model switch. Normal deferred choices may apply on the next turn. A deferred expensive choice may need confirmation and resubmission after the turn. There is no transcript mirror. Sharing starts in `v0.0.2`. No client adds terminal-read, sudo, or secret operations.

## Transport and deployment boundary

Browser auth uses protected HttpOnly cookies. Native auth may use the discovered username/password provider with isolated `URLSession` cookie storage and WebSocket tickets. Native OAuth/OIDC is supported only when the provider's reviewed callback transport is accepted by pinned Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e` and proven on the target Apple platform. An unsupported or unproven transport is blocked; no approved upstream change exists.

Hermes uses a fixed private, non-loopback bind on `:9119` and a firewall. Caddy and Traefik are equal supported proxy choices. Missing or mismatched deployment attestation, or a failed behavioral probe, blocks live operation.

## Proof order

Paper is first. Then protocol, security, deployment, accessibility, and performance proofs. Application scaffolding and live integration follow only after those gates pass. The [product scope](../product/README.md), [protocol plan](../protocol/README.md), [security plan](../security/README.md), and [deployment plan](../deployment/README.md) are the focused references.
