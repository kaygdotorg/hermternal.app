# Web client

## Status

This directory is in the planning, mock, and proof phase. It has no application scaffold, package manifest, live call, or production authentication flow.

## v0.0.1 target

The future web client is a static Svelte 5 and SvelteKit 2 application built with Bun. It owns the web chat and the full web-only `/api/pty` Terminal. Apple clients do not use this Terminal surface.

The planned chat surface has one profile, provider-neutral discovery, session restore, streaming, approvals, clarification, interruption, images only for attachments, and no transcript mirror.

Internal stable session and message IDs remain allowed. Required authentication callback routing also remains allowed.

User-facing deep-link UI and full-text session-search UI are deferred to `v0.0.2`. Both UIs need redesign. The deep-link and search contracts remain future compatibility references. User-facing sharing is deferred to `v0.0.2`.

An active model change applies immediately when the conversation is idle. During streaming, a normal choice may defer to the next turn and does not interrupt the current stream. If the deferred choice needs expensive-model confirmation, the pinned server drops it; the client must confirm and submit it after the turn.

## Transport boundary

Browser authentication uses server-issued HttpOnly cookies. Do not put reusable Hermes credentials in local storage, session storage, or other browser-readable state.

The client targets Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`. The pinned Dashboard does not report its revision. Missing or mismatched out-of-band deployment attestation, or a failed behavioral probe, blocks live operation. Provider discovery must stay provider-neutral and must not rely on an unreviewed provider name.

The web client may expose the full `/api/pty` Terminal. It does not add separate terminal-read, sudo, or secret operations. Caddy and Traefik are equal supported proxy choices; both must preserve the required HTTPS and WebSocket behavior.

## Proof order

Paper states and responsive layouts come first. Protocol, security, deployment, accessibility, and performance proofs must pass before application or live integration work. Use the [protocol contract](../../contracts/hermes-dashboard/README.md), [state models](../../contracts/state-models/README.md), and [deployment plan](../../docs/deployment/README.md) as the focused references.
