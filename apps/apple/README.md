# Apple clients

## Status

This directory is in the planning, mock, and proof phase. It has no Xcode project, Swift package, signing configuration, credential, or live Hermes call.

## v0.0.1 target

The future Apple clients are native SwiftUI chat apps for iOS, iPadOS, and macOS. They share contracts and fixtures with the web client, but keep UI, networking, authentication, persistence, lifecycle, navigation, gestures, motion, and accessibility native.

The chat surface has one profile, provider-neutral discovery, session restore, streaming, approvals, clarification, interruption, images only for attachments, and no transcript mirror.

Internal stable session and message IDs remain allowed. Required authentication callback routing also remains allowed.

User-facing deep-link UI and full-text session-search UI are deferred to `v0.0.2`. Both UIs need redesign. The deep-link and search contracts remain future compatibility references. User-facing sharing is deferred to `v0.0.2`.

An active model change applies immediately when the conversation is idle. During streaming, a normal deferred choice may apply to the next turn and does not interrupt the current stream. If the deferred choice needs expensive-model confirmation, the pinned server drops it; the client must confirm and submit it after the turn.

The Apple clients do not include the Terminal. The full `/api/pty` Terminal is web-only. They do not add terminal-read, sudo, or secret operations.

## Native transport boundary

Native authentication may use the discovered username/password provider with an isolated `URLSession` cookie store and WebSocket tickets. Store only approved session material in the platform credential store; never share browser cookies with native code.

Native OAuth/OIDC is supported only when the configured provider's reviewed callback transport is accepted by pinned Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e` and proven on the target Apple platform. An unsupported or unproven transport is blocked. There is no approved upstream change, so a client must not bypass this boundary with a hidden provider flow.

Missing or mismatched deployment revision attestation, or a failed behavioral probe, blocks live operation. Use the [Dashboard contract](../../contracts/hermes-dashboard/README.md), [state models](../../contracts/state-models/README.md), and [security plan](../../docs/security/README.md) as the focused references.
