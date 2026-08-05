# Prototypes

## Status

Current visual exploration happens in Paper. Paper is the source of truth for the planned Hermternal screens and component states. This repository is still in the planning, mock, and proof phase; no prototype may call live Hermes services.

## Required prototype boundary

Every exported or coded prototype must state which data, interactions, authentication, persistence, and Hermes operations are mocked. Use synthetic fixtures only. Do not include credentials, live transcripts, provider data, or user data.

Prototype coverage should include static web chat, native Apple chat for iOS, iPadOS, and macOS, the web-only full `/api/pty` Terminal, one profile, provider-neutral discovery, images-only attachments, approvals, clarification, idle-now and source-correct deferred model switching, private `/v1/c/...` deep links, and the no-transcript-mirror boundary. Sharing is deferred to `v0.0.2`. No prototype adds terminal-read, sudo, or secret operations.

Paper states must show the relevant resting, hover, focused, pressed, selected, expanded, loading, empty, success, and failure states. A local runtime proof must later verify motion, focus transfer, keyboard behavior, reduced motion, and responsive behavior; Paper alone does not prove runtime behavior.

Use the [design tokens](../contracts/design-tokens/README.md), [state models](../contracts/state-models/README.md), and [product scope](../docs/product/README.md). Paper proof gates come before application scaffolding, live integration, and performance claims. Measure the performance baseline first.
