# Product

<!-- impeccable:product-schema 1 -->
<!-- Product truth was inferred from the approved prototype brief and repository evidence during init. -->

## Platform

web

## Stack

static HTML/CSS with native ES modules; no build step or runtime dependency.

## Users

People using Hermes as a general-purpose agent from a desktop, tablet, or phone browser. They issue a direction, follow the agent's work, inspect tool output, and make approval decisions while moving between short operational tasks and longer-form conversations.

## Product Purpose

Hermternal is the web frontend prototype for Hermes. It gives an agent conversation a calm, readable surface while keeping execution states—streaming, tool work, attachments, approvals, and results—visible and understandable. Success means a user can compose a request, understand what Hermes is doing, and decide what happens next without losing the conversational thread.

## Positioning

The product treats an agent conversation as an inspectable execution trace rather than a generic chat transcript: prompts, responses, operations, and approvals share one readable thread, so the user can move from intent to outcome without opening a separate monitoring dashboard.

## Operating Context

Users may read and respond on a fine-pointer desktop, a touch tablet, or a narrow phone viewport. Sessions can include long prompts, streaming output, tool details, attachment context, approval requests, and recoverable local feedback. The current prototype is evaluated visually over a NetBird-served local web server.

## Capabilities and Constraints

- The current surface is a high-fidelity mockup with three interchangeable conversation compositions: Canvas, Stacks, and Focus.
- Local interactions cover navigation, themes, reading stances, model selection, composer expansion, attachments, context feedback, voice-note timing, approval choices, tool inspection, Escape dismissal, and mock streaming.
- Conversations, files, models, tools, permissions, streaming, and send results are fixtures or browser-only simulations. Nothing is sent to a Hermes gateway, persisted, authenticated, uploaded, or generated.
- Production gateway contracts, account/auth flows, persistence, model inventory, and live capability discovery remain open decisions for a later phase.
- The current phase is web-only UI prototyping; native iOS, iPadOS, and macOS clients are future products, not shared UI implementation.

## Brand Commitments

- Use the Hermes/Hermternal product name and a composed, precise voice.
- Geist Sans and Geist Mono are the approved prototype font families, with system fallbacks.
- The interface should feel coherent, touch-friendly, and materially consistent across transparent surfaces. Apple-inspired interaction and motion are references, not a claim of native implementation.

## Evidence on Hand

- `README.md` and `prototypes/chat-lanes/README.md` document the prototype's scope, mock boundaries, responsive behavior, and interaction intent.
- `prototypes/chat-lanes/index.html`, `styles.css`, `primitives.css`, and the ES module sources contain the current runnable surface and fixtures.
- No live user data, production credentials, provider integrations, testimonials, or deployment configuration are available or should be fabricated.

## Product Principles

- Make the next useful action obvious and immediate.
- Keep agent work inspectable without turning the conversation into a log dump.
- Preserve user control around tools, permissions, and irreversible actions.
- Prefer a coherent, reusable interaction language over feature-specific chrome.
- Treat speed, accessibility, and visual polish as product requirements during prototyping.

## Accessibility & Inclusion

- Support keyboard navigation, visible focus, semantic landmarks, screen-reader labels, browser zoom, and 320px-wide layouts.
- Preserve at least 44 CSS-pixel touch targets for primary controls.
- Respect reduced-motion, reduced-transparency, and increased-contrast preferences.
- Validate production contrast and native assistive-technology behavior before release.
