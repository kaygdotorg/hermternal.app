# Hermternal command / inspect prototype

## Current three-lane exploration

The active design critique surface lives in `prototypes/chat-lanes/`. It replaces the rejected visual direction with three isolated conversation compositions behind a neutral picker. See [`prototypes/chat-lanes/README.md`](prototypes/chat-lanes/README.md) for the mock boundaries, controls, themes, and NetBird serving command.

The original prototype below is retained only as a discarded baseline and is not imported by the new exploration.

This directory is a high-fidelity, web-only interaction prototype for Hermternal. Open `index.html` directly or serve the directory with:

```sh
python -m http.server 8000
```

Then visit `http://localhost:8000`. It has no build step, package install, account, remote asset, or network requirement.

## Visual thesis: the quiet instrument

Hermternal is designed as a calm instrument for issuing a direction and inspecting what follows, not as a generic chat dashboard. The moonlit graphite workspace holds two physical objects: a compact Tahoe-inspired history sidebar and one continuous, chrome-rimmed conversation shell. Inside that shell, a luminous signal rail connects prompts, responses, tool work, approval, and streaming into a legible execution trace. Strong spacing and typography establish the reading hierarchy; the assistant's key statement alone receives an editorial serif treatment.

The deliberate visual risk is the trace rail. It gives operational states a shared grammar without turning prose into log output. The rest of the interface stays low-chroma and avoids feature tiles, decorative cards, oversized pills, rainbow accents, arbitrary gradients, and stacked glass panels. Sidebar and composer share the same material recipe and blur weight because both are controls floating above the reading surface. The larger conversation shell is more solid so text remains stable and calm.

Four environments are intentionally distinct rather than accent swaps:

- **Moon** is the default blue-black, night-focused workspace.
- **Paper** changes the entire material and depth model for warm daylight reading.
- **Archive** uses an olive study palette with softer document contrast.
- **Ink** removes decorative shadow and pushes edges and type toward hard contrast.

Three reading stances change measure, rhythm, type treatment, and state density: Reflective favors editorial pacing, Compact favors operational scanning, and Wide supports long-form review.

The System environment follows the browser's light or dark color-scheme preference; explicit theme fixtures remain deterministic.

## Interaction and motion intent

Desktop and tablet navigation remains a persistent floating object. Below 851px it moves off-canvas behind a hamburger and scrim, traps keyboard focus, and returns focus on dismissal. The composer keeps attachment and context actions at bottom-left, model / voice / send at right, and long-prompt expansion at top-right.

Menus originate beside their controls. The drawer, scrim, and menu state use short, interruptible transform/opacity transitions with no `transition: all`, `scale(0)`, ease-in, or exaggerated bounce. Magnetic movement is restricted to fine pointers, capped at three pixels, and paired with immediate press feedback. Reduced-motion removes spatial motion; reduced-transparency replaces glass with solid material; unsupported blur receives the same solid fallback.

## What is interactive

The mobile drawer, theme environments, reading stances, model menu, composer expansion, mock attachment, context feedback, voice-note timer, approval choices, tool inspection, Escape dismissal, Command/Ctrl–Enter send, and focus states are interactive. Sending appends a local mock command and a short simulated streaming state to demonstrate command → inspect feedback. It never transmits or generates content.

The transcript includes realistic static prompt, attachment, assistant, tool, approval, and active-streaming states. Loading, denial, empty/new-thread, and completion feedback are represented through local controls and live-region messages.

## Accessibility and responsive behavior

The page uses semantic landmarks, headings, navigation, articles, forms, labels, fieldsets, time elements, and live regions. Primary controls meet a 44px minimum target. Focus is visible, Escape closes the topmost layer, the mobile drawer traps focus, and narrow layouts reflow through 320px without overlapping the transcript and composer. System fonts support browser zoom and platform text rendering. Color choices still require production contrast validation before adoption.

## Performance and mocked boundaries

There are no external dependencies, fonts, images, frameworks, polling loops, APIs, authentication, persistence, analytics, deployment settings, credentials, live data, or Hermes gateway integration. Icons are inline SVG; animation uses transforms and opacity except for tiny status indicators. The voice timer runs only while its local mock state is active.

This remains a planning prototype. Conversations, attachments, models, tools, permissions, connectivity, profile data, streaming, and send results are fixtures or browser-only simulations. Refresh restores the initial state. Nothing reaches a service, model, file system, or other user.

See `DESIGN-NOTES.md` for the command/inspect composition sketch and the pre-build critique that guided this pass.
