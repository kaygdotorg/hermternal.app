# Hermternal chat lanes mockup design

## Status and scope

This document defines a web-only, high-fidelity prototype exploration for the Hermternal chat screen. All conversations, models, attachments, tool calls, approvals, voice recording, streaming, and connection states are local fixtures or browser-only simulations. The prototype does not use a Hermes gateway, authentication, credentials, production APIs, persistence, telemetry, or live user data.

The current command/inspect prototype is rejected. Its traffic-light window controls, mixed radius language, arbitrary bold/serif emphasis, and competing message treatments are not carried forward.

## Product purpose

Hermternal is a calm, fast interface for holding a long conversation with an assistant while understanding tool activity and approvals. The primary action is composing a message. The primary reading task is following the conversation without operational states fragmenting it into a dashboard.

## Exploration format

An isolated prototype page presents one full-size variant at a time behind the exact neutral picker defined by the installed `prototype` skill. Switching is instant and supports the picker's keyboard controls. Prototype files do not feed into the eventual product surface. The picker remains available until the user selects a direction.

The three variants share content, behavior, accessibility semantics, theme tokens, and responsive breakpoints. They diverge only in the conversation container model and information density.

### Lane 1: Continuous Canvas

One chrome-rimmed conversation shell contains an open reading lane. Assistant responses sit directly on the canvas. User prompts use one restrained inset surface. Tool calls, approvals, attachments, errors, and streaming states appear inline at the same text measure instead of becoming unrelated cards. The composer anchors the bottom of the shell.

This is the recommended direction because it produces the strongest hierarchy with the fewest competing shapes. Its cost is that it feels less like a conventional messenger.

### Lane 2: Turn Stacks

Each user prompt and the resulting assistant activity form one grouped turn. A quiet shared boundary and internal spacing connect the prompt, response, tool activity, and approval state. Turns are separated by whitespace rather than individually styled bubbles.

This is the most familiar and scannable direction. Its cost is greater vertical density and more visible structure.

### Lane 3: Focus Lane

A narrow centered transcript minimizes persistent metadata. Author, model, timing, and response actions appear only where they clarify state or on focus/hover when a fine pointer is present. Operational events occupy compact rows aligned to the reading lane.

This is the quietest long-form reading direction. Its cost is lower immediate visibility for secondary state.

## Shared visual system

### Geometry

The interface uses a derived three-step radius system:

- `--radius-control: 12px` for buttons, fields, compact rows, and menus.
- `--radius-nested: 18px` for the composer, selected navigation regions, and grouped turn surfaces.
- `--radius-shell: 26px` for the sidebar and primary conversation shell.

Nested radii decrease with their inset. No component invents a fourth rounded-rectangle radius. Circles are reserved for avatars, status indicators, and icon-only controls. Desktop and mobile controls have a minimum 44 by 44 CSS-pixel target.

### Typography

The UI uses the platform system stack with optical sizing enabled. Display-sized conversation titles use the system display cut; prose and controls use the system text cut; code or tool output alone may use `ui-monospace`.

Only three weights are permitted:

- `400` for transcript prose and secondary labels.
- `500` for controls, authors, and selected navigation.
- `600` for the conversation title and a small number of primary headings.

Message content never changes font family to create drama. Hierarchy comes from size, spacing, color, and placement. Large text uses tighter tracking and leading; small labels use slightly more tracking and comfortable contrast.

### Material and color

Sidebar and composer use the same material recipe: identical background alpha, blur, saturation, border highlight, and elevation. The larger conversation shell is calmer and more opaque for stable reading. Translucent materials never stack directly on one another.

The default Tahoe Frost palette is:

- Canvas: `#E9EDF3`
- Reading surface: `#F8FAFC`
- Primary ink: `#171A21`
- Secondary ink: `#697180`
- Glass highlight: `rgba(255, 255, 255, 0.68)`
- Action blue: `#3478F6`

Theme selection changes semantic color and material tokens only. It never changes layout, radii, typography, or component behavior. The exploration includes System, Nord, Dracula, Gruvbox, Solarized, Catppuccin, Tokyo Night, Rosé Pine, One Dark, and Monokai families, with contrast-safe light or dark mappings.

### Signature

The memorable element is the single chrome conversation shell: a restrained bright rim and contextual depth make the entire conversation feel like one precise instrument. There are no macOS traffic lights, fake title-bar furniture, decorative trace rails, serif pull quotes, neon glows, or unrelated gradients.

## Layout and components

```text
large web
┌ floating glass sidebar ┐  ┌ one chrome conversation shell ─────────────┐
│ brand + new chat       │  │ title + quiet session actions              │
│ search / history       │  │                                            │
│                        │  │ lane-specific conversation composition      │
│ theme + profile        │  │                                            │
└────────────────────────┘  │  matched-glass composer                    │
                            └────────────────────────────────────────────┘

mobile web
┌ glass toolbar: menu · title · new ┐
┌ edge-conscious conversation shell ┐
│ lane-specific transcript           │
│ matched-glass composer              │
└─────────────────────────────────────┘
sidebar enters from and exits to the left behind a scrim
```

Shared component families are app shell, sidebar, mobile toolbar/drawer, conversation header, transcript entry, operational event row, attachment, approval request, composer, model menu, theme menu, and prototype picker. Repeated controls use variants of the same primitives rather than copied styling.

## Composer behavior

The composer is the primary interaction surface. Attachment and context controls sit at bottom-left. Model selection, voice note, and send sit at bottom-right. Expand sits at top-right and increases the writing area without replacing the conversation.

The model and theme menus originate from their triggers. The mobile drawer follows the finger when gesture work is included, remains interruptible, and returns focus to the hamburger after dismissal. Escape closes the topmost layer. Command or Control plus Enter sends a local mock response. Empty sends remain disabled.

## Motion

Frequent actions prioritize immediate response over spectacle. Press feedback begins on pointer down and uses a restrained `scale(0.97)` response. Fine-pointer magnetic hover is capped at three pixels and never runs on touch devices. Menus enter in 150–200ms from their trigger origin. Drawer motion uses a critically damped, interruptible response around 300ms; keyboard-triggered actions do not wait on animation.

Only transform and opacity animate during ordinary UI transitions. Reduced motion replaces spatial movement with short cross-fades. Reduced transparency uses a near-solid material, and increased contrast strengthens boundaries and foreground contrast.

## Responsive and accessibility behavior

The sidebar is persistent on large screens and becomes a left drawer below the tablet breakpoint. The conversation remains usable at 320 CSS pixels, at 200% browser zoom, and with long realistic content. Focus order follows navigation, conversation actions, transcript actions, then composer controls. Every icon-only control has an accessible name. Status changes use restrained live regions; static transcript content does not repeatedly announce itself.

The mockup includes idle, hover, pressed, focused, disabled, loading, empty, success, denied approval, error, attached-file, voice-recording, and streaming states. Focus is visible against every theme. Mobile controls preserve 44-pixel targets without forcing horizontal overflow.

## Performance boundaries

The exploration remains dependency-free unless an existing project dependency is clearly required. It loads no remote fonts or imagery, performs no polling, and makes no network requests. Long transcript entries use lightweight DOM and CSS. Pointer movement updates only the affected element transform and stops immediately when the pointer leaves.

## Verification

Before presenting the picker:

1. Verify all three lanes at desktop, tablet, and mobile widths.
2. Exercise picker switching, mobile drawer, theme selection, model selection, composer expansion, mock attachment, voice recording, approval actions, and local send/streaming.
3. Check keyboard navigation, Escape dismissal, visible focus, semantic labels, 200% zoom, reduced motion, reduced transparency, and high contrast.
4. Capture each lane at the same desktop viewport plus the selected mobile state.
5. Compare geometry, typography, material hierarchy, icon treatment, and transcript cohesion against this specification.
6. Confirm the browser console is clean and no request leaves the local prototype.

## Selection and promotion

The user chooses a lane after comparing the live variants. No lane is promoted merely because it is recommended here. After selection, the chosen container model may be integrated into the product prototype and the isolated picker is removed unless the user asks to retain it.
