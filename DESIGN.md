---
name: Hermternal chat lanes
description: A calm, inspectable chat surface for Hermes agent work.
colors:
  primary: "#3478f6"
  neutral-bg: "#e9edf3"
  neutral-surface: "#f8fafc"
  neutral-raised: "#ffffff"
  neutral-text: "#171a21"
  neutral-muted: "#4e5663"
  neutral-faint: "#737c8b"
  dark-bg: "#171a20"
  dark-surface: "#20242b"
  dark-text: "#f1f3f5"
typography:
  display:
    fontFamily: "Geist, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "-0.018em"
  body:
    fontFamily: "Geist, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "clamp(0.91rem, 1.05vw, 1rem)"
    fontWeight: 400
    lineHeight: 1.7
  label:
    fontFamily: "Geist, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "0.015em"
  mono:
    fontFamily: "Geist Mono, ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "0.67rem"
    fontWeight: 400
rounded:
  control: "12px"
  nested: "18px"
  shell: "26px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  section: "48px"
components:
  button-primary:
    backgroundColor: "{colors.neutral-text}"
    textColor: "{colors.neutral-surface}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "44px"
  button-accent:
    backgroundColor: "{colors.primary}"
    textColor: "#ffffff"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    size: "48px"
  input-search:
    backgroundColor: "{colors.neutral-raised}"
    textColor: "{colors.neutral-text}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "44px"

# Design System: Hermternal chat lanes

## Overview

**Creative North Star: "The Quiet Instrument"**

Hermternal is a calm instrument for issuing a direction and inspecting what follows. The interface keeps the conversation readable while making operational states—tool work, approvals, attachments, and streaming—legible in the same thread. It is composed rather than ornamental: a cool graphite canvas, a compact Tahoe-inspired sidebar, a chrome-rimmed conversation shell, and a restrained blue accent.

The surface uses self-hosted Geist for a single consistent voice, with Geist Mono reserved for code and measured values. Translucent controls are physical objects above the reading surface: they share one 50% material recipe, 20px blur, and a small radius vocabulary. The three lane variants change composition, not identity.

**Key Characteristics:**

- One typographic voice with clear weight and measure changes.
- 50% translucent control surfaces with shared blur and saturation.
- Cool neutral canvas, restrained semantic accent, and theme-driven color roles.
- Operational states use a quiet single-line utility-row grammar.
- Touch targets stay at least 44px; magnetic motion is pointer-only and restrained.

## Colors

The default System environment is cool and light, then follows the browser's dark preference. Named theme fixtures replace semantic roles rather than changing geometry or behavior.

### Primary

- **Signal Blue** (`{colors.primary}`): Send, approval, focus, and selected states.

### Neutral

- **Cool Paper** (`{colors.neutral-bg}`): Default canvas and ambient field.
- **Raised White** (`{colors.neutral-surface}`): Solid fallback and light text-on-dark contrast surface.
- **Ink** (`{colors.neutral-text}`): Primary text and primary action fill.
- **Slate** (`{colors.neutral-muted}`): Assistant prose and secondary controls.
- **Faint Slate** (`{colors.neutral-faint}`): Metadata, timestamps, and supporting copy.
- **Night Graphite** (`{colors.dark-bg}`): System dark canvas.
- **Night Surface** (`{colors.dark-surface}`): System dark shell and controls.

**The Rare Accent Rule.** Keep the accent concentrated on state, action, and focus. It should guide the next decision, not decorate every surface.

## Typography

**Display Font:** Geist (with system UI fallbacks)
**Body Font:** Geist (with system UI fallbacks)
**Label/Mono Font:** Geist Mono for code, measurements, and keyboard hints.

**Character:** Geist keeps the interface precise and quiet without introducing a second display personality. Weight and measure create hierarchy; size changes stay restrained.

### Hierarchy

- **Display** (600, `0.9375rem`, line-height 1): Conversation title and compact identity labels.
- **Body** (400, `clamp(0.91rem, 1.05vw, 1rem)`, line-height 1.7): Assistant prose, with a readable long-form measure.
- **Label** (400–600, `0.64–0.8125rem`, line-height 1.2): Metadata, navigation rows, controls, and state copy.
- **Mono** (400, `0.67rem`, line-height 1.55): Tool details and keyboard hints only.

**The One Voice Rule.** Do not introduce a second UI font. Use Geist Mono only when the content is actually code, data, or a measurement.

## Layout

Wide layouts use a 17.5rem floating sidebar, a 1rem gap, and a flexible conversation shell inside a 1rem page inset. The shell and sidebar stretch to the same document height. Conversation reading measure is approximately 47rem, with Canvas, Stacks, and Focus variants changing only their composition model.

At 820px and below, the sidebar becomes a left drawer behind a scrim and a fixed mobile toolbar. The conversation remains the primary surface and reflows through 320px without horizontal overflow. The composer stays docked and reserves space above the prototype picker.

## Elevation & Depth

Depth comes from tonal layering and ambient shadows, not hard offset decoration. Glass surfaces use 50% material opacity, `20px` backdrop blur, and `1.38` saturation; reduced-transparency and unsupported-blur paths use the corresponding solid material token. The conversation shell is more solid so prose remains stable; sidebar, composer, menus, and header islands share the lighter material recipe.

### Shadow Vocabulary

- **Floating control:** `var(--shadow-float)` for sidebar, composer, menus, and status surfaces.
- **Conversation shell:** `var(--shadow-shell)` for the main reading container.

**The Material Consistency Rule.** Transparent surfaces use the same opacity, blur, saturation, edge, and fallback recipe unless a surface is deliberately solid for readability.

## Shapes

The form language is a small derived radius scale: 12px controls, 18px nested content, 26px shells, and 999px pills. Borders are one-pixel quiet lines; controls use generous internal space rather than extra nested containers. Primary touch controls are 44px, with composer actions at 48px.

## Components

### Buttons

- **Shape:** 12px control radius for labeled actions; 999px for circular or pill action controls.
- **Primary:** Ink or Signal Blue fill with high-contrast text and a 44–48px target.
- **Hover / Focus:** Accent-soft tint, visible 2px focus outline, and capped pointer-only magnetic translation.
- **Secondary:** Transparent controls rely on text, spacing, and the shared material rather than individual capsules.

### Glass Surfaces

- **Background:** 50% semantic material token with 20px blur and 1.38 saturation.
- **Edge:** One-pixel glass edge plus a restrained ambient shadow.
- **Fallback:** Solid material when reduced transparency is requested or blur is unsupported.

### Inputs / Fields

- **Style:** Transparent textarea inside a compact glass composer; search uses a 44px raised field.
- **Focus:** Accent border and soft focus ring; the composer itself remains visually quiet.
- **Actions:** Attach and context stay bottom-left; model, voice, and send stay bottom-right; expansion sits top-right.

### Navigation

- **Desktop:** Persistent floating sidebar with one-label history rows and footer islands.
- **Mobile:** Hidden left drawer opened by a hamburger, with scrim, focus return, and Escape dismissal.

### Operational Rows

- **Structure:** 56px minimum utility row with one clear label and no decorative leading icon or stacked subtitle.
- **States:** Tool rows disclose details; approval rows make the decision explicit; streaming rows use a single restrained status indicator.

## Do's and Don'ts

### Do:

- **Do** keep Geist consistent across the UI and reserve Geist Mono for code or measurements.
- **Do** use the shared material tokens for every translucent surface.
- **Do** keep the reading hierarchy open and let operational states attach to the conversation.
- **Do** preserve 44px minimum touch targets and reduced-motion alternatives.
- **Do** treat themes as semantic token sets, never as geometry changes.

### Don't:

- **Don't** add solid dashboard chrome or traffic-light window buttons.
- **Don't** stack a title and subtitle inside compact pills or sidebar rows.
- **Don't** introduce arbitrary radii, fonts, gradients, or nested glass cards.
- **Don't** use decorative motion that competes with reading or approval decisions.
- **Don't** imply live Hermes integrations in this prototype; all data and actions remain mocked.
