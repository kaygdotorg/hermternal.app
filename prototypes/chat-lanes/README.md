# Hermternal chat lanes

This directory is an isolated, web-only design exploration. It compares three complete conversation compositions while holding geometry, typography, materials, content, interactions, and responsive behavior constant:

- **Canvas** keeps assistant prose open and reserves surfaces for authored input and operational states.
- **Stacks** groups each prompt, response, tool event, and approval into one turn boundary.
- **Focus** narrows the reading measure and quiets secondary metadata on fine pointers.

Use the bottom picker, number keys `1`–`3`, or left/right arrow keys to switch instantly. The picker selection is stored in the `?v=` URL parameter.

## Run

From the repository root:

```sh
python3 -m http.server 33918 --bind 0.0.0.0 --directory prototypes/chat-lanes
```

The prototype has no build step and no runtime dependency. It loads no remote fonts, images, scripts, or data.

## Shared design constraints

The three surfaces use one derived radius scale (`12px`, `18px`, `26px`) and pinned, self-hosted Geist Sans and Geist Mono prototype assets under SIL OFL 1.1. Compact chrome contains one primary label. Its top islands use one reusable `ui-glass-pill` geometry (a shared 50px by 166px desktop frame) and magnetic-return primitive: pointer entry and movement attract up to 12px, with a subtle scale-and-depth acknowledgement. The status island is removed at narrow widths instead of becoming an empty capsule. Material and raised surfaces are 50% opaque with a `20px` backdrop blur and `1.38` saturation, plus a reduced-transparency fallback. The composer collapses to one prompt line while preserving 48px touch targets and a larger control-label scale; its expand affordance appears only after a draft wraps to two visual lines and remains available while expanded. The composer dock does not paint an additional veil. Ten popular color fixtures change semantic tokens only: System, Nord, Dracula, Gruvbox, Solarized, Catppuccin, Tokyo Night, Rosé Pine, One Dark, and Monokai.

Floating menus render beside, rather than inside, blurred shells so each surface samples the real content behind it and preserves the same material recipe. Composer actions use 48px touch targets with 20–21px icons; tool and approval rows reserve a 40px two-line copy block instead of compressing their title and supporting text.

The distilled conversation chrome keeps only the title and local-session islands; unimplemented share, overflow, copy, and regenerate controls are intentionally omitted until their interactions exist. Navigation search filters the fixture history locally, New conversation resets the mock thread, and Stop ends the simulated stream so every visible control has a bounded prototype behavior.

`primitives.css` is the prototype-level reuse boundary. It defines the shared glass surface plus semantic button, icon-button, pill, selector, and independent-action-cluster families. Magnetic controls follow the pointer at 18% strength with a 7px clamp and settle back through the individual CSS `translate` property, allowing press-scale to compose without displacement bugs. Touch and reduced-motion input do not drift.

Controls meet a 44 CSS-pixel target. The navigation becomes a left drawer below 820px; its scrim and close control remain above the fixed mobile toolbar, while the page behind the open drawer is inert and keyboard focus wraps within the drawer. Focus visibility, reduced motion, reduced transparency, increased contrast, and 320px-wide layouts are represented in the prototype CSS.

Motion is intentionally limited to state changes that benefit from visible causality. Pointer-opened menus settle from `scale(.97)` and zero opacity in `180ms`, then leave in `130ms`; keyboard-opened menus appear immediately. Pointer-created toasts, newly submitted local turns, and approval results use short transform-and-opacity entrances, while keyboard-created equivalents settle immediately. Transcript loading, theme changes, and composer expansion do not receive decorative animation. Reduced Motion replaces spatial travel with a `120ms` opacity-only transition, while magnetic drift is disabled entirely.

## Mocked boundaries

Conversations, models, attachments, context, tool details, approvals, voice timing, streaming, and send results are browser-only fixtures or simulations. Nothing is uploaded, persisted, generated, authenticated, or sent to a Hermes gateway. Refresh restores the initial state.

The current fixtures are informed by Hermes Agent's documented sessions, tools, approvals, vision attachments, memory, skills, delegation, voice, and scheduled-task capabilities. This refinement does not add those integrations; it only keeps the prototype component boundaries broad enough to explore them later without overloading the composer.

The rejected root prototype remains untouched so the comparison is reversible. The selected lane can be promoted later; this exploration does not define production architecture.
